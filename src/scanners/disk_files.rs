use crate::config::{extension_kind, is_excluded, is_target_extension, ExtensionKind, RunConfig};

use crate::matcher::Matcher;
use crate::report::{KeywordHit, MatchRecord, Section};
use std::collections::HashSet;
use anyhow::Result;
use rayon::prelude::*;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use walkdir::WalkDir;

const MMAP_THRESHOLD: u64 = 64 * 1024;
const CONTEXT_HALF: usize = 60;

/// Walk all configured roots, collect candidate files, then scan in parallel.
pub fn scan(cfg: &RunConfig, matcher: &Matcher) -> Result<Vec<MatchRecord>> {
    // Phase 1: enumerate candidate files
    let mut candidates: Vec<PathBuf> = Vec::new();
    for root in &cfg.roots {
        let walker = WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| !is_excluded(e.path(), &cfg.excludes));
        for entry in walker.filter_map(|e| e.ok()) {
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            if !is_target_extension(path, &cfg.extensions) {
                continue;
            }
            if let Ok(meta) = entry.metadata() {
                if meta.len() > cfg.max_file_size {
                    continue;
                }
            }
            candidates.push(path.to_path_buf());
        }
    }

    // Tell the user what's running. The progress bar lives on the next line.
    eprintln!("  磁碟文字檔搜尋（掃描中，候選 {} 檔）", candidates.len());

    // Hand-rolled progress bar — pure ANSI, no third-party TTY detection.
    // The previous indicatif version fell back to "append a new line per tick"
    // because indicatif's Windows cursor-move path uses Win32 SetConsoleCursorPosition
    // which is gated on its own TTY detection. We bypass that entirely.
    let total = candidates.len() as u64;
    let progress = Arc::new(AtomicU64::new(0));
    let current_msg: Arc<Mutex<String>> = Arc::new(Mutex::new(format!("候選 {} 檔", candidates.len())));
    let done = Arc::new(AtomicBool::new(false));

    let drawer = {
        let progress = progress.clone();
        let current_msg = current_msg.clone();
        let done = done.clone();
        std::thread::spawn(move || progress_drawer(total, progress, current_msg, done))
    };

    let results = Mutex::new(Vec::<MatchRecord>::new());

    candidates.par_iter().for_each(|path| {
        // Full path in progress bar (user-requested). May wrap in narrow terminals;
        // the `\r ... \x1B[K` redraw will still keep the trailing line clean.
        if let Ok(mut m) = current_msg.lock() {
            *m = path.display().to_string();
        }
        if let Ok(Some(record)) = scan_one(path, matcher) {
            let mut g = results.lock().unwrap();
            g.push(record);
        }
        progress.fetch_add(1, Ordering::Relaxed);
    });

    done.store(true, Ordering::Relaxed);
    let _ = drawer.join();

    Ok(results.into_inner().unwrap())
}

/// Scan one file. Returns at most one MatchRecord per file (None if nothing matched).
/// Aggregates filename hits + content hits, deduped so each unique keyword appears
/// once per file with its first occurrence's line and context.
fn scan_one(path: &Path, matcher: &Matcher) -> Result<Option<MatchRecord>> {
    let mut seen: HashSet<(String, bool)> = HashSet::new();
    let mut hits: Vec<KeywordHit> = Vec::new();

    // (1) Filename hits — no line, context is the filename itself.
    if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
        for h in matcher.find_all(name) {
            let key = (h.keyword.pattern.clone(), h.keyword.case_sensitive);
            if seen.insert(key) {
                hits.push(KeywordHit {
                    keyword: h.keyword.pattern.clone(),
                    case_sensitive: h.keyword.case_sensitive,
                    line: None,
                    context: format!("（檔名命中）{}", name),
                });
            }
        }
    }

    // (2) Content hits.
    let kind = extension_kind(path);
    let content = match kind {
        ExtensionKind::PlainText => read_plain_text(path)?,
        ExtensionKind::Office => read_office_ooxml(path).unwrap_or_default(),
        ExtensionKind::LegacyOffice => read_legacy_office(path).unwrap_or_default(),
        ExtensionKind::Pdf => read_pdf(path).unwrap_or_default(),
    };
    if !content.is_empty() {
        for h in matcher.find_all(&content) {
            let key = (h.keyword.pattern.clone(), h.keyword.case_sensitive);
            if !seen.insert(key) {
                continue; // already recorded — keep only first occurrence per keyword
            }
            let line = match kind {
                ExtensionKind::PlainText => Some(line_number_at(&content, h.start)),
                _ => None,
            };
            let context = make_context(&content, h.start, h.end);
            hits.push(KeywordHit {
                keyword: h.keyword.pattern.clone(),
                case_sensitive: h.keyword.case_sensitive,
                line,
                context,
            });
        }
    }

    if hits.is_empty() {
        return Ok(None);
    }
    Ok(Some(MatchRecord {
        section: Section::DiskText,
        source: Section::DiskText.short().to_string(),
        location: path.display().to_string(),
        hits,
    }))
}

/// Read a file as text. Uses mmap for large files; small files go through fs::read.
/// Detects encoding via chardetng and decodes through encoding_rs.
fn read_plain_text(path: &Path) -> Result<String> {
    let meta = std::fs::metadata(path)?;
    let len = meta.len();
    if len == 0 {
        return Ok(String::new());
    }
    let bytes: Vec<u8> = if len >= MMAP_THRESHOLD {
        let file = std::fs::File::open(path)?;
        // SAFETY: We treat mmap as read-only. If the file is truncated mid-scan,
        // we may SIGBUS — acceptable trade for the speedup on large files.
        match unsafe { memmap2::Mmap::map(&file) } {
            Ok(m) => m.as_ref().to_vec(),
            Err(_) => std::fs::read(path)?,
        }
    } else {
        std::fs::read(path)?
    };
    Ok(decode_bytes(&bytes))
}

fn decode_bytes(bytes: &[u8]) -> String {
    // Fast path: UTF-8 BOM
    if bytes.starts_with(b"\xEF\xBB\xBF") {
        return String::from_utf8_lossy(&bytes[3..]).into_owned();
    }
    // UTF-16 BOMs
    if bytes.starts_with(b"\xFF\xFE") {
        return encoding_rs::UTF_16LE.decode(&bytes[2..]).0.into_owned();
    }
    if bytes.starts_with(b"\xFE\xFF") {
        return encoding_rs::UTF_16BE.decode(&bytes[2..]).0.into_owned();
    }
    // Detect
    let mut det = chardetng::EncodingDetector::new();
    let sample_len = bytes.len().min(64 * 1024);
    det.feed(&bytes[..sample_len], true);
    let enc = det.guess(None, true);
    enc.decode(bytes).0.into_owned()
}

fn line_number_at(s: &str, byte_offset: usize) -> u64 {
    let bo = byte_offset.min(s.len());
    let mut n: u64 = 1;
    for (i, b) in s.as_bytes().iter().enumerate() {
        if i >= bo {
            break;
        }
        if *b == b'\n' {
            n += 1;
        }
    }
    n
}

/// Extract a tight context window guaranteed to contain the matched keyword
/// `s[start..end]`. Takes ~CONTEXT_HALF chars before the hit and CONTEXT_HALF
/// chars after; collapses whitespace; marks truncation with "…".
///
/// Critical contract: the returned string must literally contain the matched
/// substring (so terminal/log can find and highlight it). The old impl built a
/// ±240-byte window that the terminal layer then re-truncated to 100 chars,
/// which could chop the keyword off the end of the displayed slice.
fn make_context(s: &str, start: usize, end: usize) -> String {
    // Find the byte position CONTEXT_HALF chars before `start`.
    let pre_chars: usize = s[..start].chars().count();
    let skip_chars = pre_chars.saturating_sub(CONTEXT_HALF);
    let before_byte = if skip_chars == 0 {
        0
    } else {
        s.char_indices()
            .nth(skip_chars)
            .map(|(i, _)| i)
            .unwrap_or(start)
    };

    // Find the byte position CONTEXT_HALF chars after `end`.
    let after_byte = s[end..]
        .char_indices()
        .nth(CONTEXT_HALF)
        .map(|(i, _)| end + i)
        .unwrap_or(s.len());

    let prefix_truncated = before_byte > 0;
    let suffix_truncated = after_byte < s.len();
    let slice = &s[before_byte..after_byte];

    let mut out = String::with_capacity(slice.len() + 8);
    if prefix_truncated {
        out.push('…');
    }
    let mut last_space = false;
    for ch in slice.chars() {
        let mapped = if matches!(ch, '\n' | '\r' | '\t') {
            ' '
        } else {
            ch
        };
        if mapped == ' ' {
            if !last_space {
                out.push(' ');
            }
            last_space = true;
        } else {
            out.push(mapped);
            last_space = false;
        }
    }
    if suffix_truncated {
        out.push('…');
    }
    out
}

/// Background drawer: every 125 ms, write `\r<bar><stats><filename>\x1B[K` to stderr.
/// Pure ANSI, no third-party TTY detection. Requires VT processing enabled on Windows
/// (we do that in `main::enable_vt_processing` at startup).
///
/// `\r` moves cursor to column 0; `\x1B[K` clears from cursor to end-of-line. Together
/// they produce a reliable in-place refresh.
fn progress_drawer(
    total: u64,
    progress: Arc<AtomicU64>,
    current_msg: Arc<Mutex<String>>,
    done: Arc<AtomicBool>,
) {
    let start = Instant::now();
    let spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
    let bar_width: u64 = 14;
    let mut tick: usize = 0;

    loop {
        let n = progress.load(Ordering::Relaxed);
        let pct = if total > 0 { (n * 100 / total).min(100) } else { 0 };
        let filled = if total > 0 {
            (n * bar_width / total).min(bar_width) as usize
        } else {
            0
        };
        let empty = (bar_width as usize).saturating_sub(filled);
        let bar = format!("{}{}", "█".repeat(filled), " ".repeat(empty));
        let elapsed = start.elapsed().as_secs();
        let h = elapsed / 3600;
        let m = (elapsed % 3600) / 60;
        let s = elapsed % 60;
        let msg = current_msg.lock().map(|g| g.clone()).unwrap_or_default();
        let sp = spinner[tick % spinner.len()];
        // Total visual width: "  " 2 + spinner 1 + " " 1 + "[" 1 + bar 14 + "]" 1 + " " 1
        //   + "[hh:mm:ss]" 10 + " " 1 + "999999/999999" 13 + " " 1 + "(100%)" 6 + " " 1
        //   + msg 26 = 79 cols. Edge of 80-col terminal.
        let line = format!(
            "  {sp} [{bar}] [{h:02}:{m:02}:{s:02}] {n}/{total} ({pct}%) {msg}"
        );
        // \r → go to column 0 ; \x1B[K → clear to end of line.
        let mut stderr = std::io::stderr().lock();
        let _ = write!(stderr, "\r{line}\x1B[K");
        let _ = stderr.flush();

        if done.load(Ordering::Relaxed) {
            // Final clear so the bar line is gone before subsequent prints.
            let _ = write!(stderr, "\r\x1B[K");
            let _ = stderr.flush();
            break;
        }
        tick = tick.wrapping_add(1);
        std::thread::sleep(Duration::from_millis(125));
    }
}

/// Extract text from OOXML (.docx/.xlsx/.pptx) by concatenating all <w:t>, <t> text nodes
/// inside the embedded XML parts.
fn read_office_ooxml(path: &Path) -> Result<String> {
    use std::io::Read;
    let file = std::fs::File::open(path)?;
    let mut zip = zip::ZipArchive::new(file)?;
    let mut text = String::new();
    let xml_names: Vec<String> = (0..zip.len())
        .filter_map(|i| zip.by_index(i).ok().map(|f| f.name().to_string()))
        .filter(|n| {
            n.ends_with(".xml")
                && (n.starts_with("word/")
                    || n.starts_with("xl/")
                    || n.starts_with("ppt/"))
        })
        .collect();
    for name in xml_names {
        let mut zf = match zip.by_name(&name) {
            Ok(f) => f,
            Err(_) => continue,
        };
        let mut buf = String::new();
        if zf.read_to_string(&mut buf).is_err() {
            continue;
        }
        extract_xml_text(&buf, &mut text);
        text.push('\n');
    }
    Ok(text)
}

fn extract_xml_text(xml: &str, out: &mut String) {
    use quick_xml::events::Event;
    use quick_xml::Reader;
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();
    let mut capture_depth = 0i32;
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let name = e.name();
                let local = name.local_name();
                let l = local.as_ref();
                if l == b"t" || l == b"v" || l == b"si" {
                    capture_depth += 1;
                }
            }
            Ok(Event::End(e)) => {
                let name = e.name();
                let local = name.local_name();
                let l = local.as_ref();
                if l == b"t" || l == b"v" || l == b"si" {
                    capture_depth -= 1;
                }
            }
            Ok(Event::Text(t)) => {
                if capture_depth > 0 {
                    if let Ok(s) = t.unescape() {
                        out.push_str(&s);
                        out.push(' ');
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
}

/// Best-effort text extraction from legacy .doc/.xls/.ppt (OLE Compound Document).
/// We combine three views of the raw bytes so that keywords in any common encoding
/// have a chance of matching:
///   1. ASCII printable runs (catches English / numbers / URLs / emails)
///   2. UTF-16 LE decode of the full byte stream (catches modern Word's wide-char text,
///      where Chinese is stored as pairs of bytes)
///   3. Big5 + GBK decode (catches older docs created on ZH-Hant/ZH-Hans systems)
/// Junk bytes in each decoded view are harmless — aho-corasick only reports real
/// keyword matches.
fn read_legacy_office(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path)?;

    let mut out = String::with_capacity(bytes.len());

    // (1) ASCII runs
    let mut run = Vec::<u8>::with_capacity(64);
    for &b in &bytes {
        if (0x20..=0x7E).contains(&b) || b == b'\n' || b == b'\t' {
            run.push(b);
        } else {
            if run.len() >= 4 {
                if let Ok(s) = std::str::from_utf8(&run) {
                    out.push_str(s);
                    out.push('\n');
                }
            }
            run.clear();
        }
    }
    if run.len() >= 4 {
        if let Ok(s) = std::str::from_utf8(&run) {
            out.push_str(s);
        }
    }

    // (2) UTF-16 LE — modern Word/Excel store strings as wide chars inside CFB streams.
    //     Decoding the entire blob produces some garbage, but real text is recovered.
    //     We try both byte-alignments because text can start at an odd offset inside
    //     the CFB container, and a 1-byte shift turns Chinese into garbage.
    out.push('\n');
    let (utf16_a, _, _) = encoding_rs::UTF_16LE.decode(&bytes);
    out.push_str(&filter_decoded(&utf16_a));
    if bytes.len() > 1 {
        out.push('\n');
        let (utf16_b, _, _) = encoding_rs::UTF_16LE.decode(&bytes[1..]);
        out.push_str(&filter_decoded(&utf16_b));
    }

    // (3) Big5 / GBK — Office 97-2003 ZH documents commonly used these.
    out.push('\n');
    let (big5, _, _) = encoding_rs::BIG5.decode(&bytes);
    out.push_str(&filter_decoded(&big5));
    out.push('\n');
    let (gbk, _, _) = encoding_rs::GBK.decode(&bytes);
    out.push_str(&filter_decoded(&gbk));

    Ok(out)
}

/// Drop control chars and stray replacement chars so the haystack doesn't blow up
/// in memory and so the matcher's context windows stay readable.
fn filter_decoded(s: &str) -> String {
    let mut out = String::with_capacity(s.len() / 2);
    let mut last_space = false;
    for ch in s.chars() {
        if ch == '\u{FFFD}' || ch.is_control() && ch != '\n' && ch != '\t' {
            if !last_space {
                out.push(' ');
                last_space = true;
            }
        } else {
            out.push(ch);
            last_space = false;
        }
    }
    out
}

/// Extract text from a PDF using lopdf directly. We avoid the higher-level
/// `pdf-extract` crate because it emits debug println!/eprintln! messages
/// ("Unicode mismatch", "unknown glyph name") that obliterate the progress bar.
/// catch_unwind shields the parallel scan from panics in malformed PDFs.
fn read_pdf(path: &Path) -> Result<String> {
    let path_owned = path.to_path_buf();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || -> std::result::Result<String, lopdf::Error> {
            let doc = lopdf::Document::load(&path_owned)?;
            let page_nums: Vec<u32> = doc.get_pages().keys().copied().collect();
            doc.extract_text(&page_nums)
        },
    ));
    match result {
        Ok(Ok(s)) => Ok(s),
        _ => Ok(String::new()),
    }
}
