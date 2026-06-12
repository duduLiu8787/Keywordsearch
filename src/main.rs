mod config;
mod matcher;
mod report;
mod scanners;

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use std::time::Instant;

use config::{parse_targets, ExtensionSet, RunConfig};
use matcher::Matcher;
use report::{DetectionReport, MatchRecord, Section};

#[derive(Parser, Debug)]
#[command(version, about = "電腦採證快速搜尋工具 (Rust)", long_about = None)]
struct Cli {
    /// targets.txt 路徑（每行一個關鍵字；# 開頭為註解；"xxx" 表示區分大小寫）
    #[arg(short = 't', long, default_value = "targets.txt")]
    targets: PathBuf,

    /// 要掃描的根目錄（可重複指定，或逗號分隔）。預設：Windows 上掃所有磁碟，其他平台 $HOME。
    #[arg(short = 'r', long = "root", value_delimiter = ',')]
    roots: Vec<PathBuf>,

    /// 排除路徑（可重複指定，或逗號分隔）
    #[arg(short = 'x', long = "exclude", value_delimiter = ',')]
    excludes: Vec<PathBuf>,

    /// 關閉「自動排除 exe 所在磁碟與目錄」（預設會自動排除，避免掃到自己輸出的報告）
    #[arg(long)]
    no_auto_exclude: bool,

    /// Worker 數（預設 = 邏輯核心數 × 2，封頂 128。例：32 邏輯核 → 64）
    #[arg(short = 'w', long)]
    workers: Option<usize>,

    /// 輸出目錄
    #[arg(short = 'o', long, default_value = ".")]
    output_dir: PathBuf,

    /// 最大檔案大小（bytes）；超過則略過。預設 200 MB。
    #[arg(long, default_value_t = 200 * 1024 * 1024)]
    max_file_size: u64,

    /// 上下文字元數
    #[arg(long, default_value_t = 60)]
    context_chars: usize,

    /// 略過特定模組：disk,browser,event,registry,remote,comms（逗號分隔）
    #[arg(long, default_value = "")]
    skip: String,

    /// 副檔名清單檔（每行一個，# 註解；點號可有可無）。
    /// 若未提供且 exe 旁有 extensions.txt 會自動載入；都沒有則用內建預設。
    #[arg(long, value_name = "FILE")]
    ext_file: Option<PathBuf>,

    /// 直接以逗號分隔指定副檔名（會覆蓋 --ext-file 與內建預設）
    /// 例：--ext txt,csv,docx,xlsx
    #[arg(long, value_name = "LIST")]
    ext: Option<String>,

    /// 在內建/檔案副檔名清單上「加上」這些（逗號分隔）
    #[arg(long, value_name = "LIST")]
    ext_add: Option<String>,

    /// 從清單中「移除」這些副檔名（逗號分隔）
    #[arg(long, value_name = "LIST")]
    ext_remove: Option<String>,

    /// 列出最終生效的副檔名清單後立即退出
    #[arg(long)]
    list_extensions: bool,
}

fn main() -> Result<()> {
    // Suppress Windows' "no disk in drive" / "drive not ready" dialogs that would
    // otherwise pop up the moment we probe removable / mapped drives.
    #[cfg(windows)]
    {
        suppress_windows_error_dialogs();
        enable_vt_processing();
    }

    // Silence panic messages from third-party parsers (lopdf, etc) — we wrap their
    // calls in catch_unwind so the panics are handled, but the default hook would
    // still print a backtrace-ish line that interleaves with the progress bar.
    std::panic::set_hook(Box::new(|_| {}));

    // Immediate banner so the user sees something even if a later step fails.
    eprintln!("forensic_search 啟動中…");

    let cli = Cli::parse();

    // If launched by double-clicking (no parent console / no piped stdin),
    // pause at exit so the user can read the output.
    #[cfg(windows)]
    let pause_at_exit = launched_by_explorer();
    #[cfg(not(windows))]
    let pause_at_exit = false;

    let run_result = (|| -> Result<()> {
        run_main(cli)
    })();

    if pause_at_exit {
        eprintln!();
        eprintln!("執行結束，按 Enter 鍵關閉視窗...");
        let mut _buf = String::new();
        let _ = std::io::stdin().read_line(&mut _buf);
    }
    run_result
}

fn run_main(cli: Cli) -> Result<()> {
    // Resolve extension whitelist before anything else so --list-extensions
    // can exit early without needing a valid targets.txt.
    let extensions = resolve_extensions(&cli)?;
    if cli.list_extensions {
        let mut list: Vec<String> = extensions.extensions.iter().cloned().collect();
        list.sort();
        println!("生效的副檔名清單（共 {} 種）：", list.len());
        for ext in &list {
            println!("  .{}", ext);
        }
        if extensions.include_no_ext_special {
            println!();
            println!("無副檔名特殊檔名: {}", config::NO_EXT_TEXT_NAMES.join(", "));
        }
        return Ok(());
    }

    let keywords = parse_targets(&cli.targets)
        .with_context(|| format!("讀取 {} 失敗", cli.targets.display()))?;
    if keywords.is_empty() {
        anyhow::bail!("targets.txt 中沒有任何有效關鍵字");
    }

    let roots = if cli.roots.is_empty() {
        default_roots()
    } else {
        cli.roots.clone()
    };

    let mut excludes = cli.excludes.clone();
    if !cli.no_auto_exclude {
        for p in auto_excludes() {
            if !excludes.iter().any(|e| e == &p) {
                excludes.push(p);
            }
        }
    }

    let workers = cli.workers.unwrap_or_else(default_workers);
    rayon::ThreadPoolBuilder::new()
        .num_threads(workers)
        .build_global()
        .ok();

    let cfg = RunConfig {
        keywords: keywords.clone(),
        roots: roots.clone(),
        excludes: excludes.clone(),
        workers,
        context_chars: cli.context_chars,
        output_dir: cli.output_dir.clone(),
        max_file_size: cli.max_file_size,
        extensions: extensions.clone(),
    };

    let matcher = Matcher::build(&keywords)?;

    let targets_display = keywords
        .iter()
        .map(|k| k.display_label())
        .collect::<Vec<_>>()
        .join(" | ");
    let excludes_display: Vec<String> =
        cfg.excludes.iter().map(|p| p.display().to_string()).collect();

    report::terminal::print_header(
        &targets_display,
        workers,
        &excludes_display,
        extensions.extensions.len(),
    );

    let skip: std::collections::HashSet<String> = cli
        .skip
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();

    let started_at = chrono::Local::now();
    let t0 = Instant::now();

    // Compute output paths up-front so terminal can mention the log filename
    // in tail hints ("⋯ 其餘 N 筆已寫入 ...").
    std::fs::create_dir_all(&cfg.output_dir)?;
    let stamp = started_at.format("%Y%m%d_%H%M%S").to_string();
    let txt_path = cfg.output_dir.join(format!("forensic_result_{}.txt", stamp));
    let jsonl_path = cfg
        .output_dir
        .join(format!("forensic_result_{}.jsonl", stamp));
    let html_path = cfg.output_dir.join(format!("forensic_result_{}.html", stamp));
    let log_basename = txt_path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "forensic_result.txt".to_string());

    let mut records: Vec<MatchRecord> = Vec::new();
    #[allow(unused_mut)]
    let mut detection = DetectionReport::default();

    // Run the four keyword scanners in parallel. Disk runs on the main scope
    // thread so its progress bar is visible; the other three (browser, event,
    // registry) finish much sooner and silently. After all four return we
    // print results in a fixed order.
    let do_disk = !skip.contains("disk");
    let do_browser = !skip.contains("browser");
    let do_event = !skip.contains("event");
    let do_registry = !skip.contains("registry");

    let (disk_rs, browser_rs, event_rs, registry_rs) = std::thread::scope(|s| {
        let browser_h = do_browser.then(|| {
            s.spawn(|| scanners::browser::scan(&matcher).unwrap_or_default())
        });
        #[cfg(windows)]
        let event_h = do_event.then(|| {
            s.spawn(|| scanners::event_log::scan(&matcher).unwrap_or_default())
        });
        #[cfg(windows)]
        let registry_h = do_registry.then(|| {
            s.spawn(|| scanners::registry::scan(&matcher).unwrap_or_default())
        });
        #[cfg(not(windows))]
        let _ = (do_event, do_registry);

        let disk = if do_disk {
            match scanners::disk_files::scan(&cfg, &matcher) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("disk scan error: {e}");
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };

        let browser = browser_h.map(|h| h.join().unwrap_or_default()).unwrap_or_default();
        #[cfg(windows)]
        let event = event_h.map(|h| h.join().unwrap_or_default()).unwrap_or_default();
        #[cfg(not(windows))]
        let event: Vec<MatchRecord> = Vec::new();
        #[cfg(windows)]
        let registry = registry_h.map(|h| h.join().unwrap_or_default()).unwrap_or_default();
        #[cfg(not(windows))]
        let registry: Vec<MatchRecord> = Vec::new();

        (disk, browser, event, registry)
    });

    // Render sections in a stable order, regardless of which scanner finished first.
    if do_disk {
        report::terminal::print_section(
            Section::DiskText.title(),
            Some(&format!("{} 個位置", disk_rs.len())),
        );
        report::terminal::print_hits_grouped(&disk_rs, &log_basename);
    }
    if do_browser {
        report::terminal::print_section(
            Section::BrowserHistory.title(),
            Some(&format!("{} 個位置", browser_rs.len())),
        );
        report::terminal::print_hits_grouped(&browser_rs, &log_basename);
    }
    #[cfg(windows)]
    {
        if do_event {
            report::terminal::print_section(
                Section::EventLog.title(),
                Some(&format!("{} 個位置", event_rs.len())),
            );
            report::terminal::print_hits_grouped(&event_rs, &log_basename);
        }
        if do_registry {
            report::terminal::print_section(
                Section::Registry.title(),
                Some(&format!("{} 個位置", registry_rs.len())),
            );
            report::terminal::print_hits_grouped(&registry_rs, &log_basename);
        }
    }

    records.extend(disk_rs);
    records.extend(browser_rs);
    records.extend(event_rs);
    records.extend(registry_rs);

    #[cfg(windows)]
    {
        if !skip.contains("remote") {
            match scanners::remote_access::scan() {
                Ok(s) => {
                    report::terminal::print_section(Section::RemoteAccess.title(), None);
                    report::terminal::print_remote_access(&s);
                    detection.remote_access = Some(s);
                }
                Err(e) => eprintln!("remote access scan error: {e}"),
            }
        }
        if !skip.contains("comms") {
            match scanners::comms::scan() {
                Ok(s) => {
                    report::terminal::print_section(Section::Comms.title(), None);
                    report::terminal::print_comms(&s);
                    detection.comms = Some(s);
                }
                Err(e) => eprintln!("comms scan error: {e}"),
            }
        }
    }

    let elapsed = t0.elapsed();

    let text_report = report::text::TextReport {
        started_at,
        targets_display,
        workers,
        excludes: excludes_display,
    };
    text_report.write(&txt_path, &records, &detection, elapsed)?;
    report::jsonl::write(&jsonl_path, &records, &detection)?;
    report::html::HtmlReport {
        started_at: &started_at,
        targets_display: &text_report.targets_display,
        workers,
        excludes: &text_report.excludes,
        elapsed,
    }.write(&html_path, &records, &detection)?;

    report::terminal::print_summary(
        &records,
        &detection,
        elapsed,
        &txt_path.display().to_string(),
        &jsonl_path.display().to_string(),
    );

    Ok(())
}

/// Paths that should be automatically excluded:
/// - The directory containing the running exe (so we don't re-ingest our own output files)
/// - The drive root the exe lives on (matches the original Python tool's behavior)
///
/// On non-Windows platforms we only return the exe's parent directory.
/// Resolve the extension whitelist using this priority:
///   1. `--ext "a,b,c"` (full override)
///   2. `--ext-file PATH`
///   3. Auto-load `extensions.txt` from CWD or next to the exe
///   4. Built-in defaults
/// `--ext-add` and `--ext-remove` are applied on top of whatever was chosen.
fn resolve_extensions(cli: &Cli) -> Result<ExtensionSet> {
    let mut set = if let Some(list) = &cli.ext {
        ExtensionSet::from_strings(list.split(','))
    } else if let Some(path) = &cli.ext_file {
        ExtensionSet::from_file(path)
            .with_context(|| format!("讀取副檔名清單 {} 失敗", path.display()))?
    } else if let Some(p) = autodetect_ext_file() {
        eprintln!("(載入副檔名清單：{})", p.display());
        ExtensionSet::from_file(&p)
            .with_context(|| format!("讀取副檔名清單 {} 失敗", p.display()))?
    } else {
        ExtensionSet::from_defaults()
    };
    if let Some(add) = &cli.ext_add {
        for e in add.split(',') {
            let e = e.trim().trim_start_matches('.').to_ascii_lowercase();
            if !e.is_empty() {
                set.extensions.insert(e);
            }
        }
    }
    if let Some(rm) = &cli.ext_remove {
        for e in rm.split(',') {
            let e = e.trim().trim_start_matches('.').to_ascii_lowercase();
            set.extensions.remove(&e);
        }
    }
    Ok(set)
}

/// Look for an extensions.txt next to the exe or in the current working directory.
fn autodetect_ext_file() -> Option<PathBuf> {
    let cwd_candidate = std::path::PathBuf::from("extensions.txt");
    if cwd_candidate.exists() {
        return Some(cwd_candidate);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let p = parent.join("extensions.txt");
            if p.exists() {
                return Some(p);
            }
        }
    }
    None
}

fn auto_excludes() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return out,
    };
    // Canonicalize defensively; on Windows this returns `\\?\` verbatim paths,
    // which both look ugly in reports AND break `Path::starts_with` against the
    // non-verbatim paths produced by walkdir. Strip the prefix.
    let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
    let exe = strip_verbatim_prefix(&exe);
    if let Some(parent) = exe.parent() {
        out.push(parent.to_path_buf());
    }
    #[cfg(windows)]
    {
        if let Some(drive) = drive_root(&exe) {
            out.push(drive);
        }
    }
    out
}

#[cfg(windows)]
fn strip_verbatim_prefix(p: &std::path::Path) -> PathBuf {
    let s = p.to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{}", rest));
    }
    if let Some(rest) = s.strip_prefix(r"\\?\") {
        return PathBuf::from(rest);
    }
    p.to_path_buf()
}
#[cfg(not(windows))]
fn strip_verbatim_prefix(p: &std::path::Path) -> PathBuf {
    p.to_path_buf()
}

#[cfg(windows)]
fn drive_root(path: &std::path::Path) -> Option<PathBuf> {
    use std::path::Component;
    let mut comps = path.components();
    match comps.next() {
        Some(Component::Prefix(prefix)) => {
            // Build "<prefix>\" — e.g. "D:\"
            let mut root = std::ffi::OsString::from(prefix.as_os_str());
            root.push("\\");
            Some(PathBuf::from(root))
        }
        _ => None,
    }
}

fn default_roots() -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        // Use the kernel's bitmask of mounted drives instead of probing each letter
        // with fs::exists(). Probing A:\ on a system with no floppy used to trigger
        // a "Please insert disk" hardware dialog; on modern Windows, removable /
        // virtual drives mapped to optional features can also pop up an installer
        // window. GetLogicalDrives is a pure in-kernel call.
        let mut out = Vec::new();
        let mask = unsafe { GetLogicalDrives() };
        for i in 0..26u32 {
            if mask & (1 << i) != 0 {
                let letter = (b'A' + i as u8) as char;
                let p = PathBuf::from(format!("{}:\\", letter));
                // Filter out CD-ROM / removable so we don't spin up media. Fixed disks only.
                let kind = drive_kind(letter);
                if matches!(kind, DriveKind::Fixed | DriveKind::Network) {
                    out.push(p);
                }
            }
        }
        out
    }
    #[cfg(not(windows))]
    {
        std::env::var("HOME")
            .ok()
            .map(|h| vec![PathBuf::from(h)])
            .unwrap_or_else(|| vec![PathBuf::from(".")])
    }
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DriveKind { Unknown, NoRoot, Removable, Fixed, Network, CdRom, Ram }

#[cfg(windows)]
fn drive_kind(letter: char) -> DriveKind {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    let path = format!("{}:\\", letter);
    let wide: Vec<u16> = OsStr::new(&path).encode_wide().chain(std::iter::once(0)).collect();
    let t = unsafe { GetDriveTypeW(wide.as_ptr()) };
    match t {
        0 => DriveKind::Unknown,
        1 => DriveKind::NoRoot,
        2 => DriveKind::Removable,
        3 => DriveKind::Fixed,
        4 => DriveKind::Network,
        5 => DriveKind::CdRom,
        6 => DriveKind::Ram,
        _ => DriveKind::Unknown,
    }
}

#[cfg(windows)]
extern "system" {
    fn GetLogicalDrives() -> u32;
    fn GetDriveTypeW(lpRootPathName: *const u16) -> u32;
    fn SetErrorMode(uMode: u32) -> u32;
    fn GetConsoleProcessList(lpdwProcessList: *mut u32, dwProcessCount: u32) -> u32;
    fn GetStdHandle(nStdHandle: u32) -> *mut core::ffi::c_void;
    fn GetConsoleMode(hConsoleHandle: *mut core::ffi::c_void, lpMode: *mut u32) -> i32;
    fn SetConsoleMode(hConsoleHandle: *mut core::ffi::c_void, dwMode: u32) -> i32;
    fn SetConsoleOutputCP(wCodePageID: u32) -> i32;
}

#[cfg(windows)]
fn suppress_windows_error_dialogs() {
    // SEM_FAILCRITICALERRORS (0x0001) | SEM_NOOPENFILEERRORBOX (0x8000)
    unsafe { SetErrorMode(0x0001 | 0x8000); }
}

/// Switch the Windows console to UTF-8 and enable ANSI escape sequence processing.
/// Without ENABLE_VIRTUAL_TERMINAL_PROCESSING (0x0004), cmd.exe prints escape codes
/// as literal "ESC[..." garbage instead of interpreting colors and cursor moves.
#[cfg(windows)]
fn enable_vt_processing() {
    const STD_OUTPUT_HANDLE: u32 = (-11i32) as u32;
    const STD_ERROR_HANDLE: u32 = (-12i32) as u32;
    const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
    const CP_UTF8: u32 = 65001;
    unsafe {
        SetConsoleOutputCP(CP_UTF8);
        for h_id in [STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
            let h = GetStdHandle(h_id);
            if h.is_null() { continue; }
            let mut mode: u32 = 0;
            if GetConsoleMode(h, &mut mode) != 0 {
                SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
            }
        }
    }
}

/// Heuristic: if the only process attached to our console is ourselves, we were
/// almost certainly launched by double-click (Explorer creates a fresh console).
/// When run from cmd / PowerShell, the shell is also attached → count >= 2.
#[cfg(windows)]
fn launched_by_explorer() -> bool {
    let mut buf = [0u32; 4];
    let count = unsafe { GetConsoleProcessList(buf.as_mut_ptr(), buf.len() as u32) };
    count <= 1
}

/// Default worker count = 2× logical processors, matching the original Python tool's
/// behavior. The 2× oversubscription overlaps disk I/O waits with CPU work
/// (decoding + aho-corasick) and is well suited to scanning many small files.
/// Capped at 128 to avoid pathological behavior on extreme core-count machines.
fn default_workers() -> usize {
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    (cores * 2).min(128)
}
