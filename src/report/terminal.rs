use super::{CommsSummary, DetectionReport, KeywordHit, MatchRecord, RemoteAccessSummary, Section};
use owo_colors::{OwoColorize, Style};
use std::collections::BTreeMap;

const BAR_WIDTH: usize = 70;
const MAX_TERMINAL_RECORDS: usize = 5;
const KEYWORD_COL_WIDTH: usize = 24;

fn s_header() -> Style { Style::new().bright_cyan().bold() }
fn s_dim_bar() -> Style { Style::new().bright_black() }
fn s_path() -> Style { Style::new().bright_blue().underline() }
fn s_lineno() -> Style { Style::new().bright_black() }
fn s_keyword() -> Style { Style::new().yellow() }
fn s_hit_in_ctx() -> Style { Style::new().bright_red().bold() }
fn s_count_pos() -> Style { Style::new().bright_yellow().bold() }
fn s_count_zero() -> Style { Style::new().bright_black() }
fn s_found() -> Style { Style::new().bright_green() }
fn s_missing() -> Style { Style::new().bright_black() }
fn s_warning() -> Style { Style::new().bright_red().bold() }
fn s_pipe() -> Style { Style::new().bright_black() }

pub fn print_header(targets: &str, workers: usize, excludes: &[String], ext_count: usize) {
    println!("{}", "電腦採證快速搜尋工具 (Rust)".style(s_header()));
    println!("  搜尋目標：{}", targets.yellow());
    println!("  Workers：{}", workers.bright_white());
    println!("  排除路徑：{}", excludes.join(", "));
    println!(
        "  副檔名清單：{} 種（--list-extensions 檢視）",
        ext_count.bright_white()
    );
    println!();
}

/// Print a section header. If `count_label` is `Some`, it's shown right-aligned on the
/// same line as the title (e.g. "972 筆命中").
pub fn print_section(title: &str, count_label: Option<&str>) {
    let bar: String = "─".repeat(BAR_WIDTH);
    println!("{}", bar.style(s_dim_bar()));
    match count_label {
        Some(label) => {
            // Pad so the count sits flush right.
            let title_display = format!("  {}", title);
            let title_width = visible_width(&title_display);
            let label_width = visible_width(label);
            let pad = BAR_WIDTH.saturating_sub(title_width + label_width);
            println!(
                "{}{}{}",
                title_display.style(s_header()),
                " ".repeat(pad),
                label.style(s_count_pos())
            );
        }
        None => {
            println!("  {}", title.style(s_header()));
        }
    }
    println!("{}", bar.style(s_dim_bar()));
}

/// Render hit records (one record = one location with aggregated keyword hits).
/// Caps at `MAX_TERMINAL_RECORDS` entries and appends a tail hint pointing to the log.
pub fn print_hits_grouped(records: &[MatchRecord], log_filename: &str) {
    if records.is_empty() {
        println!();
        println!("  {}", "（未命中）".style(s_missing()));
        println!();
        return;
    }
    println!();

    for r in records.iter().take(MAX_TERMINAL_RECORDS) {
        print_one_record(r);
        println!();
    }
    if records.len() > MAX_TERMINAL_RECORDS {
        let remaining = records.len() - MAX_TERMINAL_RECORDS;
        println!(
            "  {}",
            format!("⋯ 其餘 {} 個位置已寫入 {}", remaining, log_filename)
                .style(s_dim_bar())
        );
        println!();
    }
}

fn print_one_record(r: &MatchRecord) {
    // Location header: path/URL/key, underlined blue.
    println!("{}", r.location.style(s_path()));
    for hit in &r.hits {
        print_one_hit(hit);
    }
}

fn print_one_hit(h: &KeywordHit) {
    let line_col = match h.line {
        Some(n) => format!("{:>5}", n),
        None => format!("{:>5}", "·"),
    };
    let kw_label = keyword_display(&h.keyword, h.case_sensitive);
    let kw_padded = pad_visual(&kw_label, KEYWORD_COL_WIDTH);
    let context = highlight(&h.context, &h.keyword, h.case_sensitive);
    println!(
        "  {}  {} {} {}",
        line_col.style(s_lineno()),
        kw_padded.style(s_keyword()),
        "│".style(s_pipe()),
        context
    );
}

/// Detection panel for the Remote Access scanner.
pub fn print_remote_access(s: &RemoteAccessSummary) {
    println!();
    let rdp_status = match s.rdp_enabled {
        Some(true) => "●  已啟用".style(s_warning()).to_string(),
        Some(false) => "○  已停用".style(s_dim_bar()).to_string(),
        None => "?  未知".style(s_dim_bar()).to_string(),
    };
    println!("  {:<22}  {}", "Windows RDP 功能", rdp_status);

    if !s.rdp_hosts.is_empty() {
        let label = format!("RDP 曾連線主機 ({})", s.rdp_hosts.len());
        for (i, h) in s.rdp_hosts.iter().enumerate() {
            if i == 0 {
                println!("  {:<22}  {}", label, h.bright_white());
            } else {
                println!("  {:<22}  {}", "", h.bright_white());
            }
        }
    }
    if !s.rdp_files.is_empty() {
        let label = format!(".rdp 設定檔 ({})", s.rdp_files.len());
        for (i, f) in s.rdp_files.iter().enumerate() {
            if i == 0 {
                println!("  {:<22}  {}", label, f.dimmed());
            } else {
                println!("  {:<22}  {}", "", f.dimmed());
            }
        }
    }
    println!();

    println!(
        "  {}  已發現工具",
        "✓".style(s_found())
    );
    if s.found_tools.is_empty() {
        println!("     {}", "（無）".style(s_missing()));
    } else {
        for t in &s.found_tools {
            println!("     {} {}", "●".style(s_warning()), t.name.bright_white());
            let n = t.evidence.len();
            for (i, ev) in t.evidence.iter().enumerate() {
                let glyph = if i + 1 == n { "└─" } else { "├─" };
                println!("        {} {}", glyph.style(s_pipe()), ev.dimmed());
            }
        }
    }
    println!();
    println!(
        "  {}  未發現工具 ({})",
        "✗".style(s_dim_bar()),
        s.missing_tools.len()
    );
    if !s.missing_tools.is_empty() {
        let wrapped = wrap_list(&s.missing_tools, "、", 60);
        for (i, line) in wrapped.iter().enumerate() {
            let prefix = if i == 0 { "     " } else { "     " };
            println!("{}{}", prefix, line.dimmed());
        }
    }
    println!();
}

/// Detection panel for the Comms scanner.
pub fn print_comms(s: &CommsSummary) {
    println!();
    println!(
        "  {}  已發現 ({})",
        "✓".style(s_found()),
        s.found.len()
    );
    if s.found.is_empty() {
        println!("     {}", "（無）".style(s_missing()));
    } else {
        for t in &s.found {
            println!("     {} {}", "●".style(s_warning()), t.name.bright_white());
            let n = t.evidence.len();
            for (i, ev) in t.evidence.iter().enumerate() {
                let glyph = if i + 1 == n { "└─" } else { "├─" };
                println!("        {} {}", glyph.style(s_pipe()), ev.dimmed());
            }
        }
    }
    println!();
    println!(
        "  {}  未發現 ({})",
        "✗".style(s_dim_bar()),
        s.missing.len()
    );
    if !s.missing.is_empty() {
        let wrapped = wrap_list(&s.missing, "、", 60);
        for line in &wrapped {
            println!("     {}", line.dimmed());
        }
    }
    println!();
}

pub fn print_summary(
    records: &[MatchRecord],
    detection: &DetectionReport,
    elapsed: std::time::Duration,
    txt_path: &str,
    jsonl_path: &str,
) {
    println!();
    let bar = "═".repeat(BAR_WIDTH);
    println!("{}", bar.green());
    println!("  {}", "彙整摘要".style(Style::new().bright_green().bold()));
    println!("{}", bar.green());

    // Per section: file/location count + total keyword-hit count
    let mut file_totals: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut hit_totals: BTreeMap<&'static str, usize> = BTreeMap::new();
    for r in records {
        *file_totals.entry(r.section.short()).or_insert(0) += 1;
        *hit_totals.entry(r.section.short()).or_insert(0) += r.hits.len();
    }
    let label_width = 18;
    for s in [
        Section::DiskText,
        Section::BrowserHistory,
        Section::EventLog,
        Section::Registry,
    ] {
        let files = file_totals.get(s.short()).copied().unwrap_or(0);
        let hits = hit_totals.get(s.short()).copied().unwrap_or(0);
        let display = if files == 0 {
            "0 個位置".to_string()
        } else {
            format!("{} 個位置 ({} 個關鍵字命中)", files, hits)
        };
        let colored = if files > 0 {
            display.style(s_count_pos()).to_string()
        } else {
            display.style(s_count_zero()).to_string()
        };
        println!("  {:<width$}  {}", s.short(), colored, width = label_width);
    }
    if let Some(ra) = &detection.remote_access {
        if ra.found_tools.is_empty() {
            println!(
                "  {:<width$}  {}",
                Section::RemoteAccess.short(),
                "未發現".style(s_count_zero()),
                width = label_width
            );
        } else {
            let names: Vec<&str> = ra.found_tools.iter().map(|t| t.name.as_str()).collect();
            println!(
                "  {:<width$}  {}",
                Section::RemoteAccess.short(),
                names.join("、").style(s_warning()),
                width = label_width
            );
        }
    }
    if let Some(comms) = &detection.comms {
        if comms.found.is_empty() {
            println!(
                "  {:<width$}  {}",
                Section::Comms.short(),
                "未發現".style(s_count_zero()),
                width = label_width
            );
        } else {
            let names: Vec<&str> = comms.found.iter().map(|t| t.name.as_str()).collect();
            println!(
                "  {:<width$}  {}",
                Section::Comms.short(),
                names.join("、").style(s_count_pos()),
                width = label_width
            );
        }
    }
    println!("  {}", "─".repeat(label_width + 16).style(s_dim_bar()));
    let total_locations = records.len();
    let total_hits: usize = records.iter().map(|r| r.hits.len()).sum();
    println!(
        "  {:<width$}  {}",
        "總計",
        format!("{} 個位置 ({} 個關鍵字命中)", total_locations, total_hits)
            .style(s_count_pos()),
        width = label_width
    );
    println!("{}", bar.green());

    let secs = elapsed.as_secs();
    println!(
        "  耗時：{}:{:02}:{:02}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    );
    println!();
    println!("  {} {}", "報告：".dimmed(), txt_path.bright_white());
    println!("  {} {}", "JSON ：".dimmed(), jsonl_path.bright_white());
}

// ─── helpers ─────────────────────────────────────────────────────────────

fn keyword_display(kw: &str, case_sensitive: bool) -> String {
    if case_sensitive {
        format!("\"{}\" 完全符合", kw)
    } else {
        kw.to_string()
    }
}

/// Highlight every keyword occurrence in `ctx` with bright_red bold.
fn highlight(ctx: &str, keyword: &str, case_sensitive: bool) -> String {
    if keyword.is_empty() {
        return ctx.to_string();
    }
    let mut out = String::new();
    let mut i = 0usize;
    let lower_ctx = if case_sensitive { String::new() } else { ctx.to_ascii_lowercase() };
    let lower_kw = if case_sensitive { String::new() } else { keyword.to_ascii_lowercase() };
    while i < ctx.len() {
        let found = if case_sensitive {
            ctx[i..].find(keyword)
        } else {
            lower_ctx[i..].find(&lower_kw)
        };
        match found {
            Some(pos) => {
                out.push_str(&ctx[i..i + pos]);
                let end = i + pos + keyword.len();
                if end > ctx.len() {
                    out.push_str(&ctx[i + pos..]);
                    break;
                }
                let seg = &ctx[i + pos..end];
                out.push_str(&seg.style(s_hit_in_ctx()).to_string());
                i = end;
            }
            None => {
                out.push_str(&ctx[i..]);
                break;
            }
        }
    }
    out
}

/// Approximate visual width: CJK / wide chars count as 2.
fn visible_width(s: &str) -> usize {
    let mut w = 0usize;
    for ch in s.chars() {
        // Strip ANSI escape sequences
        if ch == '\u{1b}' { continue; }
        w += if is_wide(ch) { 2 } else { 1 };
    }
    w
}

fn is_wide(ch: char) -> bool {
    let c = ch as u32;
    matches!(
        c,
        0x1100..=0x115F
        | 0x2E80..=0x303E
        | 0x3041..=0x33FF
        | 0x3400..=0x4DBF
        | 0x4E00..=0x9FFF
        | 0xA000..=0xA4CF
        | 0xAC00..=0xD7A3
        | 0xF900..=0xFAFF
        | 0xFE30..=0xFE4F
        | 0xFF00..=0xFF60
        | 0xFFE0..=0xFFE6
        | 0x20000..=0x2FFFD
        | 0x30000..=0x3FFFD
    )
}

/// Pad/truncate to a given visual column width (CJK aware).
fn pad_visual(s: &str, width: usize) -> String {
    let w = visible_width(s);
    if w == width {
        s.to_string()
    } else if w < width {
        format!("{}{}", s, " ".repeat(width - w))
    } else {
        // Truncate with ellipsis
        let mut out = String::new();
        let mut acc = 0usize;
        for ch in s.chars() {
            let chw = if is_wide(ch) { 2 } else { 1 };
            if acc + chw > width.saturating_sub(1) {
                break;
            }
            acc += chw;
            out.push(ch);
        }
        out.push('…');
        while visible_width(&out) < width {
            out.push(' ');
        }
        out
    }
}

/// Wrap a list-separated string into lines no wider than `max_width` visual chars.
fn wrap_list(items: &[String], sep: &str, max_width: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for (i, item) in items.iter().enumerate() {
        let needed = if i == 0 { item.len() } else { sep.len() + item.len() };
        if !cur.is_empty() && visible_width(&cur) + needed > max_width {
            out.push(cur);
            cur = String::new();
        }
        if !cur.is_empty() {
            cur.push_str(sep);
        }
        cur.push_str(item);
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}
