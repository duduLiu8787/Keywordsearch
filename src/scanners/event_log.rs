use crate::matcher::Matcher;
use crate::report::{KeywordHit, MatchRecord, Section};
use anyhow::Result;
use std::collections::HashSet;
use std::process::Command;

const CHANNELS: &[&str] = &[
    "Application",
    "Security",
    "System",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
];

/// Use `wevtutil qe <channel> /f:text`. One MatchRecord per event with keyword hits deduped.
pub fn scan(matcher: &Matcher) -> Result<Vec<MatchRecord>> {
    let mut records = Vec::new();
    for chan in CHANNELS {
        let output = Command::new("wevtutil")
            .args(["qe", chan, "/rd:false", "/f:text"])
            .output();
        let output = match output {
            Ok(o) => o,
            Err(_) => continue,
        };
        if !output.status.success() {
            continue;
        }
        let text = match std::str::from_utf8(&output.stdout) {
            Ok(s) => s.to_string(),
            Err(_) => {
                let mut det = chardetng::EncodingDetector::new();
                det.feed(&output.stdout, true);
                let enc = det.guess(None, true);
                enc.decode(&output.stdout).0.into_owned()
            }
        };
        scan_channel_text(chan, &text, matcher, &mut records);
    }
    Ok(records)
}

fn scan_channel_text(channel: &str, text: &str, matcher: &Matcher, out: &mut Vec<MatchRecord>) {
    // Split on blank lines — wevtutil's text format separates events that way.
    for (idx, block) in text.split("\n\n").enumerate() {
        if block.trim().is_empty() {
            continue;
        }
        let mut seen: HashSet<(String, bool)> = HashSet::new();
        let mut hits: Vec<KeywordHit> = Vec::new();
        for h in matcher.find_all(block) {
            let key = (h.keyword.pattern.clone(), h.keyword.case_sensitive);
            if !seen.insert(key) {
                continue;
            }
            hits.push(KeywordHit {
                keyword: h.keyword.pattern.clone(),
                case_sensitive: h.keyword.case_sensitive,
                line: None,
                context: make_context(block, h.start, h.end),
            });
        }
        if !hits.is_empty() {
            out.push(MatchRecord {
                section: Section::EventLog,
                source: channel.to_string(),
                location: format!("Event #{}", idx + 1),
                hits,
            });
        }
    }
}

/// Tight context window guaranteed to contain the matched keyword.
fn make_context(s: &str, start: usize, end: usize) -> String {
    const HALF: usize = 80;
    let pre_chars: usize = s[..start].chars().count();
    let skip_chars = pre_chars.saturating_sub(HALF);
    let before_byte = if skip_chars == 0 {
        0
    } else {
        s.char_indices()
            .nth(skip_chars)
            .map(|(i, _)| i)
            .unwrap_or(start)
    };
    let after_byte = s[end..]
        .char_indices()
        .nth(HALF)
        .map(|(i, _)| end + i)
        .unwrap_or(s.len());
    let mut out = String::new();
    if before_byte > 0 {
        out.push('…');
    }
    let mut last_space = false;
    for ch in s[before_byte..after_byte].chars() {
        let mapped = if matches!(ch, '\n' | '\r' | '\t') { ' ' } else { ch };
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
    if after_byte < s.len() {
        out.push('…');
    }
    out
}
