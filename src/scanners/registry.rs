use crate::matcher::Matcher;
use crate::report::{KeywordHit, MatchRecord, Section};
use anyhow::Result;
use std::collections::HashSet;
use winreg::enums::*;
use winreg::RegKey;

const MAX_DEPTH: usize = 6;

const SKIP_SUBKEYS: &[&str] = &[
    // Volatile / huge / noisy
    "HARDWARE",
    "DRIVERS",
    "RNG",
];

pub fn scan(matcher: &Matcher) -> Result<Vec<MatchRecord>> {
    let mut out = Vec::new();
    let hives: &[(isize, &str)] = &[
        (HKEY_LOCAL_MACHINE as isize, "HKLM"),
        (HKEY_CURRENT_USER as isize, "HKCU"),
        (HKEY_USERS as isize, "HKU"),
    ];
    for (h, name) in hives {
        let key = RegKey::predef(*h as winreg::HKEY);
        walk(&key, name, 0, matcher, &mut out);
    }
    Ok(out)
}

fn walk(key: &RegKey, path: &str, depth: usize, matcher: &Matcher, out: &mut Vec<MatchRecord>) {
    if depth > MAX_DEPTH {
        return;
    }
    // Per-value aggregation: one MatchRecord per (key, value name) with deduped keyword hits
    // matched against value name + value data.
    for v in key.enum_values().flatten() {
        let (name, value) = v;
        let value_str = format!("{:?}", value);
        let location = format!("{}\\{}", path, name);

        let mut seen: HashSet<(String, bool)> = HashSet::new();
        let mut hits: Vec<KeywordHit> = Vec::new();
        // Match value name
        for h in matcher.find_all(&name) {
            let key_id = (h.keyword.pattern.clone(), h.keyword.case_sensitive);
            if seen.insert(key_id) {
                hits.push(KeywordHit {
                    keyword: h.keyword.pattern.clone(),
                    case_sensitive: h.keyword.case_sensitive,
                    line: None,
                    context: format!("（value 名稱）{}", name),
                });
            }
        }
        // Match value data
        for h in matcher.find_all(&value_str) {
            let key_id = (h.keyword.pattern.clone(), h.keyword.case_sensitive);
            if !seen.insert(key_id) {
                continue;
            }
            hits.push(KeywordHit {
                keyword: h.keyword.pattern.clone(),
                case_sensitive: h.keyword.case_sensitive,
                line: None,
                context: truncate_chars(&value_str, 200),
            });
        }
        if !hits.is_empty() {
            out.push(MatchRecord {
                section: Section::Registry,
                source: "value".to_string(),
                location,
                hits,
            });
        }
    }

    for sub in key.enum_keys().flatten() {
        if SKIP_SUBKEYS.iter().any(|s| sub.eq_ignore_ascii_case(s)) {
            continue;
        }
        if let Ok(child) = key.open_subkey(&sub) {
            let new_path = format!("{}\\{}", path, sub);
            // Key-name hit aggregated as its own record (one record per matched subkey).
            let mut seen: HashSet<(String, bool)> = HashSet::new();
            let mut hits: Vec<KeywordHit> = Vec::new();
            for h in matcher.find_all(&sub) {
                let key_id = (h.keyword.pattern.clone(), h.keyword.case_sensitive);
                if seen.insert(key_id) {
                    hits.push(KeywordHit {
                        keyword: h.keyword.pattern.clone(),
                        case_sensitive: h.keyword.case_sensitive,
                        line: None,
                        context: sub.clone(),
                    });
                }
            }
            if !hits.is_empty() {
                out.push(MatchRecord {
                    section: Section::Registry,
                    source: "key name".to_string(),
                    location: new_path.clone(),
                    hits,
                });
            }
            walk(&child, &new_path, depth + 1, matcher, out);
        }
    }
}

fn truncate_chars(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_string();
    }
    let cut = s.char_indices().nth(n).map(|(i, _)| i).unwrap_or(s.len());
    format!("{}…", &s[..cut])
}
