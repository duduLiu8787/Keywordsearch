use crate::matcher::Matcher;
use crate::report::{KeywordHit, MatchRecord, Section};
use anyhow::Result;
use rusqlite::OpenFlags;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Locate browser profile directories and search History/places SQLite DBs.
/// Supports Chrome, Edge, Brave (Chromium-family) and Firefox.
pub fn scan(matcher: &Matcher) -> Result<Vec<MatchRecord>> {
    let mut records = Vec::new();
    for profile in chromium_family_profiles() {
        let history = profile.path.join("History");
        if history.exists() {
            if let Ok(mut rs) = scan_chromium_history(&history, &profile.label, matcher) {
                records.append(&mut rs);
            }
        }
    }
    for profile in firefox_profiles() {
        let places = profile.path.join("places.sqlite");
        if places.exists() {
            if let Ok(mut rs) = scan_firefox_places(&places, &profile.label, matcher) {
                records.append(&mut rs);
            }
        }
    }
    Ok(records)
}

struct Profile {
    label: String,
    path: PathBuf,
}

fn user_dirs() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if cfg!(windows) {
        if let Ok(v) = std::env::var("USERPROFILE") {
            out.push(PathBuf::from(v));
        }
    } else if let Ok(v) = std::env::var("HOME") {
        out.push(PathBuf::from(v));
    }
    out
}

#[cfg(windows)]
fn appdata_local() -> Option<PathBuf> {
    std::env::var("LOCALAPPDATA").ok().map(PathBuf::from)
}
#[cfg(not(windows))]
fn appdata_local() -> Option<PathBuf> {
    None
}

#[cfg(windows)]
fn appdata_roaming() -> Option<PathBuf> {
    std::env::var("APPDATA").ok().map(PathBuf::from)
}
#[cfg(not(windows))]
fn appdata_roaming() -> Option<PathBuf> {
    None
}

/// All Chromium-family browsers we look for, with their per-platform `User Data` roots.
fn chromium_family_profiles() -> Vec<Profile> {
    let mut out = Vec::new();
    let entries: &[(&str, &[&str], &[&str], &[&str])] = &[
        // (label-prefix, win subpath under LOCALAPPDATA, macOS subpath under ~/Library/Application Support, linux subpath under ~)
        (
            "Chrome",
            &["Google", "Chrome", "User Data"],
            &["Google", "Chrome"],
            &[".config", "google-chrome"],
        ),
        (
            "Edge",
            &["Microsoft", "Edge", "User Data"],
            &["Microsoft Edge"],
            &[".config", "microsoft-edge"],
        ),
        (
            "Brave",
            &["BraveSoftware", "Brave-Browser", "User Data"],
            &["BraveSoftware", "Brave-Browser"],
            &[".config", "BraveSoftware", "Brave-Browser"],
        ),
    ];

    for (label, win, mac, lin) in entries {
        for base in chromium_bases(win, mac, lin) {
            if !base.exists() {
                continue;
            }
            for entry in std::fs::read_dir(&base).into_iter().flatten().flatten() {
                let p = entry.path();
                if !p.is_dir() {
                    continue;
                }
                let name = entry.file_name().to_string_lossy().into_owned();
                if name == "Default" || name.starts_with("Profile ") {
                    out.push(Profile {
                        label: format!("{} {}", label, name),
                        path: p,
                    });
                }
            }
        }
    }
    out
}

fn chromium_bases(win: &[&str], mac: &[&str], lin: &[&str]) -> Vec<PathBuf> {
    if cfg!(windows) {
        appdata_local()
            .map(|p| {
                let mut path = p;
                for seg in win {
                    path = path.join(seg);
                }
                vec![path]
            })
            .unwrap_or_default()
    } else if cfg!(target_os = "macos") {
        user_dirs()
            .into_iter()
            .map(|h| {
                let mut p = h.join("Library").join("Application Support");
                for seg in mac {
                    p = p.join(seg);
                }
                p
            })
            .collect()
    } else {
        user_dirs()
            .into_iter()
            .map(|h| {
                let mut p = h;
                for seg in lin {
                    p = p.join(seg);
                }
                p
            })
            .collect()
    }
}

fn firefox_profiles() -> Vec<Profile> {
    let mut out = Vec::new();
    let bases: Vec<PathBuf> = if cfg!(windows) {
        appdata_roaming()
            .map(|p| vec![p.join("Mozilla").join("Firefox").join("Profiles")])
            .unwrap_or_default()
    } else if cfg!(target_os = "macos") {
        user_dirs()
            .into_iter()
            .map(|h| h.join("Library/Application Support/Firefox/Profiles"))
            .collect()
    } else {
        user_dirs()
            .into_iter()
            .map(|h| h.join(".mozilla/firefox"))
            .collect()
    };
    for base in bases {
        if !base.exists() {
            continue;
        }
        for entry in std::fs::read_dir(&base).into_iter().flatten().flatten() {
            let p = entry.path();
            if !p.is_dir() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            out.push(Profile {
                label: format!("Firefox {}", name),
                path: p,
            });
        }
    }
    out
}

/// A read-only SQLite snapshot. Copies the source DB (and -wal / -shm if present)
/// to a temp directory so live browsers holding write locks don't block us, then
/// returns the temp path. The Drop impl deletes the temp dir.
struct DbSnapshot {
    _tmp_dir: tempdir::TempDir,
    pub path: PathBuf,
}

/// Hand-rolled minimal tempdir replacement to avoid pulling in an extra crate.
mod tempdir {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    pub struct TempDir(PathBuf);
    impl TempDir {
        pub fn new(prefix: &str) -> std::io::Result<Self> {
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let n = SEQ.fetch_add(1, Ordering::Relaxed);
            let pid = std::process::id();
            let p = std::env::temp_dir().join(format!("{}-{}-{}", prefix, pid, n));
            std::fs::create_dir_all(&p)?;
            Ok(TempDir(p))
        }
        pub fn path(&self) -> &std::path::Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

fn snapshot_db(src: &Path) -> std::io::Result<DbSnapshot> {
    let tmp = tempdir::TempDir::new("forensic_db")?;
    let dst = tmp.path().join(
        src.file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("db.sqlite")),
    );
    std::fs::copy(src, &dst)?;
    // Also copy WAL / SHM sidecar files if present — without them SQLite may not
    // see committed-but-not-yet-checkpointed data.
    for suffix in ["-wal", "-shm"] {
        let mut sidecar = src.as_os_str().to_owned();
        sidecar.push(suffix);
        let sidecar = PathBuf::from(sidecar);
        if sidecar.exists() {
            let mut dst_sidecar = dst.as_os_str().to_owned();
            dst_sidecar.push(suffix);
            let _ = std::fs::copy(&sidecar, PathBuf::from(dst_sidecar));
        }
    }
    Ok(DbSnapshot {
        _tmp_dir: tmp,
        path: dst,
    })
}

/// Open the snapshot read-only.
fn open_ro(path: &Path) -> rusqlite::Result<rusqlite::Connection> {
    rusqlite::Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
}

fn scan_chromium_history(db: &Path, label: &str, matcher: &Matcher) -> Result<Vec<MatchRecord>> {
    let snap = match snapshot_db(db) {
        Ok(s) => s,
        Err(_) => return Ok(Vec::new()),
    };
    let conn = match open_ro(&snap.path) {
        Ok(c) => c,
        Err(_) => return Ok(Vec::new()),
    };
    let mut stmt = match conn.prepare("SELECT url, title FROM urls") {
        Ok(s) => s,
        Err(_) => return Ok(Vec::new()),
    };
    let rows = stmt.query_map([], |row| {
        let url: String = row.get(0).unwrap_or_default();
        let title: String = row.get(1).unwrap_or_default();
        Ok((url, title))
    })?;
    let mut records = Vec::new();
    let origin = db.display().to_string();
    for r in rows.flatten() {
        let (url, title) = r;
        if let Some(rec) = scan_row(matcher, &url, &title, label, &origin) {
            records.push(rec);
        }
    }
    Ok(records)
}

fn scan_firefox_places(db: &Path, label: &str, matcher: &Matcher) -> Result<Vec<MatchRecord>> {
    let snap = match snapshot_db(db) {
        Ok(s) => s,
        Err(_) => return Ok(Vec::new()),
    };
    let conn = match open_ro(&snap.path) {
        Ok(c) => c,
        Err(_) => return Ok(Vec::new()),
    };
    let mut stmt = match conn.prepare("SELECT url, title FROM moz_places") {
        Ok(s) => s,
        Err(_) => return Ok(Vec::new()),
    };
    let rows = stmt.query_map([], |row| {
        let url: String = row.get(0).unwrap_or_default();
        let title: String = row.get::<_, Option<String>>(1)?.unwrap_or_default();
        Ok((url, title))
    })?;
    let mut records = Vec::new();
    let origin = db.display().to_string();
    for r in rows.flatten() {
        let (url, title) = r;
        if let Some(rec) = scan_row(matcher, &url, &title, label, &origin) {
            records.push(rec);
        }
    }
    Ok(records)
}

/// One row in the history table → at most one MatchRecord with aggregated, deduped hits.
/// Matches against `url + " | " + title` (mirrors the Python tool's combined-field strategy).
fn scan_row(
    matcher: &Matcher,
    url: &str,
    title: &str,
    label: &str,
    db_path: &str,
) -> Option<MatchRecord> {
    if url.is_empty() && title.is_empty() {
        return None;
    }
    let combined = if title.is_empty() {
        url.to_string()
    } else {
        format!("{} | {}", url, title)
    };
    let mut seen: HashSet<(String, bool)> = HashSet::new();
    let mut hits: Vec<KeywordHit> = Vec::new();
    for h in matcher.find_all(&combined) {
        let key = (h.keyword.pattern.clone(), h.keyword.case_sensitive);
        if !seen.insert(key) {
            continue;
        }
        let ctx = if combined.chars().count() > 200 {
            // Take first 200 chars (char-aware truncation)
            let cut = combined
                .char_indices()
                .nth(200)
                .map(|(i, _)| i)
                .unwrap_or(combined.len());
            format!("{}…", &combined[..cut])
        } else {
            combined.clone()
        };
        hits.push(KeywordHit {
            keyword: h.keyword.pattern.clone(),
            case_sensitive: h.keyword.case_sensitive,
            line: None,
            context: ctx,
        });
    }
    if hits.is_empty() {
        return None;
    }
    Some(MatchRecord {
        section: Section::BrowserHistory,
        source: label.to_string(),
        location: format!("{}  {}", db_path, url),
        hits,
    })
}
