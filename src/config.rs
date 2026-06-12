use anyhow::{Context, Result};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// A single keyword loaded from targets.txt.
#[derive(Debug, Clone)]
pub struct Keyword {
    /// The exact pattern string (after stripping wrapping quotes).
    pub pattern: String,
    /// Quoted (`"xxx"`) → case-sensitive; unquoted → case-insensitive.
    pub case_sensitive: bool,
}

impl Keyword {
    /// Pretty label for the report (mirrors the Python tool's "完全符合" suffix).
    pub fn display_label(&self) -> String {
        if self.case_sensitive {
            format!("\"{}\"（完全符合）", self.pattern)
        } else {
            self.pattern.clone()
        }
    }
}

/// Parses targets.txt:
///   - Lines starting with `#` are comments
///   - Blank lines are ignored
///   - Lines wrapped in `"..."` are case-sensitive
///   - Everything else is case-insensitive substring
pub fn parse_targets<P: AsRef<Path>>(path: P) -> Result<Vec<Keyword>> {
    let raw = std::fs::read_to_string(path.as_ref())
        .with_context(|| format!("failed to read targets file {}", path.as_ref().display()))?;
    let mut keywords = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (pattern, case_sensitive) = if line.starts_with('"') && line.ends_with('"') && line.len() >= 2 {
            (line[1..line.len() - 1].to_string(), true)
        } else {
            (line.to_string(), false)
        };
        if pattern.is_empty() {
            continue;
        }
        keywords.push(Keyword { pattern, case_sensitive });
    }
    Ok(keywords)
}

/// Built-in defaults — used when the user provides no extensions.txt or --ext flag.
pub const DEFAULT_TEXT_EXTENSIONS: &[&str] = &[
    "txt", "log", "csv", "tsv", "md", "rst", "ini", "conf", "cfg", "toml", "yaml", "yml",
    "json", "xml", "html", "htm", "css", "js", "ts", "jsx", "tsx", "py", "rs", "go",
    "c", "h", "cpp", "cc", "hpp", "hh", "cs", "java", "kt", "swift", "php", "rb",
    "pl", "sh", "bash", "zsh", "fish", "bat", "cmd", "ps1", "psm1", "sql", "tex",
    "vue", "svelte", "lua", "r", "scala", "groovy", "dart", "ex", "exs", "erl",
    "lisp", "el", "clj", "cljs", "edn", "asm", "s", "f", "f90", "vb", "vbs",
    "diff", "patch", "env", "gitignore", "dockerfile", "makefile", "mk",
];

/// Extensions that need OOXML extraction (zip + xml). The handler is dispatched
/// purely by extension; if a user adds one of these to their whitelist, the
/// internal handler picks it up automatically.
pub const OFFICE_EXTENSIONS: &[&str] = &["docx", "xlsx", "pptx"];
pub const LEGACY_OFFICE_EXTENSIONS: &[&str] = &["doc", "xls", "ppt"];
pub const PDF_EXTENSIONS: &[&str] = &["pdf"];

/// Filenames (no extension) we always treat as readable text.
pub const NO_EXT_TEXT_NAMES: &[&str] =
    &["dockerfile", "makefile", "rakefile", "gemfile", "license", "readme"];

/// The fully-resolved extension whitelist for a run. Built from defaults / file / CLI.
#[derive(Debug, Clone)]
pub struct ExtensionSet {
    pub extensions: HashSet<String>,
    /// If true, files without extension whose basename matches NO_EXT_TEXT_NAMES are included.
    pub include_no_ext_special: bool,
}

impl ExtensionSet {
    pub fn from_defaults() -> Self {
        let mut s: HashSet<String> = DEFAULT_TEXT_EXTENSIONS.iter().map(|e| e.to_string()).collect();
        for e in OFFICE_EXTENSIONS
            .iter()
            .chain(LEGACY_OFFICE_EXTENSIONS.iter())
            .chain(PDF_EXTENSIONS.iter())
        {
            s.insert(e.to_string());
        }
        Self { extensions: s, include_no_ext_special: true }
    }

    pub fn from_strings<I, S>(iter: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let extensions = iter
            .into_iter()
            .filter_map(|s| normalize_ext(s.as_ref()))
            .collect();
        Self { extensions, include_no_ext_special: true }
    }

    /// Read a file with one extension per line; supports `#` comments and blank lines.
    /// Lines may include or omit the leading dot; case-insensitive.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let raw = std::fs::read_to_string(path.as_ref())
            .with_context(|| format!("讀取副檔名清單失敗：{}", path.as_ref().display()))?;
        let mut extensions = HashSet::new();
        let mut include_no_ext_special = false;
        for line in raw.lines() {
            let trimmed = line.split('#').next().unwrap_or("").trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.eq_ignore_ascii_case("@no-ext-special") {
                include_no_ext_special = true;
                continue;
            }
            if let Some(ext) = normalize_ext(trimmed) {
                extensions.insert(ext);
            }
        }
        Ok(Self { extensions, include_no_ext_special })
    }

    pub fn contains(&self, ext_lower: &str) -> bool {
        self.extensions.contains(ext_lower)
    }
}

fn normalize_ext(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_start_matches('.').trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_ascii_lowercase())
}

/// Returns true if the path's extension is in the configured whitelist.
pub fn is_target_extension(path: &Path, set: &ExtensionSet) -> bool {
    if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
        let lower = ext.to_ascii_lowercase();
        return set.contains(&lower);
    }
    // No extension: only allow well-known config-style filenames.
    if set.include_no_ext_special {
        if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
            let lower = name.to_ascii_lowercase();
            return NO_EXT_TEXT_NAMES.contains(&lower.as_str());
        }
    }
    false
}

pub fn extension_kind(path: &Path) -> ExtensionKind {
    let Some(ext) = path.extension().and_then(|s| s.to_str()) else {
        return ExtensionKind::PlainText;
    };
    let lower = ext.to_ascii_lowercase();
    if OFFICE_EXTENSIONS.iter().any(|e| *e == lower) {
        ExtensionKind::Office
    } else if LEGACY_OFFICE_EXTENSIONS.iter().any(|e| *e == lower) {
        ExtensionKind::LegacyOffice
    } else if PDF_EXTENSIONS.iter().any(|e| *e == lower) {
        ExtensionKind::Pdf
    } else {
        ExtensionKind::PlainText
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionKind {
    PlainText,
    Office,
    LegacyOffice,
    Pdf,
}

/// Runtime configuration assembled from CLI args.
#[derive(Debug, Clone)]
pub struct RunConfig {
    pub keywords: Vec<Keyword>,
    pub roots: Vec<PathBuf>,
    pub excludes: Vec<PathBuf>,
    pub workers: usize,
    pub context_chars: usize,
    pub output_dir: PathBuf,
    pub max_file_size: u64,
    pub extensions: ExtensionSet,
}

/// Returns true if `path` should be skipped because it lives under one of `excludes`.
pub fn is_excluded(path: &Path, excludes: &[PathBuf]) -> bool {
    excludes.iter().any(|ex| path.starts_with(ex))
}
