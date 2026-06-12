pub mod html;
pub mod jsonl;
pub mod terminal;
pub mod text;

use serde::{Deserialize, Serialize};

/// One record per "location" (file path, browser URL, event, registry value, etc.).
/// All keyword hits inside that location are aggregated into `hits`. Each keyword
/// appears at most once per record — only the first occurrence is kept.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchRecord {
    pub section: Section,
    /// Free-form label of where this came from (file kind, browser profile, event channel, etc.).
    pub source: String,
    /// The identifying path of this record (file path, URL, event id, registry key).
    pub location: String,
    /// One entry per unique keyword that matched in this location.
    pub hits: Vec<KeywordHit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeywordHit {
    pub keyword: String,
    pub case_sensitive: bool,
    pub line: Option<u64>,
    pub context: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Section {
    DiskText,
    BrowserHistory,
    EventLog,
    Registry,
    RemoteAccess,
    Comms,
}

impl Section {
    pub fn title(&self) -> &'static str {
        match self {
            Section::DiskText => "磁碟文字檔搜尋",
            Section::BrowserHistory => "瀏覽器歷史紀錄搜尋",
            Section::EventLog => "Windows Event Log 搜尋",
            Section::Registry => "Windows Registry 搜尋（關鍵字）",
            Section::RemoteAccess => "遠端存取工具偵測",
            Section::Comms => "通訊軟體偵測（安裝 + 執行痕跡）",
        }
    }

    pub fn short(&self) -> &'static str {
        match self {
            Section::DiskText => "磁碟文字檔",
            Section::BrowserHistory => "瀏覽器歷史",
            Section::EventLog => "Event Log",
            Section::Registry => "Registry",
            Section::RemoteAccess => "遠端存取工具",
            Section::Comms => "通訊軟體",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DetectionReport {
    pub remote_access: Option<RemoteAccessSummary>,
    pub comms: Option<CommsSummary>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RemoteAccessSummary {
    pub rdp_enabled: Option<bool>,
    pub rdp_hosts: Vec<String>,
    pub rdp_files: Vec<String>,
    pub found_tools: Vec<DetectedTool>,
    pub missing_tools: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CommsSummary {
    pub found: Vec<DetectedTool>,
    pub missing: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DetectedTool {
    pub name: String,
    pub evidence: Vec<String>,
}
