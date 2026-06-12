pub mod disk_files;
pub mod browser;

#[cfg(windows)]
pub mod event_log;
#[cfg(windows)]
pub mod registry;
#[cfg(windows)]
pub mod remote_access;
#[cfg(windows)]
pub mod comms;

#[cfg(not(windows))]
pub mod event_log {
    use crate::matcher::Matcher;
    use crate::report::MatchRecord;
    use anyhow::Result;
    pub fn scan(_m: &Matcher) -> Result<Vec<MatchRecord>> { Ok(Vec::new()) }
}
#[cfg(not(windows))]
pub mod registry {
    use crate::matcher::Matcher;
    use crate::report::MatchRecord;
    use anyhow::Result;
    pub fn scan(_m: &Matcher) -> Result<Vec<MatchRecord>> { Ok(Vec::new()) }
}
#[cfg(not(windows))]
pub mod remote_access {
    use crate::report::RemoteAccessSummary;
    use anyhow::Result;
    pub fn scan() -> Result<RemoteAccessSummary> { Ok(RemoteAccessSummary::default()) }
}
#[cfg(not(windows))]
pub mod comms {
    use crate::report::CommsSummary;
    use anyhow::Result;
    pub fn scan() -> Result<CommsSummary> { Ok(CommsSummary::default()) }
}
