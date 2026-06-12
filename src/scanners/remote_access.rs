use crate::report::{DetectedTool, RemoteAccessSummary};
use anyhow::Result;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use winreg::enums::*;
use winreg::RegKey;

/// Known RAT signatures: (display name, executable substrings to look for).
const RATS: &[(&str, &[&str])] = &[
    ("Microsoft RDP (mstsc)", &["MSTSC.EXE"]),
    ("Microsoft Remote Desktop (Store)", &["MICROSOFTREMOTEDESKTOP", "MICROSOFT.REMOTEDESKTOP"]),
    ("TeamViewer", &["TEAMVIEWER.EXE", "TV_W32.EXE", "TV_X64.EXE"]),
    ("AnyDesk", &["ANYDESK.EXE"]),
    ("RealVNC Viewer", &["VNCVIEWER.EXE"]),
    ("TightVNC", &["TVNVIEWER.EXE", "TVNSERVER.EXE"]),
    ("UltraVNC", &["UVNC.EXE", "WINVNC.EXE", "VNCVIEWER.EXE"]),
    ("LogMeIn", &["LMIIGNITION.EXE", "LOGMEIN.EXE"]),
    ("Chrome Remote Desktop", &["REMOTING_HOST.EXE", "REMOTING_DESKTOP.EXE"]),
    ("Ammyy Admin", &["AA_V3.EXE", "AMMYY.EXE"]),
    ("Supremo", &["SUPREMO.EXE", "SUPREMOSYSTEM.EXE"]),
    ("Splashtop", &["SRSERVER.EXE", "SPLASHTOP.EXE", "STREAMER.EXE"]),
    ("ConnectWise Control", &["SCREENCONNECT.CLIENT.EXE", "SCREENCONNECT.EXE"]),
    ("Parsec", &["PARSECD.EXE", "PARSEC.EXE"]),
    ("DWService", &["DWAGENT.EXE", "DWAGSVC.EXE"]),
    ("GoToMyPC / GoToMeeting", &["G2COMM.EXE", "GOTOMYPC.EXE", "G2MCOMM.EXE"]),
    ("Zoho Assist", &["ZA_ACCESS.EXE", "ZOHOASSIST.EXE"]),
    ("AeroAdmin", &["AEROADMIN.EXE"]),
    ("NetSupport Manager", &["CLIENT32.EXE", "PCICTLUI.EXE", "PCIVIEW.EXE"]),
];

pub fn scan() -> Result<RemoteAccessSummary> {
    let mut summary = RemoteAccessSummary::default();
    summary.rdp_enabled = Some(rdp_enabled());
    summary.rdp_hosts = rdp_recent_hosts();
    summary.rdp_files = rdp_files();

    let evidence_map = collect_execution_evidence();
    let mut found: Vec<DetectedTool> = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    for (name, sigs) in RATS {
        let mut evidences: Vec<String> = Vec::new();
        for sig in *sigs {
            if let Some(sources) = evidence_map.get(*sig) {
                for src in sources {
                    evidences.push(format!("{} → {}", src, sig));
                }
            }
        }
        if !evidences.is_empty() {
            found.push(DetectedTool {
                name: name.to_string(),
                evidence: evidences,
            });
        } else {
            missing.push(name.to_string());
        }
    }
    summary.found_tools = found;
    summary.missing_tools = missing;
    Ok(summary)
}

fn rdp_enabled() -> bool {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(k) = hklm.open_subkey(r"SYSTEM\CurrentControlSet\Control\Terminal Server") {
        if let Ok(v) = k.get_value::<u32, _>("fDenyTSConnections") {
            return v == 0;
        }
    }
    false
}

fn rdp_recent_hosts() -> Vec<String> {
    let mut out = Vec::new();
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok(k) = hkcu.open_subkey(r"Software\Microsoft\Terminal Server Client\Default") {
        for v in k.enum_values().flatten() {
            let (name, val) = v;
            if name.starts_with("MRU") {
                let s = format!("{:?}", val);
                let trimmed = s.trim_matches('"').to_string();
                out.push(trimmed);
            }
        }
    }
    if let Ok(servers) = hkcu.open_subkey(r"Software\Microsoft\Terminal Server Client\Servers") {
        for sub in servers.enum_keys().flatten() {
            out.push(sub);
        }
    }
    out
}

fn rdp_files() -> Vec<String> {
    let mut out = Vec::new();
    let roots: Vec<PathBuf> = vec![
        PathBuf::from(r"C:\"),
        std::env::var("USERPROFILE").ok().map(PathBuf::from).unwrap_or_default(),
    ];
    for root in roots.into_iter().filter(|p| !p.as_os_str().is_empty() && p.exists()) {
        for entry in WalkDir::new(&root)
            .max_depth(6)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if !entry.file_type().is_file() {
                continue;
            }
            if entry
                .path()
                .extension()
                .and_then(|s| s.to_str())
                .map(|e| e.eq_ignore_ascii_case("rdp"))
                .unwrap_or(false)
            {
                out.push(entry.path().display().to_string());
                if out.len() > 100 {
                    return out;
                }
            }
        }
    }
    out
}

/// Returns map: exe-name (UPPER) → list of evidence sources (e.g. "Prefetch", "BAM", "UserAssist").
pub fn collect_execution_evidence() -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    // Prefetch: filenames like FOO.EXE-XXXXXXXX.pf
    let prefetch_dir = Path::new(r"C:\Windows\Prefetch");
    if prefetch_dir.exists() {
        for entry in WalkDir::new(prefetch_dir)
            .max_depth(1)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if !entry.file_type().is_file() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_ascii_uppercase();
            if name.ends_with(".PF") {
                if let Some(dash) = name.rfind('-') {
                    let exe = name[..dash].to_string();
                    out.entry(exe).or_default().push("Prefetch（曾執行）".to_string());
                }
            }
        }
    }
    // UserAssist
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok(ua) = hkcu.open_subkey(
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
    ) {
        for guid in ua.enum_keys().flatten() {
            if let Ok(count) = ua.open_subkey(format!("{}\\Count", guid)) {
                for v in count.enum_values().flatten() {
                    let raw = v.0;
                    let decoded = rot13(&raw);
                    let upper = decoded.to_ascii_uppercase();
                    if let Some(file) = upper.rsplit('\\').next() {
                        if file.ends_with(".EXE") {
                            out.entry(file.to_string())
                                .or_default()
                                .push("UserAssist（GUI執行記錄）".to_string());
                        }
                    }
                }
            }
        }
    }
    // BAM
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let bam_paths = [
        r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
        r"SYSTEM\CurrentControlSet\Services\bam\UserSettings",
    ];
    for bp in bam_paths {
        if let Ok(root) = hklm.open_subkey(bp) {
            for sid in root.enum_keys().flatten() {
                if let Ok(user) = root.open_subkey(&sid) {
                    for v in user.enum_values().flatten() {
                        let name = v.0.to_ascii_uppercase();
                        if let Some(exe) = name.rsplit('\\').next() {
                            if exe.ends_with(".EXE") {
                                out.entry(exe.to_string())
                                    .or_default()
                                    .push("BAM（背景執行記錄）".to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='M' | 'a'..='m' => (c as u8 + 13) as char,
            'N'..='Z' | 'n'..='z' => (c as u8 - 13) as char,
            _ => c,
        })
        .collect()
}
