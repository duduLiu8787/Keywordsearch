use crate::report::{CommsSummary, DetectedTool};
use crate::scanners::remote_access::collect_execution_evidence;
use anyhow::Result;
use std::path::PathBuf;

/// (display name, install-dir candidates {use placeholders %LOCALAPPDATA% etc.}, exe signatures)
const COMMS: &[(&str, &[&str], &[&str])] = &[
    ("LINE", &[r"%LOCALAPPDATA%\LINE", r"%APPDATA%\LINE"], &["LINE.EXE"]),
    ("Telegram", &[r"%APPDATA%\Telegram Desktop", r"%LOCALAPPDATA%\Telegram Desktop"], &["TELEGRAM.EXE"]),
    ("Discord", &[r"%APPDATA%\discord", r"%LOCALAPPDATA%\Discord"], &["DISCORD.EXE"]),
    ("WhatsApp", &[r"%LOCALAPPDATA%\WhatsApp", r"%APPDATA%\WhatsApp"], &["WHATSAPP.EXE"]),
    ("WeChat（微信）", &[r"%APPDATA%\Tencent\WeChat", r"%PROGRAMFILES(X86)%\Tencent\WeChat"], &["WECHAT.EXE", "WECHATAPP.EXE"]),
    ("Skype", &[r"%APPDATA%\Skype", r"%PROGRAMFILES(X86)%\Skype"], &["SKYPE.EXE", "SKYPEAPP.EXE"]),
    ("Microsoft Teams", &[r"%LOCALAPPDATA%\Microsoft\Teams", r"%APPDATA%\Microsoft\Teams"], &["TEAMS.EXE", "MS-TEAMS.EXE"]),
    ("Zoom", &[r"%APPDATA%\Zoom", r"%PROGRAMFILES(X86)%\Zoom"], &["ZOOM.EXE"]),
    ("Signal", &[r"%APPDATA%\Signal"], &["SIGNAL.EXE"]),
    ("Viber", &[r"%APPDATA%\ViberPC", r"%LOCALAPPDATA%\Viber"], &["VIBER.EXE"]),
    ("Slack", &[r"%APPDATA%\Slack", r"%LOCALAPPDATA%\slack"], &["SLACK.EXE"]),
    ("ICQ", &[r"%APPDATA%\ICQ"], &["ICQ.EXE"]),
    ("KakaoTalk", &[r"%APPDATA%\Kakao\KakaoTalk", r"%LOCALAPPDATA%\Kakao\KakaoTalk"], &["KAKAOTALK.EXE"]),
];

pub fn scan() -> Result<CommsSummary> {
    let evidence = collect_execution_evidence();
    let mut found: Vec<DetectedTool> = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    for (name, dirs, exes) in COMMS {
        let mut evidences: Vec<String> = Vec::new();
        for d in *dirs {
            let expanded = expand_env(d);
            if !expanded.is_empty() && PathBuf::from(&expanded).exists() {
                evidences.push(format!("目錄存在 → {}", expanded));
            }
        }
        for sig in *exes {
            if let Some(sources) = evidence.get(*sig) {
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
    Ok(CommsSummary { found, missing })
}

fn expand_env(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if let Some(end) = s[i + 1..].find('%') {
                let var = &s[i + 1..i + 1 + end];
                if let Ok(v) = std::env::var(var) {
                    out.push_str(&v);
                    i += end + 2;
                    continue;
                } else {
                    return String::new();
                }
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}
