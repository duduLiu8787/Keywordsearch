use super::{DetectionReport, MatchRecord, Section};
use anyhow::Result;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

pub struct TextReport {
    pub started_at: chrono::DateTime<chrono::Local>,
    pub targets_display: String,
    pub workers: usize,
    pub excludes: Vec<String>,
}

impl TextReport {
    pub fn write<P: AsRef<Path>>(
        &self,
        path: P,
        records: &[MatchRecord],
        detection: &DetectionReport,
        elapsed: std::time::Duration,
    ) -> Result<()> {
        let f = File::create(path.as_ref())?;
        let mut w = BufWriter::new(f);

        writeln!(w, "電腦採證快速搜尋工具")?;
        writeln!(w, "執行時間：{}", self.started_at.format("%Y-%m-%d %H:%M:%S"))?;
        writeln!(w, "搜尋目標：{}", self.targets_display)?;
        writeln!(w, "Workers：{}", self.workers)?;
        writeln!(w, "排除路徑：{}", self.excludes.join(", "))?;
        writeln!(w)?;

        // Group records by section, preserving section order
        let order = [
            Section::DiskText,
            Section::BrowserHistory,
            Section::EventLog,
            Section::Registry,
        ];
        let mut grouped: BTreeMap<usize, Vec<&MatchRecord>> = BTreeMap::new();
        for r in records {
            let idx = order.iter().position(|s| *s == r.section).unwrap_or(99);
            grouped.entry(idx).or_default().push(r);
        }

        let mut record_index = 0usize;
        for (i, section) in order.iter().enumerate() {
            writeln!(w, "{}", "=".repeat(60))?;
            writeln!(w, "  {}", section.title())?;
            writeln!(w, "{}", "=".repeat(60))?;
            if let Some(rs) = grouped.get(&i) {
                for r in rs {
                    record_index += 1;
                    writeln!(w)?;
                    writeln!(w, "  [{}] 來源：{}", record_index, r.source)?;
                    writeln!(w, "       位置：{}", r.location)?;
                    writeln!(w, "       命中關鍵字 ({} 個)：", r.hits.len())?;
                    for h in &r.hits {
                        let kw_label = if h.case_sensitive {
                            format!("\"{}\"（完全符合）", h.keyword)
                        } else {
                            h.keyword.clone()
                        };
                        let line_label = match h.line {
                            Some(n) => format!(" 第 {} 行", n),
                            None => String::new(),
                        };
                        writeln!(w, "         · {}{}", kw_label, line_label)?;
                        writeln!(w, "           內容：{}", h.context)?;
                    }
                }
            }
            writeln!(w)?;
        }

        if let Some(ra) = &detection.remote_access {
            writeln!(w, "{}", "=".repeat(60))?;
            writeln!(w, "  {}", Section::RemoteAccess.title())?;
            writeln!(w, "{}", "=".repeat(60))?;
            if let Some(enabled) = ra.rdp_enabled {
                writeln!(
                    w,
                    "  ● Windows RDP 功能：{}",
                    if enabled { "已啟用" } else { "已停用" }
                )?;
            }
            if !ra.rdp_hosts.is_empty() {
                writeln!(w, "  ● RDP 曾連線主機（{} 個）：", ra.rdp_hosts.len())?;
                for h in &ra.rdp_hosts {
                    writeln!(w, "      - {}", h)?;
                }
            }
            if !ra.rdp_files.is_empty() {
                writeln!(w, "  ● .rdp 連線設定檔（{} 個）：", ra.rdp_files.len())?;
                for f in &ra.rdp_files {
                    writeln!(w, "      - {}", f)?;
                }
            }
            writeln!(w)?;
            writeln!(w, "  【已發現遠端存取工具】")?;
            if ra.found_tools.is_empty() {
                writeln!(w, "    （未發現任何遠端存取工具）")?;
            } else {
                for t in &ra.found_tools {
                    writeln!(w, "    [V] {}", t.name)?;
                    for ev in &t.evidence {
                        writeln!(w, "        證據：{}", ev)?;
                    }
                }
            }
            if !ra.missing_tools.is_empty() {
                writeln!(w)?;
                writeln!(w, "  【未發現的遠端存取工具】")?;
                writeln!(w, "    {}", ra.missing_tools.join("、"))?;
            }
            writeln!(w)?;
        }

        if let Some(comms) = &detection.comms {
            writeln!(w, "{}", "=".repeat(60))?;
            writeln!(w, "  {}", Section::Comms.title())?;
            writeln!(w, "{}", "=".repeat(60))?;
            writeln!(w)?;
            writeln!(w, "  【已偵測到的通訊軟體】")?;
            if comms.found.is_empty() {
                writeln!(w, "    （未發現任何通訊軟體）")?;
            } else {
                for t in &comms.found {
                    writeln!(w, "    [V] {}", t.name)?;
                    for ev in &t.evidence {
                        writeln!(w, "        證據：{}", ev)?;
                    }
                }
            }
            if !comms.missing.is_empty() {
                writeln!(w)?;
                writeln!(w, "  【未發現的通訊軟體】")?;
                writeln!(w, "    {}", comms.missing.join("、"))?;
            }
            writeln!(w)?;
        }

        // Summary
        writeln!(w, "{}", "=".repeat(60))?;
        writeln!(w, "  【彙整摘要】")?;
        writeln!(w, "{}", "=".repeat(60))?;
        let mut file_totals: BTreeMap<&'static str, usize> = BTreeMap::new();
        let mut hit_totals: BTreeMap<&'static str, usize> = BTreeMap::new();
        for r in records {
            *file_totals.entry(r.section.short()).or_insert(0) += 1;
            *hit_totals.entry(r.section.short()).or_insert(0) += r.hits.len();
        }
        for s in [
            Section::DiskText,
            Section::BrowserHistory,
            Section::EventLog,
            Section::Registry,
        ] {
            let files = file_totals.get(s.short()).copied().unwrap_or(0);
            let hits = hit_totals.get(s.short()).copied().unwrap_or(0);
            writeln!(w, "  {:<22}: {} 個位置 / {} 個關鍵字命中", s.short(), files, hits)?;
        }
        if let Some(ra) = &detection.remote_access {
            if ra.found_tools.is_empty() {
                writeln!(w, "  {:<22}: 未發現", Section::RemoteAccess.short())?;
            } else {
                let names: Vec<&str> = ra.found_tools.iter().map(|t| t.name.as_str()).collect();
                writeln!(w, "  {:<22}: {}", Section::RemoteAccess.short(), names.join(", "))?;
            }
        }
        if let Some(comms) = &detection.comms {
            if comms.found.is_empty() {
                writeln!(w, "  {:<22}: 未發現", Section::Comms.short())?;
            } else {
                let names: Vec<&str> = comms.found.iter().map(|t| t.name.as_str()).collect();
                writeln!(w, "  {:<22}: {}", Section::Comms.short(), names.join(", "))?;
            }
        }
        writeln!(w, "  {}", "─".repeat(40))?;
        let total_locations = records.len();
        let total_hits: usize = records.iter().map(|r| r.hits.len()).sum();
        writeln!(
            w,
            "  {:<22}: {} 個位置 / {} 個關鍵字命中",
            "總計", total_locations, total_hits
        )?;
        writeln!(w, "{}", "=".repeat(60))?;
        writeln!(w)?;
        let secs = elapsed.as_secs();
        writeln!(
            w,
            "  耗時：{}:{:02}:{:02}",
            secs / 3600,
            (secs % 3600) / 60,
            secs % 60
        )?;
        w.flush()?;
        Ok(())
    }
}
