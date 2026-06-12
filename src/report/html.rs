use super::{DetectionReport, MatchRecord, Section};
use anyhow::Result;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

pub struct HtmlReport<'a> {
    pub started_at: &'a chrono::DateTime<chrono::Local>,
    pub targets_display: &'a str,
    pub workers: usize,
    pub excludes: &'a [String],
    pub elapsed: std::time::Duration,
}

impl<'a> HtmlReport<'a> {
    pub fn write<P: AsRef<Path>>(
        &self,
        path: P,
        records: &[MatchRecord],
        detection: &DetectionReport,
    ) -> Result<()> {
        let f = File::create(path.as_ref())?;
        let mut w = BufWriter::new(f);

        let data_json = build_data_json(records, detection);
        let meta_json = build_meta_json(self);

        write!(w, "{}", HTML_TEMPLATE
            .replace("__META_JSON__", &meta_json)
            .replace("__DATA_JSON__", &data_json))?;

        w.flush()?;
        Ok(())
    }
}

fn build_meta_json(r: &HtmlReport) -> String {
    let secs = r.elapsed.as_secs();
    let elapsed_str = format!("{}:{:02}:{:02}", secs / 3600, (secs % 3600) / 60, secs % 60);
    format!(
        r#"{{"started_at":{},"targets":{},"workers":{},"excludes":{},"elapsed":{}}}"#,
        json_str(&r.started_at.format("%Y-%m-%d %H:%M:%S").to_string()),
        json_str(r.targets_display),
        r.workers,
        json_str(&r.excludes.join(", ")),
        json_str(&elapsed_str),
    )
}

fn build_data_json(records: &[MatchRecord], _detection: &DetectionReport) -> String {
    let items: Vec<String> = records.iter().map(|rec| {
        let hits: Vec<String> = rec.hits.iter().map(|h| {
            format!(
                r#"{{"keyword":{},"case_sensitive":{},"line":{},"context":{}}}"#,
                json_str(&h.keyword),
                h.case_sensitive,
                h.line.map(|n| n.to_string()).unwrap_or_else(|| "null".to_string()),
                json_str(&h.context),
            )
        }).collect();
        format!(
            r#"{{"section":{},"source":{},"location":{},"hits":[{}]}}"#,
            json_str(rec.section.short()),
            json_str(&rec.source),
            json_str(&rec.location),
            hits.join(","),
        )
    }).collect();
    format!("[{}]", items.join(","))
}

fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"'  => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => { let _ = std::fmt::Write::write_fmt(&mut out, format_args!("\\u{:04x}", c as u32)); }
            c    => out.push(c),
        }
    }
    out.push('"');
    out
}

const HTML_TEMPLATE: &str = r#"<!DOCTYPE html>
<html lang="zh-Hant">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>採證報告</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:monospace;font-size:14px;background:#0d1117;color:#c9d1d9;display:flex;flex-direction:column;height:100vh;overflow:hidden}
a{color:inherit;text-decoration:none}

/* header */
header{background:#161b22;border-bottom:1px solid #30363d;padding:12px 24px;flex-shrink:0}
header h1{font-size:15px;color:#e6edf3;margin-bottom:4px}
header .meta{font-size:11px;color:#8b949e;line-height:1.7}
header .meta span{color:#c9d1d9}

/* layout */
.layout{display:flex;flex:1;overflow:hidden}

/* sidebar */
aside{width:220px;background:#161b22;border-right:1px solid #30363d;display:flex;flex-direction:column;flex-shrink:0}
.search-wrap{padding:10px 12px;border-bottom:1px solid #30363d}
.search-wrap input{width:100%;background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:6px 10px;font-size:12px;font-family:monospace;color:#c9d1d9;outline:none}
.search-wrap input:focus{border-color:#58a6ff}
.search-wrap input::placeholder{color:#484f58}
.filter-group{padding:10px 12px;border-bottom:1px solid #21262d;overflow-y:auto}
.filter-group h3{font-size:10px;color:#8b949e;text-transform:uppercase;letter-spacing:.07em;margin-bottom:8px}
.chip{display:flex;align-items:center;gap:7px;padding:5px 6px;border-radius:5px;cursor:pointer;font-size:12px;user-select:none}
.chip:hover{background:#21262d}
.chip input[type=checkbox]{accent-color:#e74c3c;cursor:pointer;width:13px;height:13px}
.chip .kw-label{flex:1;word-break:break-all}
.chip .badge{background:#21262d;border-radius:8px;padding:1px 7px;font-size:11px;color:#8b949e;white-space:nowrap}
.chip.exact .kw-label{color:#bc8cff}
.chip.section-chip input{accent-color:#58a6ff}
.btn-all{display:block;width:100%;margin-top:6px;padding:4px 0;background:transparent;border:1px solid #30363d;border-radius:5px;color:#8b949e;font-size:11px;font-family:monospace;cursor:pointer;text-align:center}
.btn-all:hover{background:#21262d;color:#c9d1d9}

/* content */
.content{flex:1;overflow-y:auto;background:#0d1117}
.stat-bar{padding:8px 18px;font-size:11px;color:#8b949e;border-bottom:1px solid #21262d;background:#161b22;position:sticky;top:0;z-index:5}
.stat-bar span{color:#c9d1d9}

.section-head{padding:6px 18px;background:#161b22;border-bottom:1px solid #30363d;font-size:12px;color:#8b949e;display:flex;justify-content:space-between;position:sticky;top:30px;z-index:4}
.section-head .title{color:#e6edf3;font-weight:bold}

.record{border-bottom:1px solid #21262d}
.record-header{padding:7px 18px;display:flex;align-items:center;gap:10px;cursor:pointer;font-size:12px;color:#8b949e}
.record-header:hover{background:#161b22}
.record-header .loc{flex:1;word-break:break-all;color:#58a6ff}
.record-header .filename-hit{color:#f0883e;font-size:11px;white-space:nowrap}
.record-header .hc{white-space:nowrap;color:#e74c3c;font-size:11px}
.record-header .arr{color:#484f58;font-size:10px;transition:transform .15s}
.record-header.open .arr{transform:rotate(90deg)}

.record-body{display:none;border-top:1px solid #21262d}
.record-body.open{display:block}
.hit{padding:7px 18px 7px 32px;border-top:1px solid #161b22}
.hit-top{display:flex;align-items:baseline;gap:8px;margin-bottom:4px}
.kw{font-weight:bold;color:#e74c3c}
.kw.exact{color:#bc8cff}
.lineno{color:#484f58;font-size:11px}
.ctx{font-size:12px;color:#8b949e;line-height:1.6;padding:4px 8px;background:#161b22;border-radius:4px;border-left:3px solid #30363d}
mark{background:#3d3000;color:#e3b341;border-radius:2px;padding:0 2px}
mark.exact{background:#2d1f45;color:#bc8cff}

.empty-section{padding:14px 18px;font-size:12px;color:#484f58}
.no-results{text-align:center;padding:60px;color:#484f58;font-size:13px}

/* scrollbar */
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:#0d1117}
::-webkit-scrollbar-thumb{background:#30363d;border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:#484f58}
</style>
</head>
<body>
<header>
  <h1>電腦採證快速搜尋工具</h1>
  <div class="meta" id="headerMeta"></div>
</header>
<div class="layout">
  <aside>
    <div class="search-wrap">
      <input type="text" id="q" placeholder="路徑 / 內容搜尋…" oninput="render()">
    </div>
    <div class="filter-group" style="flex:1;overflow-y:auto">
      <h3>關鍵字</h3>
      <div id="kwFilters"></div>
      <h3 style="margin-top:12px">區段</h3>
      <div id="secFilters"></div>
      <button class="btn-all" onclick="toggleAll()">全選 / 全消</button>
    </div>
  </aside>
  <div class="content">
    <div class="stat-bar" id="statBar"></div>
    <div id="results"></div>
  </div>
</div>
<script>
const META = __META_JSON__;
const DATA = __DATA_JSON__;

const SECTION_LABELS = {
  "磁碟文字檔":   "磁碟文字檔搜尋",
  "瀏覽器歷史":   "瀏覽器歷史紀錄搜尋",
  "Event Log":    "Windows Event Log 搜尋",
  "Registry":     "Windows Registry 搜尋",
};
const SECTION_ORDER = ["磁碟文字檔","瀏覽器歷史","Event Log","Registry"];

// Collect unique keywords and sections
const allKws = [];
const kwSet = new Set();
const secSet = new Set();
DATA.forEach(rec => {
  secSet.add(rec.section);
  rec.hits.forEach(h => { if (!kwSet.has(h.keyword)) { kwSet.add(h.keyword); allKws.push(h); } });
});

// Keyword hit counts
const kwCount = {};
DATA.forEach(rec => rec.hits.forEach(h => { kwCount[h.keyword] = (kwCount[h.keyword]||0)+1; }));

// Build header meta
document.getElementById('headerMeta').innerHTML =
  `執行時間：<span>${esc(META.started_at)}</span>　耗時：<span>${esc(META.elapsed)}</span>　Workers：<span>${META.workers}</span><br>` +
  `搜尋目標：<span>${esc(META.targets)}</span><br>` +
  `排除路徑：<span>${esc(META.excludes)||'（無）'}</span>`;

// Build keyword filter chips
const kwFiltersEl = document.getElementById('kwFilters');
allKws.forEach(h => {
  const d = document.createElement('label');
  d.className = 'chip' + (h.case_sensitive ? ' exact' : '');
  d.dataset.kw = h.keyword;
  d.innerHTML = `<input type="checkbox" checked onchange="render()"><span class="kw-label">${h.case_sensitive?'"':''}${esc(h.keyword)}${h.case_sensitive?'"':''}</span><span class="badge">${kwCount[h.keyword]}</span>`;
  kwFiltersEl.appendChild(d);
});

// Build section filter chips
const secFiltersEl = document.getElementById('secFilters');
SECTION_ORDER.filter(s => secSet.has(s)).forEach(s => {
  const count = DATA.filter(r => r.section === s).length;
  const d = document.createElement('label');
  d.className = 'chip section-chip';
  d.dataset.sec = s;
  d.innerHTML = `<input type="checkbox" checked onchange="render()"><span class="kw-label">${esc(s)}</span><span class="badge">${count}</span>`;
  secFiltersEl.appendChild(d);
});

function checkedKws() {
  return new Set([...document.querySelectorAll('#kwFilters .chip input:checked')].map(i => i.closest('.chip').dataset.kw));
}
function checkedSecs() {
  return new Set([...document.querySelectorAll('#secFilters .chip input:checked')].map(i => i.closest('.chip').dataset.sec));
}

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function highlight(text, keyword, isExact) {
  const cls = isExact ? 'exact' : '';
  const escaped = keyword.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
  const re = new RegExp(escaped, isExact ? 'g' : 'gi');
  return esc(text).replace(re, m => `<mark class="${cls}">${esc(m)}</mark>`);
}

let allOpen = false;
function toggleAll() {
  const cbs = [...document.querySelectorAll('#kwFilters input, #secFilters input')];
  allOpen = !allOpen;
  cbs.forEach(cb => { cb.checked = allOpen; });
  render();
}

function render() {
  const q = document.getElementById('q').value.toLowerCase();
  const kws = checkedKws();
  const secs = checkedSecs();
  const results = document.getElementById('results');
  let totalVisible = 0;

  let html = '';
  SECTION_ORDER.forEach(sec => {
    if (!secs.has(sec)) return;
    const recs = DATA.filter(rec => {
      if (rec.section !== sec) return false;
      const hasKw = rec.hits.some(h => kws.has(h.keyword));
      if (!hasKw) return false;
      if (q) {
        const locMatch = rec.location.toLowerCase().includes(q);
        const ctxMatch = rec.hits.some(h => h.context.toLowerCase().includes(q));
        if (!locMatch && !ctxMatch) return false;
      }
      return true;
    });

    const label = SECTION_LABELS[sec] || sec;
    html += `<div class="section-head"><span class="title">${esc(label)}</span><span>${recs.length} 個位置</span></div>`;
    if (recs.length === 0) {
      html += `<div class="empty-section">無符合條件的命中</div>`;
    } else {
      totalVisible += recs.length;
      recs.forEach((rec, ri) => {
        const visibleHits = rec.hits.filter(h => kws.has(h.keyword));
        const hasFileHit = visibleHits.some(h => h.line === null && h.context.startsWith('（檔名命中）'));
        const id = `r${sec.replace(/\s/g,'_')}${ri}`;
        html += `<div class="record">`;
        html += `<div class="record-header" onclick="toggleRec(this)" id="hdr_${id}">`;
        html += `<span class="loc">${esc(rec.location)}</span>`;
        if (hasFileHit) html += `<span class="filename-hit">檔名命中</span>`;
        html += `<span class="hc">${visibleHits.length} 個命中</span>`;
        html += `<span class="arr">▶</span></div>`;
        html += `<div class="record-body" id="body_${id}">`;
        visibleHits.forEach(h => {
          const isFilenameHit = h.line === null && h.context.startsWith('（檔名命中）');
          const ctxText = isFilenameHit ? h.context.replace('（檔名命中）','') : h.context;
          const ctxHtml = highlight(ctxText, h.keyword, h.case_sensitive);
          const kwLabel = h.case_sensitive ? `"${esc(h.keyword)}"（完全符合）` : esc(h.keyword);
          const lineLabel = (h.line != null) ? `<span class="lineno">第 ${h.line} 行</span>` : (isFilenameHit ? `<span class="lineno">（檔名命中）</span>` : '');
          html += `<div class="hit">`;
          html += `<div class="hit-top"><span class="kw${h.case_sensitive?' exact':''}">${kwLabel}</span>${lineLabel}</div>`;
          html += `<div class="ctx">${ctxHtml}</div>`;
          html += `</div>`;
        });
        html += `</div></div>`;
      });
    }
  });

  if (totalVisible === 0) {
    html = `<div class="no-results">沒有符合篩選條件的結果</div>`;
  }

  results.innerHTML = html;

  const totalHits = DATA.reduce((acc, r) => acc + r.hits.filter(h => kws.has(h.keyword)).length, 0);
  document.getElementById('statBar').innerHTML =
    `顯示 <span>${totalVisible}</span> 個位置，<span>${totalHits}</span> 個關鍵字命中`;
}

function toggleRec(header) {
  const id = header.id.replace('hdr_','body_');
  const body = document.getElementById(id);
  const open = body.classList.toggle('open');
  header.classList.toggle('open', open);
}

render();
</script>
</body>
</html>
"#;
