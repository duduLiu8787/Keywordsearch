# forensic_search

電腦採證快速關鍵字搜尋工具，Rust 實作。一份 `targets.txt` 列出要找的關鍵字，掃描磁碟文字檔 / Office / PDF / 瀏覽器歷史 / Windows Event Log / Registry，並偵測常見遠端存取工具與通訊軟體。

跨平台優先支援 Windows；macOS / Linux 跑得起來，但 Windows-only 模組（Event Log / Registry / 遠端工具 / 通訊軟體）會自動略過。

## 編譯

需要 Rust 1.70+（[rustup](https://rustup.rs/)）。

```bash
# 原生平台（Linux / macOS）
cargo build --release

# Windows 64-bit cross-compile（Linux 上需 mingw-w64）
cargo build --release --target x86_64-pc-windows-gnu

# Windows 32-bit cross-compile（Linux 上需 mingw-w64）
cargo build --release --target i686-pc-windows-gnu
```


## 使用

```bash
# 最常見：用 targets.txt，掃預設範圍（Windows 自動偵測所有固定 + 網路磁碟）
forensic_search.exe -t targets.txt

# 指定 root / 排除路徑（重複 flag 或逗號分隔皆可）
forensic_search.exe -r D:\ -r E:\ -x D:\Backup
forensic_search.exe -r D:\,E:\ -x D:\Backup,C:\Windows

# 略過特定模組
forensic_search.exe --skip browser,event,registry

# 手動指定 worker 數（預設 2× logical processors）
forensic_search.exe -w 8

# 用自家副檔名清單
forensic_search.exe --ext-file my-extensions.txt
forensic_search.exe --ext "txt,csv,docx"
forensic_search.exe --ext-add pdf --ext-remove log

# 看完整參數
forensic_search.exe --help
```

## `targets.txt` 語法

```
# 註解
example.com                # case-insensitive substring
john@example.com
"ExactKeyword"             # 雙引號包起來 → case-sensitive
"CaseSensitive"
```

## `extensions.txt`（可選）

控制要掃哪些副檔名。優先順序：

```
CLI --ext  >  CLI --ext-file  >  ./extensions.txt 或 exe 旁邊的  >  內建預設
```

之後可再用 `--ext-add` / `--ext-remove` 加減。`--list-extensions` 看最終生效清單。

格式：每行一個副檔名（點號可省略），`#` 註解、空行忽略，不分大小寫。寫 `@no-ext-special` 開啟 Dockerfile / Makefile / README / LICENSE 等無副檔名特殊檔名。

## 輸出

每次跑會在 `--output-dir`（預設 `.`）產出三個檔：

- `forensic_result_YYYYMMDD_HHMMSS.txt` — 人讀純文字報告（含全部命中）
- `forensic_result_YYYYMMDD_HHMMSS.jsonl` — 每行一筆 JSON，方便後續用 jq / Excel / Python 分析
- `forensic_result_YYYYMMDD_HHMMSS.html` — 互動式深色主題報告；支援關鍵字 / 區段篩選、路徑與內容全文搜尋、每筆可展開收合；自包含 HTML，直接用瀏覽器開啟

Terminal 上每個區段只顯示前 5 筆命中，其餘提示去看 log。

## 模組

| 模組 | 平台 | 內容 |
|---|---|---|
| 磁碟文字檔 | 全平台 | 純文字 / .docx/.xlsx/.pptx / .doc/.xls/.ppt / PDF；自動偵測 UTF-8/UTF-16/Big5/GBK 等編碼；含檔名比對 |
| 瀏覽器歷史 | 全平台 | Chrome / Edge / Firefox 所有 profile 的 SQLite history |
| Windows Event Log | Windows | Application / Security / System / PowerShell / TerminalServices / RDPCoreTS 各取最新 10000 筆 |
| Windows Registry | Windows | HKLM / HKCU / HKU 遞迴掃 key / value name / value data |
| 遠端存取工具偵測 | Windows | 19 種 RAT（mstsc / TeamViewer / AnyDesk / Parsec…）— Prefetch + UserAssist + BAM |
| 通訊軟體偵測 | Windows | LINE / Telegram / Discord / WhatsApp / WeChat / Teams / Zoom… — 安裝目錄 + 執行痕跡 |

## 技術重點

- **多 pattern 同時比對**：`aho-corasick` 一次掃描比對所有關鍵字（vs. per-keyword 線性掃）
- **大檔 mmap、小檔 read**：64 KB 以上用 `memmap2`，省 buffer copy 與 syscall
- **平行掃描**：`rayon` work-stealing，預設 `logical_processors × 2`，I/O 等待時自動填滿 CPU
- **編碼偵測**：`chardetng` + `encoding_rs`，Big5/GBK/UTF-16 LE 等都會試
- **舊版 Office**：CFB 不解析，但對 raw bytes 做四種 decoding（ASCII runs / UTF-16 LE 雙 alignment / Big5 / GBK）聯集後比對

## 已知限制

- 加密 PDF、純圖片 PDF（沒有文字層）抓不到 → 需要 OCR，不在範圍
- 舊版 Office (.doc/.xls) 中文覆蓋率約 90%+；要 100% 需完整 CFB + BIFF parser
- Windows Event Log 透過 `wevtutil` 外部進程；單頻道限 10000 筆
- Cross-compile 出來的 Windows binary 是 GNU ABI，不是 MSVC

## 授權

未指定。

