## DevLog
### 2026-03-23: Doc suite refresh
Updated README to scout standard (concise, tables, license). Updated WORK.md with feature ideas.

### 2026-03-20: Stats tab scroll + layout fixes
Made stats tab respect same header/status framing as ports tab. Added j/k scroll with height clamping and padding so status bar stays pinned. Files: main.go.

### 2026-03-20: Dashboard layout + system stats overhaul
Rewrote stats tab as horizontal 2-panel dashboard (Scout-style):
- Left panel: CPU/MEM/SWAP bars+sparklines, disk usage (deduped by device ID)
- Right panel: network rx/tx + sparklines, system info (hostname, kernel, uptime, load, port counts)
- Bottom panel: top 5 processes by CPU
Added hostname/kernel readers, fixed disk dedup, removed TCP connections panel. Added CPU%/MEM% columns to port table. Files: main.go, stats.go, styles.go.
