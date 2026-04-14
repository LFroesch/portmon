## DevLog
### 2026-04-13: In-app label editor
Added a saved-label editor on `e` so port names can be created, changed, or cleared from the TUI without hand-editing config. Also replaced string-parsed row actions with explicit row metadata so section headers and spacer rows no longer confuse open/kill behavior after refreshes or filters. Files: model.go, helpers.go, view.go, update.go, helpers_test.go, update_test.go, README.md, WORK.md.

### 2026-04-13: Ports tab details pane removed
Removed the selected-port details pane from the Ports tab after it proved noisy without materially helping discovery. Kept the simpler filter/search flow and restored table space for the main list. Files: view.go, helpers.go, model.go, README.md, WORK.md.

### 2026-04-13: Filter input keybinding fix
Fixed Ports-tab filter input so typed digits like `1` and `2` no longer trigger global tab switching while the filter is active. Added a regression test for filter-mode key routing. Files: update.go, update_test.go.

### 2026-04-13: Ports tab filter + details pane
Trimmed built-in labels down to canonical service ports so the UI stops implying that arbitrary dev ports are authoritative. Added `/` filter on the Ports tab plus a selected-port details panel to make it easier to find and inspect the process the user actually cares about. Files: view.go, update.go, model.go, helpers.go, helpers_test.go, README.md, WORK.md.

### 2026-04-13: Built-in port labels + lsof UDP fix
Added built-in labels for common ports so the Ports tab can name typical services even without user config, while still letting config overrides win. Also fixed the `lsof` fallback parser to include UDP listeners instead of effectively showing TCP-only results on that path. Files: helpers.go, helpers_test.go, README.md, WORK.md.

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
