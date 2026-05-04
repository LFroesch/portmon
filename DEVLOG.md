## DevLog
### 2026-05-04: Release polish for diagnostics and platform handling
Closed the main v1 professionalism gaps. Port scanning now reports missing-tool / command failures explicitly instead of silently rendering an empty table, the Stats tab shows a clear unsupported/unavailable state on non-Linux or unreadable `/proc` environments, and the dead `link` config field was removed from the public app surface and docs to match the current feature set. Added regression coverage for the new warning paths. Files: helpers.go, model.go, update.go, view.go, stats.go, main.go, helpers_test.go, update_test.go, README.md, WORK.md, DEVLOG.md.

### 2026-05-04: WORK audit for v1 blocker sprint
Audited `WORK.md` against the current codebase and tests. Removed the stale help-overlay task because it is already implemented, verified the current Go tests pass, and rewrote `WORK.md` around actual v1 blockers: scanner diagnostics, unsupported-platform stats handling, and the dead `link` config surface left behind after removing open-in-browser. Files: WORK.md, DEVLOG.md.

### 2026-04-18: Filter shrink panic fix
Clamped Ports-tab cursor restoration to the rebuilt row count before scanning for the next selectable row, which fixes the `index out of range` panic that could happen after filtering down from a longer list. Added a regression test that simulates a stale cursor surviving into a shorter filtered table. Files: helpers.go, helpers_test.go, README.md, WORK.md.

### 2026-04-18: Ports table fills the available height
Dropped `TableHeightPad` from 15 to 7 so the Ports tab table grows to fill the terminal instead of capping at ~6 visible rows on medium-height terminals. The pad now matches the actual chrome around the table (header + blank + filter bar + blank + status). Files: model.go.

### 2026-04-18: Stats tab condensed, dropped open-in-browser
Capped Stats-tab panel widths (50 per side, 100 total max) so the dashboard stops stretching across wide terminals with empty space, and grew the bottom Top Processes panel to consume any leftover vertical space so the dashboard fills the height of taller terminals instead of leaving dead rows under the panels. Dropped the `o`/open feature entirely — removed from status bar, help overlay, README, plus the handler in `update.go` and the `openLink` helper. The `Link` config field stays in place for the planned protocol-aware open rework. Files: view.go, update.go, helpers.go, README.md.

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
