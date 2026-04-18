# Portmon

Live port monitor and system stats dashboard for the terminal. Built with Go and [Bubble Tea](https://github.com/charmbracelet/bubbletea).

See what's running on your ports, kill processes, and monitor system resources — all from one TUI.

## Quick Install

Supported platforms: Linux (full support) and macOS (port scanning only; stats dashboard is Linux-only). On Windows, use WSL.

Recommended (installs to `~/.local/bin`):

```bash
curl -fsSL https://raw.githubusercontent.com/LFroesch/portmon/main/install.sh | bash
```

Or download a binary from [GitHub Releases](https://github.com/LFroesch/portmon/releases).

Or install with Go:

```bash
go install github.com/LFroesch/portmon@latest
```

Or build from source:

```bash
make install
```

Command:

```bash
portmon
```

## Tabs

### Ports Tab

Live table of active ports with process info:

| Column | Description |
|--------|-------------|
| Port | Port number |
| Protocol | TCP/UDP |
| Process | Process name (or custom name from config) |
| PID | Process ID |
| CPU% | Process CPU usage |
| MEM% | Process memory usage |
| User | Process owner |
| Address | Bind address |
| Status | Connection status |

Ports are split into two sections:

- **Custom** — Named ports from your config (dev servers, databases, etc.)
- **System** — Everything else

The Ports tab also includes:

- Inline filter/search with `/`
- Selection recovery when refreshes or filters shrink the visible rows
- Built-in labels only for canonical service ports like `22`, `53`, `80`, and `443`
- `e` in-app label editor for saving or clearing custom port names

### Stats Tab

btop-style system dashboard:

- CPU/MEM/SWAP usage bars with sparklines
- Disk usage (deduped by device)
- Network rx/tx rates with sparklines
- System info (hostname, kernel, uptime, load average)
- Top 5 processes by CPU

## Keybindings

| Key | Action |
|-----|--------|
| `tab`, `1/2` | Switch tabs (Ports / Stats) |
| `/` | Filter ports by port, process, label, user, PID, or address |
| `j/k`, `up/down` | Navigate |
| `e` | Edit or clear saved label for selected port |
| `enter` | Kill process (with confirmation) |
| `r` | Refresh |
| `x` | Reload config |
| `c` | Show config path |
| `?` | Help |
| `q`, `ctrl+c` | Quit |

## Configuration

Config file: `~/.config/portmon/config.json` (created on first run)

```json
{
  "refresh_interval": 2,
  "port_mappings": [
    {
      "port": "3000",
      "custom_name": "React App",
      "description": "Frontend dev server",
      "hidden": false,
      "link": "http://localhost:3000"
    }
  ]
}
```

| Field | Description | Default |
|-------|-------------|---------|
| `refresh_interval` | Auto-refresh seconds | 2 |
| `port_mappings[].port` | Port number to customize | — |
| `port_mappings[].custom_name` | Display name | — |
| `port_mappings[].description` | Description | — |
| `port_mappings[].hidden` | Hide from display | false |
| `port_mappings[].link` | Saved URL for the port | `http://localhost:PORT` |

Config mappings override the built-in canonical port labels.

You can also press `e` on the Ports tab to write `custom_name` entries back to the config file directly from the TUI. Saving a blank label clears that custom override.

## Requirements

- Linux with `netstat` or `lsof` (stats tab requires `/proc` filesystem)
- macOS: port scanning works via `lsof`, stats tab is Linux-only

## License

[AGPL-3.0](LICENSE)
