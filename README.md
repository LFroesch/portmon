# portmon

Terminal dashboard for live port inspection and lightweight system stats. `portmon` is mainly for figuring out what is listening where, which process owns it, and which noisy ports should be labeled or hidden.

![portmon hero screenshot](assets/screenshots/hero.png)

**Live demo:** [froesch.dev](https://froesch.dev)

## Release Status

Developed for WSL2/Linux first. Cross-platform testing and bug fixing for macOS and native Windows are still in progress.

Linux is the primary target. The ports view is usable on macOS, but the stats tab is Linux-only. Native Windows is not supported for this app yet.

## Install

Quick install:

```bash
curl -fsSL https://raw.githubusercontent.com/LFroesch/portmon/main/install.sh | bash
```

Direct installer: [`install.sh`](https://raw.githubusercontent.com/LFroesch/portmon/main/install.sh)

Other options:

```bash
go install github.com/LFroesch/portmon@latest
make install
```

Run:

```bash
portmon
portmon --version
```

## Tabs

| Tab | Purpose |
|-----|---------|
| Ports | Live table of listening and active ports with process info |
| Stats | Linux system dashboard with CPU, memory, disk, network, and top processes |

## Features

- Live port table with PID, process name, owner, address, CPU, and memory
- Custom labels and hidden-port rules from config
- Fast inline filtering
- Process kill flow with confirmation
- Linux stats dashboard with sparklines

## Config

Config is created on first run at `~/.config/portmon/config.json`.

```json
{
  "refresh_interval": 2,
  "port_mappings": [
    {
      "port": "3000",
      "custom_name": "React App",
      "description": "Frontend dev server",
      "hidden": false
    }
  ]
}
```

Use `e` in the app to add or clear custom labels directly from the Ports tab.

## Requirements

- Linux: `netstat` or `lsof`
- macOS: `lsof`
- Stats tab on Linux also relies on `/proc`

If neither scanner is available, `portmon` shows an explicit warning instead of an empty table.

## Controls

| Key | Action |
|-----|--------|
| `tab`, `1`, `2` | Switch tabs |
| `/` | Filter ports |
| `j/k` | Move |
| `e` | Edit label |
| `enter` | Kill selected process |
| `r` | Refresh |
| `x` | Reload config |
| `c` | Show config path |
| `?` | Help |
| `q` | Quit |

## License

[AGPL-3.0](LICENSE)
