# Portmon 🔍

A live port monitoring tool built with Go that provides a real-time, interactive terminal interface for viewing and managing network ports and their associated processes.

## Features

- **Real-time monitoring** - Configurable auto-refresh interval (default 2 seconds)
- **Interactive TUI** - Built with Bubble Tea for a smooth terminal experience
- **Process management** - Kill processes with confirmation and graceful termination (SIGTERM → SIGKILL)
- **Smart categorization** - Separates user processes from system processes
- **Responsive design** - Adapts to terminal window size
- **Multiple data sources** - Uses both `netstat` and `lsof` for comprehensive port information
- **Cross-platform** - Works on Linux, macOS, and Windows
- **Help screen** - Press `?` for interactive help
- **Safety features** - Confirmation dialogs before killing processes

## Installation

```bash
go install github.com/LFroesch/portmon@latest
```

Make sure `$GOPATH/bin` (usually `~/go/bin`) is in your PATH:
```bash
export PATH="$HOME/go/bin:$PATH"
```

### Prerequisites

- One of the following systems:
  - **Linux** with `netstat` or `lsof` available
  - **macOS** with `lsof` (usually pre-installed)
  - **Windows** with appropriate network tools

### Configuration

Portmon creates a configuration file at `~/.config/portmon/config.json` on first run. This file allows you to customize port names, descriptions, and links.

```bash
# Edit the configuration file
nano ~/.config/portmon/config.json
```

Make sure `~/.local/bin` is in your PATH.

## Usage

### Basic usage

```bash
portmon
```

### Controls

- **Arrow keys** or **j/k** - Navigate through the port list
- **?** - Show help screen with all keyboard shortcuts
- **Enter** - Kill the selected process (shows confirmation dialog)
- **o** - Open the port's URL in your default browser (cross-platform)
- **r** - Manually refresh the port list
- **x** - Reload configuration file
- **c** - Show configuration file path
- **q** or **Ctrl+C** - Quit the application

**In confirmation dialog:**
- **Y** - Confirm kill process
- **N** or **Esc** - Cancel

### Interface

The interface displays ports in two sections:

1. **User Processes** - Development servers, applications you're running
2. **System Processes** - System services, daemons

Each entry shows:
- **Port** - The port number
- **Protocol** - TCP/UDP
- **Process** - Process name
- **PID** - Process ID
- **User** - User running the process
- **Address** - Bind address (simplified display)
- **Status** - Connection status

## Configuration File

The configuration file (`~/.config/portmon/config.json`) allows you to customize how ports are displayed:

```json
{
  "refresh_interval": 2,
  "port_mappings": [
    {
      "port": "3000",
      "custom_name": "React App",
      "description": "Frontend development server",
      "hidden": false,
      "link": "http://localhost:3000"
    },
    {
      "port": "5000",
      "custom_name": "API Server",
      "description": "Backend REST API",
      "hidden": false,
      "link": "http://localhost:5000/api"
    }
  ]
}
```

### Configuration Options

**Global Settings:**
- **refresh_interval**: Auto-refresh interval in seconds (default: 2)

**Port Mapping Options:**
- **port**: The port number to customize
- **custom_name**: Display name for the port (shown in the Process column)
- **description**: Description of what runs on this port
- **hidden**: Set to `true` to hide this port from the display
- **link**: Custom URL to open when pressing 'o' (defaults to `http://localhost:PORT`)

## Smart Process Detection

Portmon intelligently categorizes processes to show your development work first:

### User Processes (shown first)
- Development servers: `node`, `python`, `go`, `php`, `ruby`
- Build tools: `npm`, `yarn`, `webpack`, `vite`
- Databases: `mysql`, `postgres`, `redis`, `mongodb`
- Web servers: `nginx`, `apache`
- Docker containers
- Common development ports (3000-3999, 4000-4999, 5000-5999, 8000-8999, 9000-9999)

### System Processes (shown after)
- System services
- Processes owned by system users (`root`, `daemon`, `www-data`, etc.)

## Examples

### Typical development scenario
```
🔍 Portmon - Live Port Monitor

Port    Protocol Process         PID     User    Address              Status
════════════════════════════════════════════════════════════════════════════
        ═══ USER PROCESSES ═══
3000    TCP      node           12345   lucas   localhost:3000       LISTEN
5432    TCP      postgres       12346   lucas   localhost:5432       LISTEN
6379    TCP      redis          12347   lucas   localhost:6379       LISTEN

        ═══ SYSTEM PROCESSES ═══
22      TCP      ssh            1234    root    *:22                 LISTEN
80      TCP      nginx          1235    www     *:80                 LISTEN
```

### Opening a port in browser
1. Navigate to the process using arrow keys
2. Press **o**
3. The port's URL will open in your default browser
4. Uses custom link from config if available, otherwise defaults to `http://localhost:PORT`

### Killing a process
1. Navigate to the process using arrow keys
2. Press **Enter**
3. The process will be terminated (SIGKILL)
4. Status message will show the result

### Refreshing and configuration
- Press **r** to manually refresh the port list
- Press **x** to reload the configuration file (useful after editing config)
- Press **c** to see the configuration file path

## Dependencies

- [Bubble Tea](https://github.com/charmbracelet/bubbletea) - TUI framework
- [Bubbles](https://github.com/charmbracelet/bubbles) - TUI components
- [Lip Gloss](https://github.com/charmbracelet/lipgloss) - Style and layout

## Technical Details

### Data Collection
- Primary: `netstat -tulpn` for comprehensive port information
- Fallback: `lsof -i -P -n` if netstat is unavailable
- User information retrieved via `ps -o user=`

### Process Termination
- Confirmation dialog before terminating any process
- Graceful termination with SIGTERM first (2-second timeout)
- Automatic force termination with SIGKILL if SIGTERM fails
- Real-time status feedback with detailed messages
- Process validation before termination

### Performance
- Lightweight Go binary
- Efficient terminal rendering
- Minimal system resource usage


## Troubleshooting

### Permission Issues
If you can't kill certain processes, you may need elevated privileges:
```bash
sudo portmon
```

### Missing Commands
Ensure `netstat` or `lsof` is available:
```bash
# On Ubuntu/Debian
sudo apt-get install net-tools

# For lsof
sudo apt-get install lsof
```

### Display Issues
If the interface appears corrupted, try resizing your terminal or restarting the application.