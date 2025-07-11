# Portmon 🔍

A live port monitoring tool built with Go that provides a real-time, interactive terminal interface for viewing and managing network ports and their associated processes.

## Features

- **Real-time monitoring** - Updates every 2 seconds automatically
- **Interactive TUI** - Built with Bubble Tea for a smooth terminal experience
- **Process management** - Kill processes directly from the interface
- **Smart categorization** - Separates user processes from system processes
- **Responsive design** - Adapts to terminal window size
- **Multiple data sources** - Uses both `netstat` and `lsof` for comprehensive port information

## Installation

### Prerequisites

- Go 1.23.3 or later
- Linux/Unix system with `netstat` or `lsof` available

### Build from source

```bash
git clone <repository-url>
cd portmon
go build -o portmon
```

### Install to local bin

```bash
# Build and copy to local bin directory
go build -o portmon
cp portmon ~/.local/bin/
```

to edit custom ports:
Run it once, then edit the portmon-config.json, in the directory with the build file.

```bash
nano ~/.local/bin/portmon-config.json 
```

Make sure `~/.local/bin` is in your PATH.

## Usage

### Basic usage

```bash
portmon
```

### Controls

- **Arrow keys** or **j/k** - Navigate through the port list
- **Enter** - Kill the selected process (with confirmation)
- **q** or **Ctrl+C** - Quit the application

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

### Killing a process
1. Navigate to the process using arrow keys
2. Press Enter
3. The process will be terminated (SIGTERM first, then SIGKILL if needed)
4. Status message will show the result
5. Press q to exit application.

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
- Graceful termination with SIGTERM first
- Force termination with SIGKILL if SIGTERM fails
- Real-time status feedback

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