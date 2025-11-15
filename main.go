package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Constants
const (
	// Default refresh interval in seconds
	DefaultRefreshInterval = 2

	// Port ranges for development
	DevPortRangeStart1 = 3000
	DevPortRangeEnd1   = 3999
	DevPortRangeStart2 = 4000
	DevPortRangeEnd2   = 4999
	DevPortRangeStart3 = 5000
	DevPortRangeEnd3   = 5999
	DevPortRangeStart4 = 8000
	DevPortRangeEnd4   = 8999
	DevPortRangeStart5 = 9000
	DevPortRangeEnd5   = 9999

	// Ephemeral port threshold
	EphemeralPortThreshold = 10000

	// Table constraints
	MinTableHeight   = 5
	MinProcessWidth  = 15
	TableHeightPad   = 6
	AvailableWidthPad = 15

	// Timeouts
	SIGTERMTimeout = 2 * time.Second

	// Colors
	ColorPrimary   = "86"  // Green
	ColorInfo      = "34"  // Blue
	ColorError     = "196" // Red
	ColorKey       = "39"  // Cyan
	ColorBullet    = "240" // Gray
	ColorDefault   = "240" // Gray
)

type Port struct {
	Port      string
	Process   string
	PID       int
	Status    string
	Protocol  string
	LocalAddr string
	User      string
}

type PortMapping struct {
	Port        string `json:"port"`
	CustomName  string `json:"custom_name"`
	Description string `json:"description"`
	Hidden      bool   `json:"hidden"`
	Link        string `json:"link"`
}

type PortConfig struct {
	Mappings        []PortMapping `json:"port_mappings"`
	RefreshInterval int           `json:"refresh_interval"` // in seconds
}

type model struct {
	table            table.Model
	ports            []Port
	portConfig       PortConfig
	configFile       string
	lastUpdate       time.Time
	width            int
	height           int
	statusMsg        string
	statusColor      string
	showHelp         bool
	showConfirmation bool
	confirmPID       int
	confirmProcess   string
	confirmPort      string
}

type tickMsg time.Time
type updatePortsMsg []Port
type killProcessMsg struct {
	success bool
	error   string
}
type statusUpdateMsg struct {
	message string
	color   string
}

func loadPortConfig(configFile string) PortConfig {
	var config PortConfig
	data, err := os.ReadFile(configFile)
	if err != nil {
		// Create default config
		defaultConfig := PortConfig{
			RefreshInterval: DefaultRefreshInterval,
			Mappings: []PortMapping{
				{Port: "3000", CustomName: "React App", Description: "Frontend development server"},
				{Port: "3001", CustomName: "Next.js", Description: "Next.js development server"},
				{Port: "5000", CustomName: "API Server", Description: "Backend REST API"},
				{Port: "5173", CustomName: "Vite Dev", Description: "Vite development server"},
				{Port: "8000", CustomName: "Django", Description: "Django development server"},
				{Port: "8080", CustomName: "Test Server", Description: "Testing environment"},
				{Port: "9000", CustomName: "Go Server", Description: "Go application server"},
			},
		}

		// Ensure config directory exists
		configDir := filepath.Dir(configFile)
		if err := os.MkdirAll(configDir, 0755); err != nil {
			log.Printf("Warning: Could not create config directory: %v", err)
			return defaultConfig
		}

		// Write default config
		configData, err := json.MarshalIndent(defaultConfig, "", "  ")
		if err != nil {
			log.Printf("Warning: Could not marshal default config: %v", err)
			return defaultConfig
		}

		if err := os.WriteFile(configFile, configData, 0644); err != nil {
			log.Printf("Warning: Could not write config file: %v", err)
		}

		return defaultConfig
	}

	// Parse existing config
	if err := json.Unmarshal(data, &config); err != nil {
		log.Printf("Warning: Could not parse config file, using defaults: %v", err)
		config = PortConfig{RefreshInterval: DefaultRefreshInterval}
	}

	// Ensure refresh interval has a valid value
	if config.RefreshInterval <= 0 {
		config.RefreshInterval = DefaultRefreshInterval
	}

	return config
}

func (m *model) getCustomName(port string) (string, string, bool, string) {
	for _, mapping := range m.portConfig.Mappings {
		if mapping.Port == port {
			return mapping.CustomName, mapping.Description, mapping.Hidden, mapping.Link
		}
	}
	return "", "", false, ""
}

func initialModel() model {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatal("Could not determine home directory: ", err)
	}
	configFile := filepath.Join(homeDir, ".config", "portmon", "config.json")

	columns := []table.Column{
		{Title: "Port", Width: 8},
		{Title: "Protocol", Width: 8},
		{Title: "Process", Width: 20},
		{Title: "PID", Width: 8},
		{Title: "User", Width: 10},
		{Title: "Address", Width: 20},
		{Title: "Status", Width: 10},
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithFocused(true),
		table.WithHeight(10),
	)

	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(false).
		Align(lipgloss.Left).
		PaddingLeft(0)
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("57")).
		Bold(false).
		Align(lipgloss.Left).
		PaddingLeft(0)
	s.Cell = s.Cell.
		Align(lipgloss.Left).
		PaddingLeft(0)
	t.SetStyles(s)

	return model{
		table:            t,
		ports:            []Port{},
		portConfig:       loadPortConfig(configFile),
		configFile:       configFile,
		lastUpdate:       time.Now(),
		width:            80,
		height:           24,
		statusMsg:        "",
		statusColor:      ColorDefault,
		showHelp:         false,
		showConfirmation: false,
		confirmPID:       0,
		confirmProcess:   "",
		confirmPort:      "",
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(
		m.tickCmd(),
		m.updatePorts(),
	)
}

func (m model) tickCmd() tea.Cmd {
	interval := time.Duration(m.portConfig.RefreshInterval) * time.Second
	return tea.Tick(interval, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m model) updatePorts() tea.Cmd {
	return func() tea.Msg {
		ports := getPorts()
		return updatePortsMsg(ports)
	}
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

		tableHeight := m.height - TableHeightPad
		if tableHeight < MinTableHeight {
			tableHeight = MinTableHeight
		}

		availableWidth := m.width - AvailableWidthPad
		portWidth := 8
		protocolWidth := 8
		pidWidth := 8
		userWidth := 10
		statusWidth := 10
		addressWidth := 20
		processWidth := availableWidth - portWidth - protocolWidth - pidWidth - userWidth - statusWidth - addressWidth

		if processWidth < MinProcessWidth {
			processWidth = MinProcessWidth
		}
		if addressWidth > availableWidth/3 {
			addressWidth = availableWidth / 3
		}

		columns := []table.Column{
			{Title: "Port", Width: portWidth},
			{Title: "Protocol", Width: protocolWidth},
			{Title: "Process", Width: processWidth},
			{Title: "PID", Width: pidWidth},
			{Title: "User", Width: userWidth},
			{Title: "Address", Width: addressWidth},
			{Title: "Status", Width: statusWidth},
		}

		m.table.SetColumns(columns)
		m.table.SetHeight(tableHeight)

	case tea.KeyMsg:
		// Handle help screen
		if m.showHelp {
			if msg.String() == "q" || msg.String() == "esc" || msg.String() == "?" {
				m.showHelp = false
				return m, nil
			}
			return m, nil
		}

		// Handle confirmation dialog
		if m.showConfirmation {
			switch msg.String() {
			case "y", "Y":
				m.showConfirmation = false
				return m, m.killProcess(m.confirmPID, m.confirmProcess, m.confirmPort)
			case "n", "N", "esc", "q":
				m.showConfirmation = false
				m.statusMsg = "Kill cancelled"
				m.statusColor = ColorInfo
				return m, nil
			}
			return m, nil
		}

		// Normal key handling
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "q":
			return m, tea.Quit
		case "?":
			m.showHelp = true
			return m, nil
		case "r":
			return m, tea.Batch(
				m.updatePorts(),
				func() tea.Msg {
					return statusUpdateMsg{message: "🔄 Refreshed", color: ColorInfo}
				},
			)
		case "x":
			m.portConfig = loadPortConfig(m.configFile)
			return m, tea.Batch(
				m.updatePorts(),
				func() tea.Msg {
					return statusUpdateMsg{message: "🔄 Config reloaded", color: ColorInfo}
				},
			)
		case "c":
			return m, func() tea.Msg {
				return statusUpdateMsg{message: fmt.Sprintf("📁 Config: %s", m.configFile), color: ColorPrimary}
			}
		case "o":
			if len(m.ports) > 0 {
				selected := m.table.SelectedRow()
				if len(selected) > 0 && selected[0] != "" {
					if strings.Contains(selected[2], "═══") || selected[2] == "" {
						return m, nil
					}

					port := selected[0]
					if _, _, _, link := m.getCustomName(port); link != "" {
						return m, m.openLink(link, port)
					} else {
						defaultLink := fmt.Sprintf("http://localhost:%s", port)
						return m, m.openLink(defaultLink, port)
					}
				}
			}
			return m, nil
		case "enter":
			if len(m.ports) > 0 {
				selected := m.table.SelectedRow()
				if len(selected) > 3 && selected[3] != "" {
					if strings.Contains(selected[2], "═══") || selected[2] == "" {
						return m, nil
					}

					pid, err := strconv.Atoi(selected[3])
					if err == nil && pid > 0 {
						// Show confirmation dialog
						m.showConfirmation = true
						m.confirmPID = pid
						m.confirmProcess = selected[2]
						m.confirmPort = selected[0]
						return m, nil
					}
				}
			}
		}
	case tickMsg:
		m.lastUpdate = time.Time(msg)
		return m, tea.Batch(
			m.tickCmd(),
			m.updatePorts(),
		)
	case updatePortsMsg:
		m.ports = []Port(msg)

		var userPorts []Port
		var systemPorts []Port

		for _, port := range m.ports {
			if _, _, hidden, _ := m.getCustomName(port.Port); hidden {
				continue
			}

			if isUserProcess(port) {
				userPorts = append(userPorts, port)
			} else {
				systemPorts = append(systemPorts, port)
			}
		}

		sort.Slice(userPorts, func(i, j int) bool {
			portI, errI := strconv.Atoi(userPorts[i].Port)
			portJ, errJ := strconv.Atoi(userPorts[j].Port)
			if errI != nil || errJ != nil {
				return userPorts[i].Port < userPorts[j].Port
			}
			return portI < portJ
		})

		sort.Slice(systemPorts, func(i, j int) bool {
			portI, errI := strconv.Atoi(systemPorts[i].Port)
			portJ, errJ := strconv.Atoi(systemPorts[j].Port)
			if errI != nil || errJ != nil {
				return systemPorts[i].Port < systemPorts[j].Port
			}
			return portI < portJ
		})

		m.ports = append(userPorts, systemPorts...)

		var rows []table.Row

		if len(userPorts) > 0 {
			rows = append(rows, table.Row{
				"", "", "═══ USER PROCESSES ═══", "", "", "", "",
			})

			for _, port := range userPorts {
				processName := cleanProcessName(port.Process)

				if customName, _, _, _ := m.getCustomName(port.Port); customName != "" {
					processName = fmt.Sprintf("%s (%s)", customName, processName)
				}

				addressDisplay := cleanAddress(port.LocalAddr)

				rows = append(rows, table.Row{
					port.Port,
					port.Protocol,
					processName,
					strconv.Itoa(port.PID),
					port.User,
					addressDisplay,
					port.Status,
				})
			}
		}

		if len(systemPorts) > 0 {
			if len(userPorts) > 0 {
				rows = append(rows, table.Row{
					"", "", "", "", "", "", "",
				})
			}

			rows = append(rows, table.Row{
				"", "", "═══ SYSTEM PROCESSES ═══", "", "", "", "",
			})

			for _, port := range systemPorts {
				processName := cleanProcessName(port.Process)

				if customName, _, _, _ := m.getCustomName(port.Port); customName != "" {
					processName = fmt.Sprintf("%s (%s)", customName, processName)
				}

				addressDisplay := cleanAddress(port.LocalAddr)

				rows = append(rows, table.Row{
					port.Port,
					port.Protocol,
					processName,
					strconv.Itoa(port.PID),
					port.User,
					addressDisplay,
					port.Status,
				})
			}
		}

		m.table.SetRows(rows)
	case killProcessMsg:
		if msg.success {
			m.statusMsg = msg.error
			m.statusColor = ColorInfo
		} else {
			m.statusMsg = "Error: " + msg.error
			m.statusColor = ColorError
		}
		return m, m.updatePorts()
	case statusUpdateMsg:
		m.statusMsg = msg.message
		m.statusColor = msg.color
		return m, nil
	}

	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

func (m model) killProcess(pid int, processName, port string) tea.Cmd {
	return func() tea.Msg {
		if pid <= 0 {
			return killProcessMsg{success: false, error: "Invalid PID"}
		}

		// Verify process exists
		process, err := os.FindProcess(pid)
		if err != nil {
			return killProcessMsg{success: false, error: fmt.Sprintf("Process %d not found: %v", pid, err)}
		}

		// Try graceful termination first with SIGTERM
		err = process.Signal(syscall.SIGTERM)
		if err != nil {
			// Process may already be dead
			return killProcessMsg{success: false, error: fmt.Sprintf("Failed to send SIGTERM to PID %d: %v", pid, err)}
		}

		// Wait for process to terminate gracefully
		terminated := make(chan bool, 1)
		go func() {
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()
			timeout := time.After(SIGTERMTimeout)

			for {
				select {
				case <-timeout:
					terminated <- false
					return
				case <-ticker.C:
					// Check if process still exists
					if err := process.Signal(syscall.Signal(0)); err != nil {
						// Process is gone
						terminated <- true
						return
					}
				}
			}
		}()

		if <-terminated {
			// Process terminated gracefully
			return killProcessMsg{
				success: true,
				error:   fmt.Sprintf("✓ Terminated %s (PID %d) on port %s", processName, pid, port),
			}
		}

		// Process didn't terminate, force kill with SIGKILL
		err = process.Kill()
		if err != nil {
			return killProcessMsg{
				success: false,
				error:   fmt.Sprintf("Failed to kill PID %d: %v", pid, err),
			}
		}

		return killProcessMsg{
			success: true,
			error:   fmt.Sprintf("✓ Force killed %s (PID %d) on port %s", processName, pid, port),
		}
	}
}

func (m model) openLink(url string, port string) tea.Cmd {
	return func() tea.Msg {
		var cmd *exec.Cmd

		// Detect OS and use appropriate command
		switch runtime.GOOS {
		case "linux":
			cmd = exec.Command("xdg-open", url)
		case "darwin":
			cmd = exec.Command("open", url)
		case "windows":
			cmd = exec.Command("cmd", "/c", "start", url)
		default:
			return statusUpdateMsg{
				message: fmt.Sprintf("❌ Unsupported OS: %s", runtime.GOOS),
				color:   ColorError,
			}
		}

		err := cmd.Start()
		if err != nil {
			return statusUpdateMsg{
				message: fmt.Sprintf("❌ Failed to open %s: %v", url, err),
				color:   ColorError,
			}
		}

		return statusUpdateMsg{
			message: fmt.Sprintf("🌐 Opened %s (port %s)", url, port),
			color:   ColorInfo,
		}
	}
}

func (m model) View() string {
	// Show help screen
	if m.showHelp {
		return m.renderHelpScreen()
	}

	// Show confirmation dialog
	if m.showConfirmation {
		return m.renderConfirmationDialog()
	}

	// Normal view
	header := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color(ColorPrimary)).
		Width(m.width).
		Align(lipgloss.Left).
		Render("🔍 Portmon - Live Port Monitor")

	baseInfo := fmt.Sprintf("Last updated: %s", m.lastUpdate.Format("15:04:05"))

	// Color styles for commands
	keyStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(ColorKey))
	actionStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(ColorPrimary))
	bulletStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(ColorBullet))

	commandsLine := fmt.Sprintf("%s: %s %s %s: %s %s %s: %s %s %s: %s %s %s: %s %s %s: %s %s %s: %s",
		keyStyle.Render("?"),
		actionStyle.Render("help"),
		bulletStyle.Render("•"),
		keyStyle.Render("q"),
		actionStyle.Render("quit"),
		bulletStyle.Render("•"),
		keyStyle.Render("enter"),
		actionStyle.Render("kill"),
		bulletStyle.Render("•"),
		keyStyle.Render("o"),
		actionStyle.Render("open"),
		bulletStyle.Render("•"),
		keyStyle.Render("r"),
		actionStyle.Render("refresh"),
		bulletStyle.Render("•"),
		keyStyle.Render("x"),
		actionStyle.Render("reload config"),
		bulletStyle.Render("•"),
		keyStyle.Render("c"),
		actionStyle.Render("config path"))

	infoText := baseInfo + "\n" + commandsLine
	if m.statusMsg != "" {
		infoText = fmt.Sprintf("%s\n> %s", infoText, m.statusMsg)
	}

	info := lipgloss.NewStyle().
		Foreground(lipgloss.Color(m.statusColor)).
		Width(m.width).
		Align(lipgloss.Left).
		Render(infoText)

	return fmt.Sprintf("%s\n\n%s\n\n%s", header, m.table.View(), info)
}

func (m model) renderHelpScreen() string {
	helpStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(ColorPrimary)).
		Padding(1, 2).
		Width(m.width - 4)

	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color(ColorPrimary))

	keyStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color(ColorKey))

	helpText := fmt.Sprintf(`%s

%s           Navigate through ports
%s       Kill selected process (with confirmation)
%s           Open port URL in browser
%s           Manually refresh port list
%s           Reload configuration file
%s           Show configuration file path
%s           Show this help screen
%s      Quit application

%s
- Refresh interval: %d seconds (configurable in config)
- Config file: %s
- Press %s or %s to close this help screen`,
		titleStyle.Render("📖 Portmon Help"),
		keyStyle.Render("↑/↓, j/k"),
		keyStyle.Render("Enter"),
		keyStyle.Render("o"),
		keyStyle.Render("r"),
		keyStyle.Render("x"),
		keyStyle.Render("c"),
		keyStyle.Render("?"),
		keyStyle.Render("q, Ctrl+C"),
		titleStyle.Render("Configuration"),
		m.portConfig.RefreshInterval,
		m.configFile,
		keyStyle.Render("?"),
		keyStyle.Render("q"))

	return lipgloss.Place(m.width, m.height,
		lipgloss.Center, lipgloss.Center,
		helpStyle.Render(helpText))
}

func (m model) renderConfirmationDialog() string {
	dialogStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(ColorError)).
		Padding(1, 2).
		Width(60)

	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color(ColorError))

	keyStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color(ColorKey))

	confirmText := fmt.Sprintf(`%s

Are you sure you want to kill this process?

Process: %s
PID:     %d
Port:    %s

The process will receive SIGTERM first, then SIGKILL if needed.

Press %s to confirm, %s to cancel`,
		titleStyle.Render("⚠️  Confirm Kill Process"),
		m.confirmProcess,
		m.confirmPID,
		m.confirmPort,
		keyStyle.Render("Y"),
		keyStyle.Render("N"))

	// Show table in background with overlay
	background := m.renderNormalView()

	dialog := lipgloss.Place(m.width, m.height,
		lipgloss.Center, lipgloss.Center,
		dialogStyle.Render(confirmText))

	// Dim the background
	dimStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))

	return lipgloss.JoinVertical(lipgloss.Left,
		dimStyle.Render(background),
		dialog)
}

func (m model) renderNormalView() string {
	header := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color(ColorPrimary)).
		Width(m.width).
		Align(lipgloss.Left).
		Render("🔍 Portmon - Live Port Monitor")

	baseInfo := fmt.Sprintf("Last updated: %s", m.lastUpdate.Format("15:04:05"))

	keyStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(ColorKey))
	actionStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(ColorPrimary))
	bulletStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(ColorBullet))

	commandsLine := fmt.Sprintf("%s: %s %s %s: %s %s %s: %s %s %s: %s %s %s: %s %s %s: %s %s %s: %s",
		keyStyle.Render("?"),
		actionStyle.Render("help"),
		bulletStyle.Render("•"),
		keyStyle.Render("q"),
		actionStyle.Render("quit"),
		bulletStyle.Render("•"),
		keyStyle.Render("enter"),
		actionStyle.Render("kill"),
		bulletStyle.Render("•"),
		keyStyle.Render("o"),
		actionStyle.Render("open"),
		bulletStyle.Render("•"),
		keyStyle.Render("r"),
		actionStyle.Render("refresh"),
		bulletStyle.Render("•"),
		keyStyle.Render("x"),
		actionStyle.Render("reload config"),
		bulletStyle.Render("•"),
		keyStyle.Render("c"),
		actionStyle.Render("config path"))

	infoText := baseInfo + "\n" + commandsLine
	if m.statusMsg != "" {
		infoText = fmt.Sprintf("%s\n> %s", infoText, m.statusMsg)
	}

	info := lipgloss.NewStyle().
		Foreground(lipgloss.Color(m.statusColor)).
		Width(m.width).
		Align(lipgloss.Left).
		Render(infoText)

	return fmt.Sprintf("%s\n\n%s\n\n%s", header, m.table.View(), info)
}

func getPorts() []Port {
	var ports []Port
	var netstatErr, lsofErr error

	// Try netstat first
	cmd := exec.Command("netstat", "-tulpn")
	output, err := cmd.Output()
	if err == nil {
		ports = parseNetstatOutput(string(output))
		if len(ports) > 0 {
			return ports
		}
	} else {
		netstatErr = err
	}

	// Fallback to lsof
	cmd = exec.Command("lsof", "-i", "-P", "-n")
	output, err = cmd.Output()
	if err == nil {
		ports = parseLsofOutput(string(output))
		if len(ports) > 0 {
			return ports
		}
	} else {
		lsofErr = err
	}

	// If both failed, log a helpful message
	if netstatErr != nil && lsofErr != nil {
		log.Printf("Warning: Both netstat and lsof failed. Please install one of these tools:")
		log.Printf("  - netstat: sudo apt-get install net-tools (Debian/Ubuntu)")
		log.Printf("  - lsof: sudo apt-get install lsof (Debian/Ubuntu)")
	}

	return ports
}

func parseNetstatOutput(output string) []Port {
	var ports []Port
	lines := strings.Split(output, "\n")

	re := regexp.MustCompile(`(\w+)\s+\d+\s+\d+\s+([^\s]+):(\d+)\s+[^\s]+\s+(\w+)(?:\s+(\d+)/([^\s]+))?`)

	for _, line := range lines {
		matches := re.FindStringSubmatch(line)
		if len(matches) >= 6 {
			port := Port{
				Port:      matches[3],
				Protocol:  strings.ToUpper(matches[1]),
				Status:    matches[4],
				LocalAddr: matches[2] + ":" + matches[3],
				Process:   "unknown",
				PID:       0,
				User:      "unknown",
			}

			if matches[5] != "" {
				if pid, err := strconv.Atoi(matches[5]); err == nil {
					port.PID = pid
				}
			}

			if matches[6] != "" {
				port.Process = matches[6]
			}

			if port.PID > 0 {
				if user := getUserFromPID(port.PID); user != "" {
					port.User = user
				}
			}

			ports = append(ports, port)
		}
	}

	return ports
}

func parseLsofOutput(output string) []Port {
	var ports []Port
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		if strings.Contains(line, "LISTEN") || strings.Contains(line, "TCP") {
			fields := strings.Fields(line)
			if len(fields) >= 9 {
				port := Port{
					Process:   fields[0],
					Status:    "LISTEN",
					Port:      "",
					Protocol:  "TCP",
					LocalAddr: "",
					PID:       0,
					User:      "unknown",
				}

				if pid, err := strconv.Atoi(fields[1]); err == nil {
					port.PID = pid
				}

				if len(fields) > 2 {
					port.User = fields[2]
				}

				if len(fields) > 8 {
					port.LocalAddr = fields[8]
					if colonIndex := strings.LastIndex(fields[8], ":"); colonIndex != -1 {
						port.Port = fields[8][colonIndex+1:]
					}
				}

				ports = append(ports, port)
			}
		}
	}

	return ports
}

func getUserFromPID(pid int) string {
	cmd := exec.Command("ps", "-o", "user=", "-p", strconv.Itoa(pid))
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}

	user := strings.TrimSpace(string(output))
	if user == "" {
		return "unknown"
	}

	return user
}

func isUserProcess(port Port) bool {
	currentUser := os.Getenv("USER")
	if currentUser == "" {
		currentUser = os.Getenv("LOGNAME")
	}

	// System users are definitely system processes
	systemUsers := []string{"root", "daemon", "nobody", "www-data", "nginx", "apache", "mysql", "postgres", "systemd+"}
	for _, sysUser := range systemUsers {
		if port.User == sysUser {
			return false
		}
	}

	// If not running under current user, it's definitely system
	if port.User != currentUser {
		return false
	}

	// High ports (ephemeral range) are typically system processes - check this FIRST
	if port.Port != "" {
		if portNum, err := strconv.Atoi(port.Port); err == nil {
			if portNum >= EphemeralPortThreshold {
				return false // High ephemeral ports are system processes
			}
		}
	}

	processName := strings.ToLower(port.Process)

	// Known development/user processes
	userProcesses := []string{
		"node", "npm", "yarn", "pnpm", "bun",
		"python", "python3", "pip", "poetry", "uvicorn", "gunicorn", "flask", "django",
		"java", "mvn", "gradle", "spring",
		"go", "air", "gin",
		"php", "composer", "artisan",
		"ruby", "rails", "bundle",
		"rust", "cargo",
		"docker", "docker-compose",
		"nginx", "apache", "httpd",
		"mysql", "postgres", "postgresql", "redis", "mongodb", "sqlite",
		"code", "vscode", "sublime", "vim", "nvim", "emacs",
		"git", "gitk",
		"webpack", "vite", "parcel", "rollup",
		"jest", "mocha", "cypress", "playwright",
		"http-server", "serve", "static-server",
	}

	// Check if it's a known development process
	for _, userProc := range userProcesses {
		if strings.Contains(processName, userProc) {
			return true
		}
	}

	// Check for common development port ranges (only for lower ports now)
	if port.Port != "" {
		portNum, err := strconv.Atoi(port.Port)
		if err == nil {
			// Common development ports
			if isCommonDevPort(portNum) {
				return true
			}

			// Development port ranges
			if (portNum >= DevPortRangeStart1 && portNum <= DevPortRangeEnd1) ||
				(portNum >= DevPortRangeStart2 && portNum <= DevPortRangeEnd2) ||
				(portNum >= DevPortRangeStart3 && portNum <= DevPortRangeEnd3) ||
				(portNum >= DevPortRangeStart4 && portNum <= DevPortRangeEnd4) ||
				(portNum >= DevPortRangeStart5 && portNum <= DevPortRangeEnd5) {
				return true
			}
		}
	}

	// Default: if it's under current user but not identified as dev process, treat as system
	return false
}

// Helper function to identify common development ports
func isCommonDevPort(portNum int) bool {
	commonDevPorts := []int{3000, 3001, 3002, 3003, 4000, 5000, 5001, 5173, 8000, 8080, 8081, 8888, 9000}
	for _, devPort := range commonDevPorts {
		if portNum == devPort {
			return true
		}
	}
	return false
}

func cleanProcessName(process string) string {
	if process == "unknown" {
		return "unknown"
	}

	switch {
	case strings.Contains(process, "node"):
		return "node"
	case strings.Contains(process, "python"):
		return "python"
	case strings.Contains(process, "java"):
		return "java"
	case strings.Contains(process, "nginx"):
		return "nginx"
	case strings.Contains(process, "apache"):
		return "apache"
	case strings.Contains(process, "mysql"):
		return "mysql"
	case strings.Contains(process, "postgres"):
		return "postgres"
	case strings.Contains(process, "redis"):
		return "redis"
	case strings.Contains(process, "docker"):
		return "docker"
	case strings.Contains(process, "ssh"):
		return "ssh"
	}

	return process
}

func cleanAddress(address string) string {
	if address == "" {
		return ""
	}

	address = strings.ReplaceAll(address, "127.0.0.1", "localhost")
	address = strings.ReplaceAll(address, "::1", "localhost")
	address = strings.ReplaceAll(address, "0.0.0.0", "*")
	address = strings.ReplaceAll(address, "::", "*")

	return address
}

func main() {
	p := tea.NewProgram(initialModel(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		log.Fatal(err)
	}

}
