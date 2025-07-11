package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
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
	Mappings []PortMapping `json:"port_mappings"`
}

type model struct {
	table       table.Model
	ports       []Port
	portConfig  PortConfig
	configFile  string
	lastUpdate  time.Time
	width       int
	height      int
	statusMsg   string
	statusColor string
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
		defaultConfig := PortConfig{
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

		data, _ := json.MarshalIndent(defaultConfig, "", "  ")
		os.WriteFile(configFile, data, 0644)
		return defaultConfig
	}

	json.Unmarshal(data, &config)
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
	execPath, err := os.Executable()
	var configFile string

	if err != nil {
		homeDir, _ := os.UserHomeDir()
		configFile = filepath.Join(homeDir, ".portmon-config.json")
	} else {
		execDir := filepath.Dir(execPath)
		configFile = filepath.Join(execDir, "portmon-config.json")
	}

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
		table:       t,
		ports:       []Port{},
		portConfig:  loadPortConfig(configFile),
		configFile:  configFile,
		lastUpdate:  time.Now(),
		width:       80,
		height:      24,
		statusMsg:   "",
		statusColor: "240",
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(
		tickCmd(),
		m.updatePorts(),
	)
}

func tickCmd() tea.Cmd {
	return tea.Tick(time.Second*2, func(t time.Time) tea.Msg {
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

		tableHeight := m.height - 6
		if tableHeight < 5 {
			tableHeight = 5
		}

		availableWidth := m.width - 15
		portWidth := 8
		protocolWidth := 8
		pidWidth := 8
		userWidth := 10
		statusWidth := 10
		addressWidth := 20
		processWidth := availableWidth - portWidth - protocolWidth - pidWidth - userWidth - statusWidth - addressWidth

		if processWidth < 15 {
			processWidth = 15
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
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "r":
			return m, tea.Batch(
				m.updatePorts(),
				func() tea.Msg {
					return statusUpdateMsg{message: "🔄 Refreshed", color: "34"}
				},
			)
		case "x":
			m.portConfig = loadPortConfig(m.configFile)
			return m, tea.Batch(
				m.updatePorts(),
				func() tea.Msg {
					return statusUpdateMsg{message: "🔄 Config reloaded", color: "34"}
				},
			)
		case "c":
			return m, func() tea.Msg {
				return statusUpdateMsg{message: fmt.Sprintf("📁 Config: %s", m.configFile), color: "86"}
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
						return m, m.killProcess(pid, selected[2])
					}
				}
			}
		}
	case tickMsg:
		m.lastUpdate = time.Time(msg)
		if m.statusMsg != "" {
			m.statusMsg = ""
			m.statusColor = "240"
		}
		return m, tea.Batch(
			tickCmd(),
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
			m.statusColor = "34"
		} else {
			m.statusMsg = "Error: " + msg.error
			m.statusColor = "196"
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

func (m model) killProcess(pid int, processName string) tea.Cmd {
	return func() tea.Msg {
		if pid <= 0 {
			return killProcessMsg{success: false, error: "Invalid PID"}
		}

		selected := m.table.SelectedRow()
		if len(selected) == 0 {
			return killProcessMsg{success: false, error: "No row selected"}
		}

		port := selected[0]

		cmd := exec.Command("lsof", "-ti", fmt.Sprintf(":%s", port))
		output, err := cmd.Output()

		if err == nil && len(output) > 0 {
			pidStr := strings.TrimSpace(string(output))
			lines := strings.Split(pidStr, "\n")

			for _, line := range lines {
				if targetPid, err := strconv.Atoi(strings.TrimSpace(line)); err == nil {
					if targetPid == pid {
						err := syscall.Kill(targetPid, syscall.SIGKILL)
						if err != nil {
							return killProcessMsg{success: false, error: fmt.Sprintf("Failed to kill PID %d: %v", targetPid, err)}
						}
						return killProcessMsg{success: true, error: fmt.Sprintf("Killed %s (PID %d) on port %s", processName, targetPid, port)}
					}
				}
			}
		}

		err = syscall.Kill(pid, syscall.SIGKILL)
		if err != nil {
			return killProcessMsg{success: false, error: fmt.Sprintf("Failed to kill PID %d: %v", pid, err)}
		}

		return killProcessMsg{success: true, error: fmt.Sprintf("Killed %s (PID %d)", processName, pid)}
	}
}

func (m model) openLink(url string, port string) tea.Cmd {
	return func() tea.Msg {
		cmd := exec.Command("cmd.exe", "/c", "start", url)
		err := cmd.Start()

		if err != nil {
			return statusUpdateMsg{message: fmt.Sprintf("❌ Failed to open %s: %v", url, err), color: "196"}
		}

		return statusUpdateMsg{message: fmt.Sprintf("🌐 Opened %s (port %s)", url, port), color: "34"}
	}
}

func (m model) View() string {
	header := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("86")).
		Width(m.width).
		Align(lipgloss.Left).
		Render("🔍 Portmon - Live Port Monitor")

	baseInfo := fmt.Sprintf("Last updated: %s | 'q': quit | 'enter': kill | 'o': open link | 'r': refresh | 'x': reload config | 'c': show config path",
		m.lastUpdate.Format("15:04:05"))

	infoText := baseInfo
	if m.statusMsg != "" {
		infoText = fmt.Sprintf("%s \n> %s", baseInfo, m.statusMsg)
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

	cmd := exec.Command("netstat", "-tulpn")
	output, err := cmd.Output()
	if err == nil {
		ports = parseNetstatOutput(string(output))
	}

	if len(ports) == 0 {
		cmd = exec.Command("lsof", "-i", "-P", "-n")
		output, err = cmd.Output()
		if err == nil {
			ports = parseLsofOutput(string(output))
		}
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

	if port.User == currentUser {
		processName := strings.ToLower(port.Process)
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

		for _, userProc := range userProcesses {
			if strings.Contains(processName, userProc) {
				return true
			}
		}

		if port.Port != "" {
			portNum, err := strconv.Atoi(port.Port)
			if err == nil {
				userPorts := []int{3000, 3001, 3002, 3003, 4000, 5000, 5001, 5173, 8000, 8080, 8081, 8888, 9000}
				for _, userPort := range userPorts {
					if portNum == userPort {
						return true
					}
				}

				if (portNum >= 3000 && portNum <= 3999) ||
					(portNum >= 4000 && portNum <= 4999) ||
					(portNum >= 5000 && portNum <= 5999) ||
					(portNum >= 8000 && portNum <= 8999) ||
					(portNum >= 9000 && portNum <= 9999) {
					return true
				}
			}
		}
	}

	systemUsers := []string{"root", "daemon", "nobody", "www-data", "nginx", "apache", "mysql", "postgres", "systemd+"}
	for _, sysUser := range systemUsers {
		if port.User == sysUser {
			return false
		}
	}

	return port.User == currentUser
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
