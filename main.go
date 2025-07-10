package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
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

type model struct {
	table       table.Model
	ports       []Port
	lastUpdate  time.Time
	width       int
	height      int
	statusMsg   string
	statusColor string
}

type tickMsg time.Time

func initialModel() model {
	columns := []table.Column{
		{Title: "Port", Width: 8},
		{Title: "Protocol", Width: 8},
		{Title: "Process", Width: 15},
		{Title: "PID", Width: 8},
		{Title: "User", Width: 10},
		{Title: "Address", Width: 20},
		{Title: "Status", Width: 10},
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithFocused(true),
		table.WithHeight(10), // Initial height, will be adjusted
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

type updatePortsMsg []Port

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

		// Adjust table height: total height - header - footer - borders
		tableHeight := m.height - 6
		if tableHeight < 5 {
			tableHeight = 5
		}

		// Adjust column widths based on terminal width
		availableWidth := m.width - 15 // Account for borders and padding
		portWidth := 8
		protocolWidth := 8
		pidWidth := 8
		userWidth := 10
		statusWidth := 10
		addressWidth := 20
		processWidth := availableWidth - portWidth - protocolWidth - pidWidth - userWidth - statusWidth - addressWidth

		if processWidth < 10 {
			processWidth = 10
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
		case "enter":
			if len(m.ports) > 0 {
				selected := m.table.SelectedRow()
				if len(selected) > 3 && selected[3] != "" {
					// Check if this is a section header row or empty spacing row
					if strings.Contains(selected[2], "═══") || selected[2] == "" {
						// Skip section headers and spacing rows
						return m, nil
					}

					pid, err := strconv.Atoi(selected[3])
					if err == nil && pid > 0 {
						return m, m.killProcess(pid, selected[2]) // Pass process name too
					}
				}
			}
		}
	case tickMsg:
		m.lastUpdate = time.Time(msg)
		// Clear status message after a few seconds
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

		// Separate user processes from system processes
		var userPorts []Port
		var systemPorts []Port

		for _, port := range m.ports {
			if isUserProcess(port) {
				userPorts = append(userPorts, port)
			} else {
				systemPorts = append(systemPorts, port)
			}
		}

		// Sort user ports by port number
		sort.Slice(userPorts, func(i, j int) bool {
			portI, errI := strconv.Atoi(userPorts[i].Port)
			portJ, errJ := strconv.Atoi(userPorts[j].Port)
			if errI != nil || errJ != nil {
				return userPorts[i].Port < userPorts[j].Port
			}
			return portI < portJ
		})

		// Sort system ports by port number
		sort.Slice(systemPorts, func(i, j int) bool {
			portI, errI := strconv.Atoi(systemPorts[i].Port)
			portJ, errJ := strconv.Atoi(systemPorts[j].Port)
			if errI != nil || errJ != nil {
				return systemPorts[i].Port < systemPorts[j].Port
			}
			return portI < portJ
		})

		// Combine ports with user processes first, then system processes
		m.ports = append(userPorts, systemPorts...)

		// Create rows with section separators
		var rows []table.Row

		// Add user processes section
		if len(userPorts) > 0 {
			// Add section header for user processes
			rows = append(rows, table.Row{
				"", "", "═══ USER PROCESSES ═══", "", "", "", "",
			})

			for _, port := range userPorts {
				processName := cleanProcessName(port.Process)
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

		// Add system processes section
		if len(systemPorts) > 0 {
			// Add spacing between sections if we have user processes
			if len(userPorts) > 0 {
				rows = append(rows, table.Row{
					"", "", "", "", "", "", "",
				})
			}

			// Add section header for system processes
			rows = append(rows, table.Row{
				"", "", "═══ SYSTEM PROCESSES ═══", "", "", "", "",
			})

			for _, port := range systemPorts {
				processName := cleanProcessName(port.Process)
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
			m.statusMsg = msg.error // Contains success message
			m.statusColor = "34"    // Green
		} else {
			m.statusMsg = "Error: " + msg.error
			m.statusColor = "196" // Red
		}
		return m, m.updatePorts()
	}

	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

type killProcessMsg struct {
	success bool
	error   string
}

func (m model) killProcess(pid int, processName string) tea.Cmd {
	return func() tea.Msg {
		if pid <= 0 {
			return killProcessMsg{success: false, error: "Invalid PID"}
		}

		// Get the port number from the selected row
		selected := m.table.SelectedRow()
		if len(selected) == 0 {
			return killProcessMsg{success: false, error: "No row selected"}
		}

		port := selected[0]

		// Try to kill by port using lsof - this is often more reliable
		cmd := exec.Command("lsof", "-ti", fmt.Sprintf(":%s", port))
		output, err := cmd.Output()

		if err == nil && len(output) > 0 {
			// lsof found PIDs using this port
			pidStr := strings.TrimSpace(string(output))
			lines := strings.Split(pidStr, "\n")

			for _, line := range lines {
				if targetPid, err := strconv.Atoi(strings.TrimSpace(line)); err == nil {
					// Only kill the exact PID we clicked on
					if targetPid == pid {
						err := syscall.Kill(targetPid, syscall.SIGKILL) // Use SIGKILL directly
						if err != nil {
							return killProcessMsg{success: false, error: fmt.Sprintf("Failed to kill PID %d: %v", targetPid, err)}
						}
						return killProcessMsg{success: true, error: fmt.Sprintf("Killed %s (PID %d) on port %s", processName, targetPid, port)}
					}
				}
			}
		}

		// Fallback to direct PID kill if lsof approach didn't work
		err = syscall.Kill(pid, syscall.SIGKILL)
		if err != nil {
			return killProcessMsg{success: false, error: fmt.Sprintf("Failed to kill PID %d: %v", pid, err)}
		}

		return killProcessMsg{success: true, error: fmt.Sprintf("Killed %s (PID %d)", processName, pid)}
	}
}

func (m model) View() string {
	header := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("86")).
		Width(m.width).
		Align(lipgloss.Left).
		Render("🔍 Portmon - Live Port Monitor")

	baseInfo := fmt.Sprintf("Last updated: %s | Press 'q' to quit | Press 'enter' to kill selected process | User processes shown first",
		m.lastUpdate.Format("15:04:05"))

	// Add status message if present
	infoText := baseInfo
	if m.statusMsg != "" {
		infoText = fmt.Sprintf("%s | %s", baseInfo, m.statusMsg)
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

	// Try netstat first
	cmd := exec.Command("netstat", "-tulpn")
	output, err := cmd.Output()
	if err == nil {
		ports = parseNetstatOutput(string(output))
	}

	// If netstat fails or returns no results, try lsof
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

	// Regex to parse netstat output
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

			// Try to get user info
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

				// Get user from field 2
				if len(fields) > 2 {
					port.User = fields[2]
				}

				// Extract port and address from field 8
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
	// Get current user
	currentUser := os.Getenv("USER")
	if currentUser == "" {
		currentUser = os.Getenv("LOGNAME")
	}

	// Check if the process is owned by the current user
	if port.User == currentUser {
		// Additional checks for commonly monitored development processes
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

		// Check for common development ports
		if port.Port != "" {
			portNum, err := strconv.Atoi(port.Port)
			if err == nil {
				// Common development/user ports
				userPorts := []int{3000, 3001, 3002, 3003, 4000, 5000, 5001, 5173, 8000, 8080, 8081, 8888, 9000}
				for _, userPort := range userPorts {
					if portNum == userPort {
						return true
					}
				}

				// Development port ranges
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

	// Check for system processes that should be deprioritized
	systemUsers := []string{"root", "daemon", "nobody", "www-data", "nginx", "apache", "mysql", "postgres", "systemd+"}
	for _, sysUser := range systemUsers {
		if port.User == sysUser {
			return false
		}
	}

	// If it's the current user but not a recognized dev process, still prioritize it
	return port.User == currentUser
}

func cleanProcessName(process string) string {
	// Handle common process name patterns
	if process == "unknown" {
		return "unknown"
	}

	// Remove common prefixes/suffixes to make names clearer
	cleanName := process

	// Handle some common cases
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

	return cleanName
}

func cleanAddress(address string) string {
	if address == "" {
		return ""
	}

	// Simplify localhost addresses
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
