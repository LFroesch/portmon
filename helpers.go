package main

import (
	"encoding/json"
	"fmt"
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

var builtinPortMappings = map[string]PortMapping{
	"22":  {Port: "22", CustomName: "SSH", Description: "Secure Shell"},
	"25":  {Port: "25", CustomName: "SMTP", Description: "Mail transfer"},
	"53":  {Port: "53", CustomName: "DNS", Description: "Domain name service"},
	"80":  {Port: "80", CustomName: "HTTP", Description: "Web server"},
	"110": {Port: "110", CustomName: "POP3", Description: "Post Office Protocol"},
	"123": {Port: "123", CustomName: "NTP", Description: "Network time"},
	"143": {Port: "143", CustomName: "IMAP", Description: "Mail access"},
	"443": {Port: "443", CustomName: "HTTPS", Description: "Secure web server"},
	"465": {Port: "465", CustomName: "SMTPS", Description: "Secure mail transfer"},
	"587": {Port: "587", CustomName: "SMTP Submit", Description: "Mail submission"},
	"631": {Port: "631", CustomName: "IPP", Description: "Printing service"},
	"993": {Port: "993", CustomName: "IMAPS", Description: "Secure mail access"},
	"995": {Port: "995", CustomName: "POP3S", Description: "Secure POP3"},
}

// --- Config ---

func loadPortConfig(configFile string) PortConfig {
	var config PortConfig
	data, err := os.ReadFile(configFile)
	if err != nil {
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
		configDir := filepath.Dir(configFile)
		if err := os.MkdirAll(configDir, 0755); err == nil {
			configData, err := json.MarshalIndent(defaultConfig, "", "  ")
			if err == nil {
				os.WriteFile(configFile, configData, 0644)
			}
		}
		return defaultConfig
	}
	if err := json.Unmarshal(data, &config); err != nil {
		config = PortConfig{RefreshInterval: DefaultRefreshInterval}
	}
	if config.RefreshInterval <= 0 {
		config.RefreshInterval = DefaultRefreshInterval
	}
	return config
}

func savePortConfig(configFile string, config PortConfig) error {
	configDir := filepath.Dir(configFile)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	tmpFile, err := os.CreateTemp(configDir, "config-*.json")
	if err != nil {
		return err
	}
	tmpName := tmpFile.Name()
	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Chmod(tmpName, 0644); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, configFile); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

// --- Table helpers ---

func (m *model) getCustomName(port string) (string, string, bool, string) {
	for _, mapping := range m.portConfig.Mappings {
		if mapping.Port == port {
			return mapping.CustomName, mapping.Description, mapping.Hidden, mapping.Link
		}
	}
	if mapping, ok := builtinPortMappings[port]; ok {
		return mapping.CustomName, mapping.Description, mapping.Hidden, mapping.Link
	}
	return "", "", false, ""
}

func (m *model) resizeTable() {
	tableHeight := m.height - TableHeightPad
	if tableHeight < MinTableHeight {
		tableHeight = MinTableHeight
	}

	availableWidth := m.width - AvailableWidthPad
	portW, protoW, pidW, cpuW, memW, userW, statusW, addrW := 8, 6, 8, 6, 6, 10, 10, 20
	processW := availableWidth - portW - protoW - pidW - cpuW - memW - userW - statusW - addrW
	if processW < MinProcessWidth {
		processW = MinProcessWidth
	}
	if addrW > availableWidth/3 {
		addrW = availableWidth / 3
	}

	m.table.SetColumns([]table.Column{
		{Title: "Port", Width: portW},
		{Title: "Proto", Width: protoW},
		{Title: "Process", Width: processW},
		{Title: "PID", Width: pidW},
		{Title: "CPU%", Width: cpuW},
		{Title: "MEM%", Width: memW},
		{Title: "User", Width: userW},
		{Title: "Address", Width: addrW},
		{Title: "Status", Width: statusW},
	})
	m.table.SetHeight(tableHeight)
}

func (m *model) buildTableRows() {
	var customPorts, systemPorts []Port
	prevPort, hasPrev := m.selectedPort()

	customPortSet := make(map[string]bool)
	for _, mapping := range m.portConfig.Mappings {
		if !mapping.Hidden {
			customPortSet[mapping.Port] = true
		}
	}

	var pids []int
	for _, port := range m.ports {
		if port.PID > 0 {
			pids = append(pids, port.PID)
		}
	}
	procResources := getProcessResources(pids)

	for _, port := range m.ports {
		if _, _, hidden, _ := m.getCustomName(port.Port); hidden {
			continue
		}
		if !m.matchesFilter(port) {
			continue
		}

		if customPortSet[port.Port] {
			customPorts = append(customPorts, port)
		} else {
			systemPorts = append(systemPorts, port)
		}
	}

	sortByPort := func(ports []Port) {
		sort.Slice(ports, func(i, j int) bool {
			pi, _ := strconv.Atoi(ports[i].Port)
			pj, _ := strconv.Atoi(ports[j].Port)
			return pi < pj
		})
	}
	sortByPort(customPorts)
	sortByPort(systemPorts)

	var rows []table.Row
	var meta []portRowMeta

	addSection := func(label string, ports []Port) {
		if len(ports) == 0 {
			return
		}
		if len(rows) > 0 {
			rows = append(rows, table.Row{"", "", "", "", "", "", "", "", ""})
			meta = append(meta, portRowMeta{kind: portRowSpacer})
		}
		rows = append(rows, table.Row{"", "", fmt.Sprintf("=== %s ===", label), "", "", "", "", "", ""})
		meta = append(meta, portRowMeta{kind: portRowSection})
		for _, p := range ports {
			name := cleanProcessName(p.Process)
			if customName, _, _, _ := m.getCustomName(p.Port); customName != "" {
				name = fmt.Sprintf("%s (%s)", customName, name)
			}
			cpuPct, memPct := "-", "-"
			if res, ok := procResources[p.PID]; ok {
				cpuPct = res.CPUPct
				memPct = res.MemPct
			}
			rows = append(rows, table.Row{
				p.Port, p.Protocol, name,
				strconv.Itoa(p.PID), cpuPct, memPct,
				p.User, cleanAddress(p.LocalAddr), p.Status,
			})
			meta = append(meta, portRowMeta{kind: portRowData, port: p})
		}
	}

	addSection("CUSTOM", customPorts)
	addSection("SYSTEM", systemPorts)

	m.portRows = meta
	m.table.SetRows(rows)
	m.restoreSelection(prevPort, hasPrev)
}

func (m model) matchesFilter(port Port) bool {
	query := strings.TrimSpace(strings.ToLower(m.filterQuery))
	if query == "" {
		return true
	}

	name, desc, _, link := m.getCustomName(port.Port)
	candidates := []string{
		port.Port,
		port.Protocol,
		port.Process,
		cleanProcessName(port.Process),
		port.User,
		port.LocalAddr,
		port.Status,
		name,
		desc,
		link,
	}
	for _, candidate := range candidates {
		if strings.Contains(strings.ToLower(candidate), query) {
			return true
		}
	}
	if port.PID > 0 && strings.Contains(strconv.Itoa(port.PID), query) {
		return true
	}
	return false
}

func (m model) countPortSections() (custom, system int) {
	customPortSet := make(map[string]bool)
	for _, mapping := range m.portConfig.Mappings {
		if !mapping.Hidden {
			customPortSet[mapping.Port] = true
		}
	}
	for _, port := range m.ports {
		if _, _, hidden, _ := m.getCustomName(port.Port); hidden {
			continue
		}
		if customPortSet[port.Port] {
			custom++
		} else {
			system++
		}
	}
	return
}

type SelectedPortDetails struct {
	Port              Port
	Row               table.Row
	Mapping           PortMapping
	DisplayName       string
	DisplayProcess    string
	HasCustomMapping  bool
	HasBuiltinMapping bool
}

func (m model) selectedPort() (Port, bool) {
	cursor := m.table.Cursor()
	if cursor < 0 || cursor >= len(m.portRows) {
		return Port{}, false
	}
	if m.portRows[cursor].kind != portRowData {
		return Port{}, false
	}
	return m.portRows[cursor].port, true
}

func (m model) selectedPortDetails() (SelectedPortDetails, bool) {
	port, ok := m.selectedPort()
	if !ok {
		return SelectedPortDetails{}, false
	}

	details := SelectedPortDetails{
		Port:           port,
		DisplayProcess: cleanProcessName(port.Process),
	}
	if rows := m.table.Rows(); m.table.Cursor() >= 0 && m.table.Cursor() < len(rows) {
		row := rows[m.table.Cursor()]
		details.Row = row
		if len(row) > 2 {
			details.DisplayName = row[2]
		}
	}

	for _, mapping := range m.portConfig.Mappings {
		if mapping.Port == port.Port {
			details.Mapping = mapping
			details.HasCustomMapping = true
			return details, true
		}
	}
	if mapping, ok := builtinPortMappings[port.Port]; ok {
		details.Mapping = mapping
		details.HasBuiltinMapping = true
	}
	return details, true
}

func (m *model) restoreSelection(prev Port, hasPrev bool) {
	if len(m.portRows) == 0 {
		m.table.SetCursor(0)
		return
	}

	if hasPrev {
		for i, row := range m.portRows {
			if row.kind != portRowData {
				continue
			}
			if row.port.Port == prev.Port && row.port.PID == prev.PID && row.port.Protocol == prev.Protocol {
				m.table.SetCursor(i)
				return
			}
		}
	}

	cursor := m.table.Cursor()
	if cursor < 0 {
		cursor = 0
	}
	if cursor >= len(m.portRows) {
		cursor = len(m.portRows) - 1
	}
	for i := cursor; i < len(m.portRows); i++ {
		if m.portRows[i].kind == portRowData {
			m.table.SetCursor(i)
			return
		}
	}
	for i := cursor - 1; i >= 0; i-- {
		if m.portRows[i].kind == portRowData {
			m.table.SetCursor(i)
			return
		}
	}
	m.table.SetCursor(0)
}

func (m *model) updatePortLabel(port, label string) error {
	label = strings.TrimSpace(label)

	index := -1
	for i, mapping := range m.portConfig.Mappings {
		if mapping.Port == port {
			index = i
			break
		}
	}

	if index >= 0 {
		m.portConfig.Mappings[index].CustomName = label
		mapping := m.portConfig.Mappings[index]
		if mapping.CustomName == "" && mapping.Description == "" && mapping.Link == "" && !mapping.Hidden {
			m.portConfig.Mappings = append(m.portConfig.Mappings[:index], m.portConfig.Mappings[index+1:]...)
		}
	} else if label != "" {
		m.portConfig.Mappings = append(m.portConfig.Mappings, PortMapping{Port: port, CustomName: label})
	}

	sort.SliceStable(m.portConfig.Mappings, func(i, j int) bool {
		pi, errI := strconv.Atoi(m.portConfig.Mappings[i].Port)
		pj, errJ := strconv.Atoi(m.portConfig.Mappings[j].Port)
		if errI == nil && errJ == nil {
			return pi < pj
		}
		return m.portConfig.Mappings[i].Port < m.portConfig.Mappings[j].Port
	})

	return savePortConfig(m.configFile, m.portConfig)
}

// --- Commands ---

func (m model) updatePorts() tea.Cmd {
	return func() tea.Msg {
		return updatePortsMsg(getPorts())
	}
}

func (m model) collectStats() tea.Cmd {
	prevCPU := m.prevCPU
	prevNet := m.prevNet
	interval := float64(m.portConfig.RefreshInterval)

	return func() tea.Msg {
		var s SystemStats

		currCPU, err := readCPUSample()
		if err == nil {
			s.CPUPercent = calcCPUPercent(prevCPU, currCPU)
		}

		mem, err := readMemInfo()
		if err == nil {
			s.MemTotal = mem.total
			s.MemUsed = mem.total - mem.available
			if mem.total > 0 {
				s.MemPercent = float64(s.MemUsed) / float64(mem.total) * 100
			}
			s.SwapTotal = mem.swapTotal
			s.SwapUsed = mem.swapTotal - mem.swapFree
			if mem.swapTotal > 0 {
				s.SwapPercent = float64(s.SwapUsed) / float64(mem.swapTotal) * 100
			}
		}

		currNet, err := readNetSample()
		if err == nil && interval > 0 {
			s.NetRxBytes = currNet.rxBytes
			s.NetTxBytes = currNet.txBytes
			s.NetRxRate = float64(currNet.rxBytes-prevNet.rxBytes) / interval
			s.NetTxRate = float64(currNet.txBytes-prevNet.txBytes) / interval
		}

		s.LoadAvg1, s.LoadAvg5, s.LoadAvg15, _ = readLoadAvg()
		s.Uptime, _ = readUptime()
		s.Disks = readDiskStats()
		s.Hostname = readHostname()
		s.Kernel = readKernelVersion()
		s.TopProcs = readTopProcs(5)

		return statsMsg(s)
	}
}

// --- Process management ---

func (m model) killProcess(pid int, processName, port string) tea.Cmd {
	return func() tea.Msg {
		if pid <= 0 {
			return killProcessMsg{success: false, error: "Invalid PID"}
		}
		process, err := os.FindProcess(pid)
		if err != nil {
			return killProcessMsg{success: false, error: fmt.Sprintf("Process %d not found: %v", pid, err)}
		}
		if err := process.Signal(syscall.SIGTERM); err != nil {
			return killProcessMsg{success: false, error: fmt.Sprintf("SIGTERM failed for PID %d: %v", pid, err)}
		}

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
					if err := process.Signal(syscall.Signal(0)); err != nil {
						terminated <- true
						return
					}
				}
			}
		}()

		if <-terminated {
			return killProcessMsg{
				success: true,
				error:   fmt.Sprintf("Terminated %s (PID %d) on port %s", processName, pid, port),
			}
		}

		if err := process.Kill(); err != nil {
			return killProcessMsg{success: false, error: fmt.Sprintf("Kill failed PID %d: %v", pid, err)}
		}
		return killProcessMsg{
			success: true,
			error:   fmt.Sprintf("Force killed %s (PID %d) on port %s", processName, pid, port),
		}
	}
}

// --- Port scanning ---

func getPorts() []Port {
	var ports []Port

	cmd := exec.Command("netstat", "-tulpn")
	output, err := cmd.Output()
	if err == nil {
		ports = parseNetstatOutput(string(output))
		if len(ports) > 0 {
			return ports
		}
	}

	cmd = exec.Command("lsof", "-i", "-P", "-n")
	output, err = cmd.Output()
	if err == nil {
		ports = parseLsofOutput(string(output))
	}
	return ports
}

func parseNetstatOutput(output string) []Port {
	var ports []Port
	re := regexp.MustCompile(`(\w+)\s+\d+\s+\d+\s+([^\s]+):(\d+)\s+[^\s]+\s+(\w+)(?:\s+(\d+)/([^\s]+))?`)
	for _, line := range strings.Split(output, "\n") {
		matches := re.FindStringSubmatch(line)
		if len(matches) >= 6 {
			port := Port{
				Port:      matches[3],
				Protocol:  strings.ToUpper(matches[1]),
				Status:    matches[4],
				LocalAddr: matches[2] + ":" + matches[3],
				Process:   "unknown",
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
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}
		protoIdx := -1
		for i, field := range fields {
			if field == "TCP" || field == "UDP" {
				protoIdx = i
				break
			}
		}
		if protoIdx == -1 || protoIdx+1 >= len(fields) {
			continue
		}

		port := Port{
			Process:  fields[0],
			Protocol: fields[protoIdx],
			Status:   strings.Trim(fields[len(fields)-1], "()"),
			User:     "unknown",
		}
		if port.Protocol == "UDP" {
			port.Status = "ACTIVE"
		}
		if pid, err := strconv.Atoi(fields[1]); err == nil {
			port.PID = pid
		}
		if len(fields) > 2 {
			port.User = fields[2]
		}

		nameField := fields[protoIdx+1]
		port.LocalAddr = nameField
		if idx := strings.LastIndex(nameField, ":"); idx != -1 {
			port.Port = strings.TrimRight(nameField[idx+1:], ")")
		}
		if port.Port == "" {
			continue
		}
		ports = append(ports, port)
	}
	return ports
}

func getUserFromPID(pid int) string {
	cmd := exec.Command("ps", "-o", "user=", "-p", strconv.Itoa(pid))
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	if user := strings.TrimSpace(string(output)); user != "" {
		return user
	}
	return "unknown"
}

func cleanProcessName(process string) string {
	if process == "unknown" {
		return "unknown"
	}
	known := map[string]string{
		"node": "node", "python": "python", "java": "java",
		"nginx": "nginx", "apache": "apache", "mysql": "mysql",
		"postgres": "postgres", "redis": "redis", "docker": "docker", "ssh": "ssh",
	}
	for key, val := range known {
		if strings.Contains(process, key) {
			return val
		}
	}
	return process
}

func cleanAddress(address string) string {
	if address == "" {
		return ""
	}
	r := strings.NewReplacer(
		"127.0.0.1", "localhost",
		"::1", "localhost",
		"0.0.0.0", "*",
		"::", "*",
	)
	return r.Replace(address)
}

// --- Table styling ---

func styledTable(t table.Model) table.Model {
	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(true).
		Foreground(colorAccent).
		Align(lipgloss.Left).
		PaddingLeft(0)
	s.Selected = s.Selected.
		Foreground(colorText).
		Background(lipgloss.Color("#3A3A5C")).
		Bold(true).
		Align(lipgloss.Left).
		PaddingLeft(0)
	s.Cell = s.Cell.
		Align(lipgloss.Left).
		PaddingLeft(0)
	t.SetStyles(s)
	return t
}
