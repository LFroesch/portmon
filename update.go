package main

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.resizeTable()
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)

	case tickMsg:
		m.lastUpdate = time.Time(msg)
		return m, tea.Batch(
			m.tickCmd(),
			m.updatePorts(),
			m.collectStats(),
		)

	case updatePortsMsg:
		m.ports = []Port(msg)
		m.buildTableRows()
		return m, nil

	case statsMsg:
		m.stats = SystemStats(msg)
		m.cpuSpark.Add(m.stats.CPUPercent)
		m.memSpark.Add(m.stats.MemPercent)
		m.swapSpark.Add(m.stats.SwapPercent)
		m.netRxSpark.Add(m.stats.NetRxRate)
		m.netTxSpark.Add(m.stats.NetTxRate)
		if cpu, err := readCPUSample(); err == nil {
			m.prevCPU = cpu
		}
		if net, err := readNetSample(); err == nil {
			m.prevNet = net
		}
		return m, nil

	case killProcessMsg:
		if msg.success {
			m.statusMsg = msg.error
		} else {
			m.statusMsg = "Error: " + msg.error
		}
		return m, m.updatePorts()

	case statusUpdateMsg:
		m.statusMsg = msg.message
		return m, nil
	}

	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

func (m *model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	if m.tab == TabPorts && m.filterInput && key != "ctrl+c" {
		return m.handlePortsKey(msg)
	}

	switch key {
	case "ctrl+c":
		return m, tea.Quit
	case "tab":
		m.tab = (m.tab + 1) % Tab(len(tabNames))
		return m, nil
	case "1":
		m.tab = TabPorts
		return m, nil
	case "2":
		m.tab = TabStats
		return m, nil
	}

	switch m.tab {
	case TabPorts:
		return m.handlePortsKey(msg)
	case TabStats:
		return m.handleStatsKey(msg)
	}

	return m, nil
}

func (m *model) handlePortsKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.showHelp {
		if msg.String() == "q" || msg.String() == "esc" || msg.String() == "?" {
			m.showHelp = false
		}
		return m, nil
	}

	if m.labelEditor {
		switch msg.String() {
		case "esc":
			m.labelEditor = false
			return m, nil
		case "enter":
			if err := m.updatePortLabel(m.labelEditPort, m.labelInput); err != nil {
				m.statusMsg = "Error: " + err.Error()
				return m, nil
			}
			m.labelEditor = false
			m.buildTableRows()
			if strings.TrimSpace(m.labelInput) == "" {
				m.statusMsg = fmt.Sprintf("Cleared custom label for port %s", m.labelEditPort)
			} else {
				m.statusMsg = fmt.Sprintf("Saved label for port %s", m.labelEditPort)
			}
			return m, nil
		case "backspace":
			runes := []rune(m.labelInput)
			if len(runes) > 0 {
				m.labelInput = string(runes[:len(runes)-1])
			}
			return m, nil
		case "ctrl+u":
			m.labelInput = ""
			return m, nil
		}
		if len(msg.Runes) > 0 && !msg.Alt {
			m.labelInput += string(msg.Runes)
		}
		return m, nil
	}

	if m.showConfirmation {
		switch msg.String() {
		case "y", "Y":
			m.showConfirmation = false
			return m, m.killProcess(m.confirmPID, m.confirmProcess, m.confirmPort)
		case "n", "N", "esc":
			m.showConfirmation = false
			m.statusMsg = "Kill cancelled"
		}
		return m, nil
	}

	if m.filterInput {
		switch msg.String() {
		case "esc":
			m.filterInput = false
			return m, nil
		case "enter":
			m.filterInput = false
			return m, nil
		case "backspace":
			runes := []rune(m.filterQuery)
			if len(runes) > 0 {
				m.filterQuery = string(runes[:len(runes)-1])
				m.buildTableRows()
			}
			return m, nil
		}
		if len(msg.Runes) > 0 && !msg.Alt {
			m.filterQuery += string(msg.Runes)
			m.buildTableRows()
		}
		return m, nil
	}

	switch msg.String() {
	case "q":
		return m, tea.Quit
	case "?":
		m.showHelp = true
	case "e":
		details, ok := m.selectedPortDetails()
		if !ok {
			m.statusMsg = "No port selected"
			return m, nil
		}
		m.labelEditor = true
		m.labelEditPort = details.Port.Port
		m.labelInput = details.Mapping.CustomName
		if m.labelInput == "" && details.HasBuiltinMapping {
			m.labelInput = details.Mapping.CustomName
		}
		return m, nil
	case "/":
		m.filterInput = true
		return m, nil
	case "r":
		return m, tea.Batch(
			m.updatePorts(),
			func() tea.Msg { return statusUpdateMsg{message: "Refreshed"} },
		)
	case "x":
		m.portConfig = loadPortConfig(m.configFile)
		return m, tea.Batch(
			m.updatePorts(),
			func() tea.Msg { return statusUpdateMsg{message: "Config reloaded"} },
		)
	case "c":
		m.statusMsg = fmt.Sprintf("Config: %s", m.configFile)
	case "esc":
		if m.filterQuery != "" {
			m.filterQuery = ""
			m.buildTableRows()
		}
	case "enter":
		if details, ok := m.selectedPortDetails(); ok {
			if details.Port.PID > 0 {
				m.showConfirmation = true
				m.confirmPID = details.Port.PID
				m.confirmProcess = details.DisplayName
				m.confirmPort = details.Port.Port
				return m, nil
			}
		}
		m.statusMsg = "No process selected"
	default:
		var cmd tea.Cmd
		m.table, cmd = m.table.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m *model) handleStatsKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q":
		return m, tea.Quit
	case "j", "down":
		m.statsScroll++
	case "k", "up":
		if m.statsScroll > 0 {
			m.statsScroll--
		}
	case "g":
		m.statsScroll = 0
	}
	return m, nil
}
