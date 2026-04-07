package main

import (
	"fmt"
	"strconv"
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

	switch msg.String() {
	case "q":
		return m, tea.Quit
	case "?":
		m.showHelp = true
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
	case "o":
		if len(m.ports) > 0 {
			selected := m.table.SelectedRow()
			if len(selected) > 0 && selected[0] != "" && !strings.Contains(selected[2], "===") {
				port := selected[0]
				if _, _, _, link := m.getCustomName(port); link != "" {
					return m, m.openLink(link, port)
				}
				return m, m.openLink(fmt.Sprintf("http://localhost:%s", port), port)
			}
		}
	case "enter":
		if len(m.ports) > 0 {
			selected := m.table.SelectedRow()
			if len(selected) > 3 && selected[3] != "" && !strings.Contains(selected[2], "===") {
				pid, err := strconv.Atoi(selected[3])
				if err == nil && pid > 0 {
					m.showConfirmation = true
					m.confirmPID = pid
					m.confirmProcess = selected[2]
					m.confirmPort = selected[0]
				}
			}
		}
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
