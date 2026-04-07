package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

func (m model) View() string {
	if m.width == 0 || m.height == 0 {
		return "loading..."
	}

	header := m.renderHeader()

	var content string
	switch m.tab {
	case TabPorts:
		if m.showHelp {
			content = m.renderHelp()
		} else if m.showConfirmation {
			content = m.renderConfirmation()
		} else {
			content = m.table.View()
		}
	case TabStats:
		contentH := m.height - 4
		if contentH < 5 {
			contentH = 5
		}
		content = m.renderStats(contentH)
	}

	status := m.renderStatus()

	return lipgloss.JoinVertical(lipgloss.Left, header, "", content, "", status)
}

func (m model) renderHeader() string {
	title := titleStyle.Render("Portmon")

	var tabs []string
	for i, name := range tabNames {
		if Tab(i) == m.tab {
			tabs = append(tabs, activeTabStyle.Render(name))
		} else {
			tabs = append(tabs, tabStyle.Render(name))
		}
	}
	tabBar := lipgloss.JoinHorizontal(lipgloss.Bottom, tabs...)

	return lipgloss.JoinHorizontal(lipgloss.Bottom,
		title,
		"  ",
		tabBar,
		"  ",
		dimTextStyle.Render(fmt.Sprintf("updated %s", m.lastUpdate.Format("15:04:05"))),
	)
}

func (m model) renderStatus() string {
	var parts []string

	switch m.tab {
	case TabPorts:
		keys := []struct{ key, action string }{
			{"?", "help"}, {"q", "quit"}, {"enter", "kill"},
			{"o", "open"}, {"r", "refresh"}, {"tab", "stats"},
		}
		for i, k := range keys {
			if i > 0 {
				parts = append(parts, bulletStyle.Render(" · "))
			}
			parts = append(parts, keyStyle.Render(k.key), " ", actionStyle.Render(k.action))
		}
	case TabStats:
		parts = append(parts,
			keyStyle.Render("j/k"), " ", actionStyle.Render("scroll"),
			bulletStyle.Render(" · "),
			keyStyle.Render("tab"), " ", actionStyle.Render("ports"),
			bulletStyle.Render(" · "),
			keyStyle.Render("q"), " ", actionStyle.Render("quit"),
		)
	}

	bar := strings.Join(parts, "")
	if m.statusMsg != "" {
		bar += "  " + statusMsgStyle.Render("> "+m.statusMsg)
	}
	return bar
}

func (m *model) renderStats(maxH int) string {
	w := m.width
	panelW := w / 2

	panel := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colorDim).
		Padding(0, 1).
		Width(panelW)

	fullPanel := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colorDim).
		Padding(0, 1).
		Width(w)

	barW := 20

	// Resources panel
	var left []string
	left = append(left, sectionStyle.Render("Resources"), "")

	addResource := func(label string, pct float64, spark *Sparkline, detail string) {
		left = append(left, fmt.Sprintf("%s %s %s",
			labelStyle.Render(label), renderBar(pct, barW), pctStyle.Render(fmt.Sprintf("%4.0f%%", pct)),
		))
		if detail != "" {
			left = append(left, "      "+dimTextStyle.Render(detail))
		}
		if spark != nil {
			left = append(left, "      "+sparkStyle.Render(spark.Render(barW)))
		}
	}

	addResource("CPU ", m.stats.CPUPercent, m.cpuSpark, "")
	left = append(left, "")
	addResource("MEM ", m.stats.MemPercent, m.memSpark,
		fmt.Sprintf("%s / %s", formatBytes(m.stats.MemUsed), formatBytes(m.stats.MemTotal)))
	left = append(left, "")
	if m.stats.SwapTotal > 0 {
		addResource("SWAP", m.stats.SwapPercent, m.swapSpark,
			fmt.Sprintf("%s / %s", formatBytes(m.stats.SwapUsed), formatBytes(m.stats.SwapTotal)))
		left = append(left, "")
	}
	for _, d := range m.stats.Disks {
		addResource("DISK", d.Percent, nil,
			fmt.Sprintf("%s / %s  %s", formatBytes(d.Used), formatBytes(d.Total), d.Mount))
	}

	// Network + System panel
	var right []string
	right = append(right, sectionStyle.Render("Network"), "")

	right = append(right, fmt.Sprintf("  %s %s    %s %s",
		dimTextStyle.Render("rx"), actionStyle.Render(formatRate(m.stats.NetRxRate)),
		dimTextStyle.Render("tx"), actionStyle.Render(formatRate(m.stats.NetTxRate)),
	))
	right = append(right, "  "+sparkStyle.Render(m.netRxSpark.Render(barW/2))+" "+sparkStyle.Render(m.netTxSpark.Render(barW/2)))

	right = append(right, "", sectionStyle.Render("System"), "")

	info := func(label, val string) string {
		return fmt.Sprintf("  %s  %s", dimTextStyle.Render(fmt.Sprintf("%-8s", label)), actionStyle.Render(val))
	}
	if m.stats.Hostname != "" {
		right = append(right, info("host", m.stats.Hostname))
	}
	if m.stats.Kernel != "" {
		right = append(right, info("kernel", m.stats.Kernel))
	}
	right = append(right, info("uptime", formatDuration(m.stats.Uptime)))
	right = append(right, info("load", fmt.Sprintf("%.2f  %.2f  %.2f", m.stats.LoadAvg1, m.stats.LoadAvg5, m.stats.LoadAvg15)))

	customCount, systemCount := m.countPortSections()
	right = append(right, info("ports", fmt.Sprintf("%d custom, %d system", customCount, systemCount)))

	for len(left) < len(right) {
		left = append(left, "")
	}
	for len(right) < len(left) {
		right = append(right, "")
	}

	leftPanel := panel.Render(strings.Join(left, "\n"))
	rightPanel := panel.Render(strings.Join(right, "\n"))
	topRow := lipgloss.JoinHorizontal(lipgloss.Top, leftPanel, rightPanel)

	// Top processes panel
	var bottom []string
	bottom = append(bottom, sectionStyle.Render("Top Processes"), "")
	bottom = append(bottom, fmt.Sprintf("  %-8s %-7s %-7s %s",
		dimTextStyle.Render("PID"), dimTextStyle.Render("CPU%"),
		dimTextStyle.Render("MEM%"), dimTextStyle.Render("Name"),
	))
	for _, p := range m.stats.TopProcs {
		bottom = append(bottom, fmt.Sprintf("  %-8d %-7s %-7s %s",
			p.PID,
			pctStyle.Render(fmt.Sprintf("%.1f", p.CPUPct)),
			pctStyle.Render(fmt.Sprintf("%.1f", p.MemPct)),
			actionStyle.Render(p.Name),
		))
	}
	bottomPanel := fullPanel.Render(strings.Join(bottom, "\n"))

	full := lipgloss.JoinVertical(lipgloss.Left, topRow, bottomPanel)
	lines := strings.Split(full, "\n")

	maxScroll := len(lines) - maxH
	if maxScroll < 0 {
		maxScroll = 0
	}
	if m.statsScroll > maxScroll {
		m.statsScroll = maxScroll
	}

	start := m.statsScroll
	end := start + maxH
	if end > len(lines) {
		end = len(lines)
	}
	visible := lines[start:end]

	for len(visible) < maxH {
		visible = append(visible, "")
	}

	return strings.Join(visible, "\n")
}

func (m model) renderHelp() string {
	helpStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colorPrimary).
		Padding(1, 2).
		Width(m.width - 4)

	keys := []struct{ key, desc string }{
		{"↑/↓, j/k", "Navigate ports"},
		{"enter", "Kill selected process"},
		{"o", "Open port URL in browser"},
		{"r", "Refresh port list"},
		{"x", "Reload config file"},
		{"c", "Show config path"},
		{"tab/1/2", "Switch tabs"},
		{"?", "Toggle this help"},
		{"q", "Quit"},
	}

	var lines []string
	lines = append(lines, titleStyle.Render("Help"))
	lines = append(lines, "")
	for _, k := range keys {
		lines = append(lines, fmt.Sprintf("  %s  %s",
			keyStyle.Render(fmt.Sprintf("%-12s", k.key)),
			k.desc,
		))
	}
	lines = append(lines, "")
	lines = append(lines, dimTextStyle.Render(fmt.Sprintf("Refresh: %ds  Config: %s",
		m.portConfig.RefreshInterval, m.configFile)))

	return lipgloss.Place(m.width, m.height-4,
		lipgloss.Center, lipgloss.Center,
		helpStyle.Render(strings.Join(lines, "\n")))
}

func (m model) renderConfirmation() string {
	dialogStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colorError).
		Padding(1, 2).
		Width(50)

	text := fmt.Sprintf("%s\n\nProcess: %s\nPID:     %d\nPort:    %s\n\n%s to confirm, %s to cancel",
		errorTextStyle.Render("Kill process?"),
		m.confirmProcess, m.confirmPID, m.confirmPort,
		keyStyle.Render("Y"), keyStyle.Render("N"))

	return lipgloss.Place(m.width, m.height-4,
		lipgloss.Center, lipgloss.Center,
		dialogStyle.Render(text))
}

func formatDuration(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, mins)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, mins)
	}
	return fmt.Sprintf("%dm", mins)
}
