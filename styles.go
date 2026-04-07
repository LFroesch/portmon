package main

import "github.com/charmbracelet/lipgloss"

var (
	// Colors — consistent palette
	colorPrimary = lipgloss.Color("#5AF78E") // green
	colorAccent  = lipgloss.Color("#57C7FF") // blue
	colorWarn    = lipgloss.Color("#FF6AC1") // pink
	colorError   = lipgloss.Color("#FF5C57") // red
	colorDim     = lipgloss.Color("#606060")
	colorText    = lipgloss.Color("#EEEEEE")
	colorBg      = lipgloss.Color("#1A1A2E")

	// Header
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorPrimary)

	// Tabs
	tabStyle = lipgloss.NewStyle().
			Padding(0, 2).
			Foreground(colorDim)

	activeTabStyle = lipgloss.NewStyle().
			Padding(0, 2).
			Foreground(colorText).
			Background(colorPrimary).
			Bold(true)

	// Sections
	sectionStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorAccent)

	// Status bar
	keyStyle = lipgloss.NewStyle().
			Foreground(colorAccent).
			Bold(true)

	actionStyle = lipgloss.NewStyle().
			Foreground(colorPrimary)

	bulletStyle = lipgloss.NewStyle().
			Foreground(colorDim)

	// Stats
	barFilledStyle = lipgloss.NewStyle().
			Foreground(colorPrimary)

	barEmptyStyle = lipgloss.NewStyle().
			Foreground(colorDim)

	labelStyle = lipgloss.NewStyle().
			Foreground(colorText).
			Bold(true).
			Width(6)

	pctStyle = lipgloss.NewStyle().
			Foreground(colorPrimary).
			Width(6).
			Align(lipgloss.Right)

	sparkStyle = lipgloss.NewStyle().
			Foreground(colorAccent)

	dimTextStyle = lipgloss.NewStyle().
			Foreground(colorDim)

	errorTextStyle = lipgloss.NewStyle().
			Foreground(colorError)

	statusMsgStyle = lipgloss.NewStyle().
			Foreground(colorAccent)
)
