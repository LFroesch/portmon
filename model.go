package main

import (
	"runtime"
	"time"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
)

// --- Constants ---

const (
	DefaultRefreshInterval = 2
	EphemeralPortThreshold = 10000
	MinTableHeight         = 3
	MinProcessWidth        = 6
	TableHeightPad         = 7
	AvailableWidthPad      = 15
	SIGTERMTimeout         = 2 * time.Second
	SparklineHistory       = 60
)

// --- Tabs ---

type Tab int

const (
	TabPorts Tab = iota
	TabStats
)

var tabNames = []string{"Ports", "Stats"}

// --- Types ---

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
}

type PortConfig struct {
	Mappings        []PortMapping `json:"port_mappings"`
	RefreshInterval int           `json:"refresh_interval"`
}

type portRowKind int

const (
	portRowSpacer portRowKind = iota
	portRowSection
	portRowData
)

type portRowMeta struct {
	kind portRowKind
	port Port
}

type model struct {
	width  int
	height int
	tab    Tab

	table            table.Model
	ports            []Port
	portRows         []portRowMeta
	portConfig       PortConfig
	configFile       string
	lastUpdate       time.Time
	statusMsg        string
	portScanWarning  string
	showHelp         bool
	showConfirmation bool
	labelEditor      bool
	confirmPID       int
	confirmProcess   string
	confirmPort      string
	filterQuery      string
	filterInput      bool
	labelEditPort    string
	labelInput       string

	cpuSpark    *Sparkline
	memSpark    *Sparkline
	swapSpark   *Sparkline
	netRxSpark  *Sparkline
	netTxSpark  *Sparkline
	prevCPU     cpuSample
	prevNet     netSample
	stats       SystemStats
	statsScroll int
}

// --- Messages ---

type tickMsg time.Time
type updatePortsMsg struct {
	ports   []Port
	warning string
}
type killProcessMsg struct {
	success bool
	error   string
}
type statusUpdateMsg struct {
	message string
}
type statsMsg SystemStats

func statsSupportMessage() string {
	switch runtime.GOOS {
	case "linux":
		return ""
	case "darwin":
		return "Stats tab is unavailable on macOS. Port scanning still works."
	default:
		return "Stats tab requires Linux with a /proc filesystem."
	}
}

// --- Init ---

func (m model) Init() tea.Cmd {
	return tea.Batch(
		m.tickCmd(),
		m.updatePorts(),
		m.collectStats(),
	)
}

func (m model) tickCmd() tea.Cmd {
	interval := time.Duration(m.portConfig.RefreshInterval) * time.Second
	return tea.Tick(interval, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}
