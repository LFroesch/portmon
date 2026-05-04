package main

import (
	"path/filepath"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestFilterInputConsumesDigitKeysBeforeGlobalTabSwitch(t *testing.T) {
	m := model{
		tab:         TabPorts,
		filterInput: true,
		filterQuery: "",
	}

	next, _ := m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'1'}})
	updated := next.(*model)

	if updated.tab != TabPorts {
		t.Fatalf("expected to remain on ports tab, got %v", updated.tab)
	}
	if updated.filterQuery != "1" {
		t.Fatalf("expected filter query to capture digit, got %q", updated.filterQuery)
	}
}

func TestEditLabelKeyOpensEditorForSelectedPort(t *testing.T) {
	m := model{
		table: testTableModel(),
		portConfig: PortConfig{
			Mappings: []PortMapping{{Port: "80", CustomName: "HTTP"}},
		},
		ports: []Port{
			{Port: "80", PID: 1, Protocol: "TCP", Process: "nginx"},
		},
	}
	m.buildTableRows()
	m.table.SetCursor(1)

	next, _ := m.handlePortsKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	updated := next.(*model)

	if !updated.labelEditor {
		t.Fatal("expected label editor to open")
	}
	if updated.labelEditPort != "80" {
		t.Fatalf("expected label editor to target port 80, got %q", updated.labelEditPort)
	}
	if updated.labelInput != "HTTP" {
		t.Fatalf("expected existing label to prefill editor, got %q", updated.labelInput)
	}
}

func TestLabelEditorEnterSavesAndRebuildsRows(t *testing.T) {
	tmpDir := t.TempDir()
	m := model{
		table:         testTableModel(),
		configFile:    filepath.Join(tmpDir, "config.json"),
		labelEditor:   true,
		labelEditPort: "3000",
		labelInput:    "Frontend",
		portConfig:    PortConfig{RefreshInterval: DefaultRefreshInterval},
		ports: []Port{
			{Port: "3000", PID: 123, Protocol: "TCP", Process: "node"},
		},
	}
	m.buildTableRows()
	m.table.SetCursor(0)

	next, _ := m.handlePortsKey(tea.KeyMsg{Type: tea.KeyEnter})
	updated := next.(*model)

	if updated.labelEditor {
		t.Fatal("expected label editor to close after saving")
	}
	if len(updated.portConfig.Mappings) != 1 || updated.portConfig.Mappings[0].CustomName != "Frontend" {
		t.Fatalf("expected saved mapping, got %+v", updated.portConfig.Mappings)
	}
	if updated.statusMsg == "" {
		t.Fatal("expected save status message")
	}
}

func TestUpdatePortsMsgStoresWarning(t *testing.T) {
	m := model{
		table: testTableModel(),
	}

	next, _ := m.Update(updatePortsMsg{
		ports:   []Port{},
		warning: "Port scan unavailable: netstat not found",
	})
	updated := next.(model)

	if updated.portScanWarning == "" {
		t.Fatal("expected port scan warning to be stored")
	}
}

func TestStatsMsgUnsupportedDoesNotPopulateSparklines(t *testing.T) {
	m := model{
		cpuSpark:   NewSparkline(10),
		memSpark:   NewSparkline(10),
		swapSpark:  NewSparkline(10),
		netRxSpark: NewSparkline(10),
		netTxSpark: NewSparkline(10),
	}

	next, _ := m.Update(statsMsg(SystemStats{
		Supported: false,
		Warning:   "Stats tab is unavailable on macOS. Port scanning still works.",
	}))
	updated := next.(model)

	if updated.stats.Supported {
		t.Fatal("expected stats to be marked unsupported")
	}
	if len(updated.cpuSpark.values) != 0 || len(updated.memSpark.values) != 0 || len(updated.netRxSpark.values) != 0 {
		t.Fatal("expected unsupported stats update to avoid polluting spark history")
	}
}
