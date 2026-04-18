package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/charmbracelet/bubbles/table"
)

func testTableModel() table.Model {
	return table.New(table.WithColumns([]table.Column{
		{Title: "Port", Width: 8},
		{Title: "Proto", Width: 6},
		{Title: "Process", Width: 20},
		{Title: "PID", Width: 8},
		{Title: "CPU%", Width: 6},
		{Title: "MEM%", Width: 6},
		{Title: "User", Width: 10},
		{Title: "Address", Width: 20},
		{Title: "Status", Width: 10},
	}))
}

func TestGetCustomNamePrefersUserMappingOverBuiltin(t *testing.T) {
	m := model{
		portConfig: PortConfig{
			Mappings: []PortMapping{
				{Port: "80", CustomName: "Local Override", Description: "custom"},
			},
		},
	}

	name, desc, hidden, link := m.getCustomName("80")
	if name != "Local Override" {
		t.Fatalf("expected user mapping to win, got %q", name)
	}
	if desc != "custom" || hidden || link != "" {
		t.Fatalf("unexpected mapping values: desc=%q hidden=%v link=%q", desc, hidden, link)
	}
}

func TestGetCustomNameFallsBackToBuiltinMapping(t *testing.T) {
	m := model{}

	name, _, _, _ := m.getCustomName("443")
	if name != "HTTPS" {
		t.Fatalf("expected builtin HTTPS label, got %q", name)
	}
}

func TestMatchesFilterUsesBuiltinAndUserMetadata(t *testing.T) {
	m := model{
		filterQuery: "frontend",
		portConfig: PortConfig{
			Mappings: []PortMapping{
				{Port: "3000", CustomName: "React App", Description: "frontend dev server"},
			},
		},
	}

	if !m.matchesFilter(Port{Port: "3000", Process: "node", Protocol: "TCP"}) {
		t.Fatal("expected filter to match custom description")
	}

	m.filterQuery = "https"
	if !m.matchesFilter(Port{Port: "443", Process: "nginx", Protocol: "TCP"}) {
		t.Fatal("expected filter to match builtin label")
	}
}

func TestParseLsofOutputIncludesTCPAndUDP(t *testing.T) {
	output := `COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
nginx    123 root    6u  IPv4  12345      0t0  TCP *:80 (LISTEN)
dnsmasq  456 nobody  4u  IPv4  67890      0t0  UDP *:53
`

	ports := parseLsofOutput(output)
	if len(ports) != 2 {
		t.Fatalf("expected 2 ports, got %d", len(ports))
	}

	if ports[0].Protocol != "TCP" || ports[0].Port != "80" || ports[0].Status != "LISTEN" {
		t.Fatalf("unexpected TCP parse result: %+v", ports[0])
	}

	if ports[1].Protocol != "UDP" || ports[1].Port != "53" || ports[1].Status != "ACTIVE" {
		t.Fatalf("unexpected UDP parse result: %+v", ports[1])
	}
}

func TestBuildTableRowsRestoresSelectionToMatchingPort(t *testing.T) {
	m := model{
		table: testTableModel(),
		portConfig: PortConfig{
			Mappings: []PortMapping{{Port: "3000", CustomName: "App"}},
		},
		ports: []Port{
			{Port: "3000", PID: 101, Protocol: "TCP", Process: "node"},
			{Port: "8080", PID: 202, Protocol: "TCP", Process: "go"},
		},
	}

	m.buildTableRows()
	m.table.SetCursor(1)

	m.ports = []Port{
		{Port: "3000", PID: 101, Protocol: "TCP", Process: "node"},
		{Port: "8080", PID: 202, Protocol: "TCP", Process: "go"},
		{Port: "9090", PID: 303, Protocol: "TCP", Process: "python"},
	}

	m.buildTableRows()

	selected, ok := m.selectedPort()
	if !ok {
		t.Fatal("expected a selected port after rebuilding rows")
	}
	if selected.Port != "3000" || selected.PID != 101 {
		t.Fatalf("expected selection to stay on port 3000, got %+v", selected)
	}
}

func TestBuildTableRowsSkipsSectionHeadersWhenSelectionDisappears(t *testing.T) {
	m := model{
		table: testTableModel(),
		ports: []Port{
			{Port: "80", PID: 1, Protocol: "TCP", Process: "nginx"},
		},
	}

	m.buildTableRows()
	m.table.SetCursor(0)

	m.ports = []Port{
		{Port: "443", PID: 2, Protocol: "TCP", Process: "nginx"},
	}

	m.buildTableRows()

	selected, ok := m.selectedPort()
	if !ok {
		t.Fatal("expected cursor to move to a real port row")
	}
	if selected.Port != "443" {
		t.Fatalf("expected cursor to land on port 443, got %+v", selected)
	}
}

func TestBuildTableRowsClampsCursorWhenFilteredRowsShrink(t *testing.T) {
	m := model{
		table: testTableModel(),
		portConfig: PortConfig{
			Mappings: []PortMapping{
				{Port: "80", CustomName: "HTTP"},
			},
		},
		ports: []Port{
			{Port: "80", PID: 1, Protocol: "TCP", Process: "nginx"},
			{Port: "3000", PID: 2, Protocol: "TCP", Process: "node"},
			{Port: "5000", PID: 3, Protocol: "TCP", Process: "python"},
			{Port: "5432", PID: 4, Protocol: "TCP", Process: "postgres"},
		},
	}

	m.buildTableRows()
	m.table.SetCursor(5)
	m.filterQuery = "5"

	m.buildTableRows()

	selected, ok := m.selectedPort()
	if !ok {
		t.Fatal("expected cursor to land on a filtered port row")
	}
	if selected.Port != "5000" && selected.Port != "5432" {
		t.Fatalf("expected selection to stay within filtered ports, got %+v", selected)
	}
	if cursor := m.table.Cursor(); cursor < 0 || cursor >= len(m.portRows) {
		t.Fatalf("expected clamped cursor within %d rows, got %d", len(m.portRows), cursor)
	}
}

func TestUpdatePortLabelCreatesAndClearsCustomMapping(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.json")

	m := model{
		configFile: configFile,
		portConfig: PortConfig{RefreshInterval: DefaultRefreshInterval},
	}

	if err := m.updatePortLabel("3000", "Frontend"); err != nil {
		t.Fatalf("save label failed: %v", err)
	}
	if len(m.portConfig.Mappings) != 1 || m.portConfig.Mappings[0].CustomName != "Frontend" {
		t.Fatalf("expected saved mapping, got %+v", m.portConfig.Mappings)
	}
	data, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatalf("read config failed: %v", err)
	}
	if string(data) == "" {
		t.Fatal("expected config file to be written")
	}

	if err := m.updatePortLabel("3000", ""); err != nil {
		t.Fatalf("clear label failed: %v", err)
	}
	if len(m.portConfig.Mappings) != 0 {
		t.Fatalf("expected mapping removal after clearing, got %+v", m.portConfig.Mappings)
	}
}
