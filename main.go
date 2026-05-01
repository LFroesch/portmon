package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
)

var version = "dev"

func main() {
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "portmon — Live port monitor and system stats dashboard\n\n")
		fmt.Fprintf(os.Stderr, "Usage: portmon [flags]\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if *showVersion {
		fmt.Println("portmon " + version)
		os.Exit(0)
	}

	p := tea.NewProgram(initialModel(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		log.Fatal(err)
	}
}

func initialModel() model {
	configFile, err := configPath()
	if err != nil {
		log.Fatal("Could not determine config path: ", err)
	}

	columns := []table.Column{
		{Title: "Port", Width: 8},
		{Title: "Proto", Width: 6},
		{Title: "Process", Width: 20},
		{Title: "PID", Width: 8},
		{Title: "CPU%", Width: 6},
		{Title: "MEM%", Width: 6},
		{Title: "User", Width: 10},
		{Title: "Address", Width: 20},
		{Title: "Status", Width: 10},
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithFocused(true),
		table.WithHeight(10),
	)
	t = styledTable(t)

	cpuBase, _ := readCPUSample()
	netBase, _ := readNetSample()

	return model{
		table:      t,
		ports:      []Port{},
		portConfig: loadPortConfig(configFile),
		configFile: configFile,
		lastUpdate: time.Now(),
		width:      80,
		height:     24,
		tab:        TabPorts,
		cpuSpark:   NewSparkline(SparklineHistory),
		memSpark:   NewSparkline(SparklineHistory),
		swapSpark:  NewSparkline(SparklineHistory),
		netRxSpark: NewSparkline(SparklineHistory),
		netTxSpark: NewSparkline(SparklineHistory),
		prevCPU:    cpuBase,
		prevNet:    netBase,
	}
}
