package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Sparkline block characters (low → high)
var blocks = []rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

type SystemStats struct {
	Supported bool
	Warning   string

	CPUPercent float64
	MemTotal   uint64 // bytes
	MemUsed    uint64
	MemPercent float64

	SwapTotal   uint64
	SwapUsed    uint64
	SwapPercent float64

	NetRxBytes uint64
	NetTxBytes uint64
	NetRxRate  float64 // bytes/sec
	NetTxRate  float64 // bytes/sec

	LoadAvg1  float64
	LoadAvg5  float64
	LoadAvg15 float64

	Uptime   time.Duration
	Hostname string
	Kernel   string

	Disks []DiskStat

	TopProcs []ProcStat
}

type DiskStat struct {
	Mount   string
	Total   uint64
	Used    uint64
	Percent float64
}

type ProcStat struct {
	PID    int
	Name   string
	CPUPct float64
	MemPct float64
}

type Sparkline struct {
	values []float64
	max    int
}

func NewSparkline(max int) *Sparkline {
	return &Sparkline{max: max}
}

func (s *Sparkline) Add(v float64) {
	s.values = append(s.values, v)
	if len(s.values) > s.max {
		s.values = s.values[1:]
	}
}

func (s *Sparkline) Render(width int) string {
	vals := s.values
	if len(vals) == 0 {
		return strings.Repeat(string(blocks[0]), width)
	}
	if len(vals) > width {
		vals = vals[len(vals)-width:]
	}

	// Find max for scaling
	maxVal := 100.0
	for _, v := range vals {
		if v > maxVal {
			maxVal = v
		}
	}

	var sb strings.Builder
	// Pad left if not enough data
	if len(vals) < width {
		for i := 0; i < width-len(vals); i++ {
			sb.WriteRune(blocks[0])
		}
	}
	for _, v := range vals {
		idx := int(v / maxVal * float64(len(blocks)-1))
		if idx < 0 {
			idx = 0
		}
		if idx >= len(blocks) {
			idx = len(blocks) - 1
		}
		sb.WriteRune(blocks[idx])
	}
	return sb.String()
}

func renderBar(pct float64, width int) string {
	filled := int(pct / 100.0 * float64(width))
	if filled > width {
		filled = width
	}
	if filled < 0 {
		filled = 0
	}
	empty := width - filled
	return barFilledStyle.Render(strings.Repeat("█", filled)) +
		barEmptyStyle.Render(strings.Repeat("░", empty))
}

// --- /proc readers ---

type cpuSample struct {
	idle  uint64
	total uint64
}

func readCPUSample() (cpuSample, error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return cpuSample{}, err
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) == 0 {
		return cpuSample{}, fmt.Errorf("empty /proc/stat")
	}
	// First line: cpu  user nice system idle iowait irq softirq steal ...
	fields := strings.Fields(lines[0])
	if len(fields) < 5 || fields[0] != "cpu" {
		return cpuSample{}, fmt.Errorf("unexpected /proc/stat format")
	}
	var total, idle uint64
	for i, f := range fields[1:] {
		v, _ := strconv.ParseUint(f, 10, 64)
		total += v
		if i == 3 { // idle is 4th value (index 3)
			idle = v
		}
	}
	return cpuSample{idle: idle, total: total}, nil
}

func calcCPUPercent(prev, curr cpuSample) float64 {
	totalDelta := float64(curr.total - prev.total)
	if totalDelta == 0 {
		return 0
	}
	idleDelta := float64(curr.idle - prev.idle)
	return (1.0 - idleDelta/totalDelta) * 100.0
}

type memInfo struct {
	total     uint64
	available uint64
	swapTotal uint64
	swapFree  uint64
}

func readMemInfo() (memInfo, error) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return memInfo{}, err
	}
	var m memInfo
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		val, _ := strconv.ParseUint(fields[1], 10, 64)
		val *= 1024 // kB to bytes
		switch fields[0] {
		case "MemTotal:":
			m.total = val
		case "MemAvailable:":
			m.available = val
		case "SwapTotal:":
			m.swapTotal = val
		case "SwapFree:":
			m.swapFree = val
		}
	}
	return m, nil
}

type netSample struct {
	rxBytes uint64
	txBytes uint64
}

func readNetSample() (netSample, error) {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return netSample{}, err
	}
	var s netSample
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, ":") || strings.HasPrefix(line, "Inter") || strings.HasPrefix(line, "face") {
			continue
		}
		// Skip loopback
		if strings.HasPrefix(line, "lo:") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) < 2 {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) < 9 {
			continue
		}
		rx, _ := strconv.ParseUint(fields[0], 10, 64)
		tx, _ := strconv.ParseUint(fields[8], 10, 64)
		s.rxBytes += rx
		s.txBytes += tx
	}
	return s, nil
}

func formatBytes(b uint64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)
	switch {
	case b >= GB:
		return fmt.Sprintf("%.1fG", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%.1fM", float64(b)/float64(MB))
	case b >= KB:
		return fmt.Sprintf("%.0fK", float64(b)/float64(KB))
	default:
		return fmt.Sprintf("%dB", b)
	}
}

func formatRate(bytesPerSec float64) string {
	return formatBytes(uint64(bytesPerSec)) + "/s"
}

// --- Load average ---

func readLoadAvg() (load1, load5, load15 float64, err error) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return 0, 0, 0, fmt.Errorf("unexpected /proc/loadavg format")
	}
	load1, _ = strconv.ParseFloat(fields[0], 64)
	load5, _ = strconv.ParseFloat(fields[1], 64)
	load15, _ = strconv.ParseFloat(fields[2], 64)
	return load1, load5, load15, nil
}

// --- Uptime ---

func readUptime() (time.Duration, error) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return 0, fmt.Errorf("unexpected /proc/uptime format")
	}
	secs, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, err
	}
	return time.Duration(secs * float64(time.Second)), nil
}

// --- Disk usage ---

// --- Top processes ---

func readTopProcs(n int) []ProcStat {
	// ps aux --sort=-%cpu, grab top N
	out, err := exec.Command("ps", "aux", "--sort=-%cpu").Output()
	if err != nil {
		return nil
	}
	lines := strings.Split(string(out), "\n")
	var procs []ProcStat
	for i, line := range lines {
		if i == 0 { // header
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 11 {
			continue
		}
		pid, _ := strconv.Atoi(fields[1])
		cpuPct, _ := strconv.ParseFloat(fields[2], 64)
		memPct, _ := strconv.ParseFloat(fields[3], 64)
		name := fields[10]
		// Use basename only
		if idx := strings.LastIndex(name, "/"); idx >= 0 {
			name = name[idx+1:]
		}
		procs = append(procs, ProcStat{
			PID:    pid,
			Name:   name,
			CPUPct: cpuPct,
			MemPct: memPct,
		})
		if len(procs) >= n {
			break
		}
	}
	return procs
}

// --- Per-process stats (for port tab) ---

type ProcessResourceInfo struct {
	CPUPct string
	MemPct string
}

func getProcessResources(pids []int) map[int]ProcessResourceInfo {
	if len(pids) == 0 {
		return nil
	}

	// Build pid list for ps
	pidStrs := make([]string, len(pids))
	for i, p := range pids {
		pidStrs[i] = strconv.Itoa(p)
	}

	out, err := exec.Command("ps", "-o", "pid=,%cpu=,%mem=", "-p", strings.Join(pidStrs, ",")).Output()
	if err != nil {
		return nil
	}

	result := make(map[int]ProcessResourceInfo)
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		pid, _ := strconv.Atoi(fields[0])
		if pid > 0 {
			result[pid] = ProcessResourceInfo{
				CPUPct: fields[1] + "%",
				MemPct: fields[2] + "%",
			}
		}
	}
	return result
}

// --- System info ---

func readHostname() string {
	data, err := os.ReadFile("/etc/hostname")
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(data))
}

func readKernelVersion() string {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return ""
	}
	// "Linux version 6.6.87.2-microsoft-standard-WSL2 ..."
	fields := strings.Fields(string(data))
	if len(fields) >= 3 {
		return fields[2]
	}
	return ""
}
