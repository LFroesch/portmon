//go:build linux

package main

import "syscall"

func readDiskStats() []DiskStat {
	mounts := []string{"/", "/home", "/tmp", "/mnt", "/data"}

	var disks []DiskStat
	seenDev := make(map[uint64]bool)
	for _, mount := range mounts {
		var stat syscall.Statfs_t
		if err := syscall.Statfs(mount, &stat); err != nil {
			continue
		}
		if stat.Blocks == 0 {
			continue
		}

		devKey := uint64(stat.Fsid.X__val[0])<<32 | uint64(uint32(stat.Fsid.X__val[1]))
		if seenDev[devKey] {
			continue
		}
		seenDev[devKey] = true

		total := stat.Blocks * uint64(stat.Bsize)
		free := stat.Bavail * uint64(stat.Bsize)
		used := total - free
		var pct float64
		if total > 0 {
			pct = float64(used) / float64(total) * 100
		}
		disks = append(disks, DiskStat{
			Mount:   mount,
			Total:   total,
			Used:    used,
			Percent: pct,
		})
	}
	return disks
}
