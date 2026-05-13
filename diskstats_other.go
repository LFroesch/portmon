//go:build !linux

package main

func readDiskStats() []DiskStat {
	return nil
}
