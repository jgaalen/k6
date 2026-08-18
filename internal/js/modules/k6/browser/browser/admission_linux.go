//go:build linux

package browser

import (
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const bytesPerMiB = 1024 * 1024

func probeBrowserResources() browserResourceSnapshot {
	var snapshot browserResourceSnapshot
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 || fields[0] != "MemAvailable:" {
				continue
			}
			if availableKB, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
				snapshot.availableMemoryMB = availableKB / 1024
				snapshot.memoryKnown = true
			}
			break
		}
	}
	if cgroupAvailableMB, ok := cgroupAvailableMemoryMB(); ok &&
		(!snapshot.memoryKnown || cgroupAvailableMB < snapshot.availableMemoryMB) {
		snapshot.availableMemoryMB = cgroupAvailableMB
		snapshot.memoryKnown = true
	}

	var stat unix.Statfs_t
	if err := unix.Statfs("/dev/shm", &stat); err == nil {
		snapshot.availableShmMB = int64(stat.Bavail) * int64(stat.Bsize) / bytesPerMiB
		snapshot.shmKnown = true
	}
	return snapshot
}

func cgroupAvailableMemoryMB() (int64, bool) {
	for _, files := range [][2]string{
		{"/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory.current"},
		{"/sys/fs/cgroup/memory/memory.limit_in_bytes", "/sys/fs/cgroup/memory/memory.usage_in_bytes"},
	} {
		limitRaw, err := os.ReadFile(files[0])
		if err != nil {
			continue
		}
		limitText := strings.TrimSpace(string(limitRaw))
		if limitText == "max" {
			continue
		}
		limit, err := strconv.ParseInt(limitText, 10, 64)
		if err != nil || limit <= 0 || limit >= 1<<60 {
			continue
		}
		currentRaw, err := os.ReadFile(files[1])
		if err != nil {
			continue
		}
		current, err := strconv.ParseInt(strings.TrimSpace(string(currentRaw)), 10, 64)
		if err != nil || current < 0 {
			continue
		}
		if current >= limit {
			return 0, true
		}
		return (limit - current) / bytesPerMiB, true
	}
	return 0, false
}
