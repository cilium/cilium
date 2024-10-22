//go:build freebsd
// +build freebsd

package memory

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Get memory statistics
func Get() (*Stats, error) {
	return collectMemoryStats()
}

// Stats represents memory statistics for freebsd
type Stats struct {
	Total, Used, Cached, Free, Active, Inactive, Wired,
	SwapTotal, SwapUsed, SwapFree uint64
}

type memStat struct {
	name  string
	ptr   *uint64
	scale *uint64
}

func collectMemoryStats() (*Stats, error) {
	var pageSize uint64
	one := uint64(1)

	var memory Stats
	memStats := []memStat{
		{"vm.stats.vm.v_page_size", &pageSize, &one},
		{"hw.physmem", &memory.Total, &one},
		{"vm.stats.vm.v_cache_count", &memory.Cached, &pageSize},
		{"vm.stats.vm.v_free_count", &memory.Free, &pageSize},
		{"vm.stats.vm.v_active_count", &memory.Active, &pageSize},
		{"vm.stats.vm.v_inactive_count", &memory.Inactive, &pageSize},
		{"vm.stats.vm.v_wire_count", &memory.Wired, &pageSize},
	}

	for _, stat := range memStats {
		ret, err := unix.SysctlRaw(stat.name)
		if err != nil {
			return nil, fmt.Errorf("failed in sysctl %s: %s", stat.name, err)
		}
		if len(ret) == 8 {
			*stat.ptr = *(*uint64)(unsafe.Pointer(&ret[0])) * *stat.scale
		} else if len(ret) == 4 {
			*stat.ptr = uint64(*(*uint32)(unsafe.Pointer(&ret[0]))) * *stat.scale
		} else {
			return nil, fmt.Errorf("failed in sysctl %s: %s", stat.name, err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// collect swap statistics from swapinfo command
	cmd := exec.CommandContext(ctx, "swapinfo", "-k")
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	memory.SwapTotal, memory.SwapUsed, err = collectSwapStats(out)
	if err != nil {
		go cmd.Wait()
		return nil, err
	}
	if err := cmd.Wait(); err != nil {
		return nil, err
	}

	memory.Used = memory.Total - memory.Free - memory.Cached - memory.Inactive
	memory.SwapFree = memory.SwapTotal - memory.SwapUsed

	return &memory, nil
}

func collectSwapStats(out io.Reader) (uint64, uint64, error) {
	scanner := bufio.NewScanner(out)
	if !scanner.Scan() {
		return 0, 0, fmt.Errorf("failed to scan output of swapinfo")
	}
	line := scanner.Text()
	if !strings.HasPrefix(line, "Device") {
		return 0, 0, fmt.Errorf("unexpected output of swapinfo: %s", line)
	}

	var total, used uint64
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		if v, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
			total += v * 1024
		}
		if v, err := strconv.ParseUint(fields[2], 10, 64); err == nil {
			used += v * 1024
		}
	}

	return total, used, nil
}
