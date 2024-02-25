//go:build darwin
// +build darwin

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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Reference: man 1 vm_stat
	cmd := exec.CommandContext(ctx, "vm_stat")
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	memory, err := collectMemoryStats(out)
	if err != nil {
		// it is needed to cleanup the process, but its result is not needed.
		go cmd.Wait() //nolint:errcheck
		return nil, err
	}
	if err := cmd.Wait(); err != nil {
		return nil, err
	}

	// Reference: sys/sysctl.h, man 3 sysctl, sysctl vm.swapusage
	ret, err := unix.SysctlRaw("vm.swapusage")
	if err != nil {
		return nil, fmt.Errorf("failed in sysctl vm.swapusage: %s", err)
	}
	swap, err := collectSwapStats(ret)
	if err != nil {
		return nil, err
	}
	memory.SwapTotal = swap.Total
	memory.SwapUsed = swap.Used
	memory.SwapFree = swap.Avail

	return memory, nil
}

// Stats represents memory statistics for darwin
type Stats struct {
	Total, Used, Cached, Free, Active, Inactive, SwapTotal, SwapUsed, SwapFree uint64
}

// References:
//   - https://support.apple.com/guide/activity-monitor/view-memory-usage-actmntr1004/10.14/mac/11.0
//   - https://opensource.apple.com/source/system_cmds/system_cmds-880.60.2/vm_stat.tproj/
func collectMemoryStats(out io.Reader) (*Stats, error) {
	scanner := bufio.NewScanner(out)
	if !scanner.Scan() {
		return nil, fmt.Errorf("failed to scan output of vm_stat")
	}
	line := scanner.Text()
	var pageSize uint64
	if _, err := fmt.Sscanf(line, "Mach Virtual Memory Statistics: (page size of %d bytes)", &pageSize); err != nil {
		return nil, fmt.Errorf("unexpected output of vm_stat: %s", line)
	}

	var memory Stats
	var speculative, wired, purgeable, fileBacked, compressed uint64
	memStats := map[string]*uint64{
		"Pages free":                   &memory.Free,
		"Pages active":                 &memory.Active,
		"Pages inactive":               &memory.Inactive,
		"Pages speculative":            &speculative,
		"Pages wired down":             &wired,
		"Pages purgeable":              &purgeable,
		"File-backed pages":            &fileBacked,
		"Pages occupied by compressor": &compressed,
	}
	for scanner.Scan() {
		line := scanner.Text()
		i := strings.IndexRune(line, ':')
		if i < 0 {
			continue
		}
		if ptr := memStats[line[:i]]; ptr != nil {
			val := strings.TrimRight(strings.TrimSpace(line[i+1:]), ".")
			if v, err := strconv.ParseUint(val, 10, 64); err == nil {
				*ptr = v * pageSize
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan error for vm_stat: %s", err)
	}

	memory.Cached = purgeable + fileBacked
	memory.Used = wired + compressed + memory.Active + memory.Inactive + speculative - memory.Cached
	memory.Total = memory.Used + memory.Cached + memory.Free
	return &memory, nil
}

// xsw_usage in sys/sysctl.h
type swapUsage struct {
	Total     uint64
	Avail     uint64
	Used      uint64
	Pagesize  int32
	Encrypted bool
}

func collectSwapStats(out []byte) (*swapUsage, error) {
	if len(out) != 32 {
		return nil, fmt.Errorf("unexpected output of sysctl vm.swapusage: %v (len: %d)", out, len(out))
	}
	return (*swapUsage)(unsafe.Pointer(&out[0])), nil
}
