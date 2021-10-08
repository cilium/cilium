// +build solaris

package mem

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/shirou/gopsutil/v3/internal/common"
)

// VirtualMemory for Solaris is a minimal implementation which only returns
// what Nomad needs. It does take into account global vs zone, however.
func VirtualMemory() (*VirtualMemoryStat, error) {
	return VirtualMemoryWithContext(context.Background())
}

func VirtualMemoryWithContext(ctx context.Context) (*VirtualMemoryStat, error) {
	result := &VirtualMemoryStat{}

	zoneName, err := zoneName()
	if err != nil {
		return nil, err
	}

	if zoneName == "global" {
		cap, err := globalZoneMemoryCapacity()
		if err != nil {
			return nil, err
		}
		result.Total = cap
	} else {
		cap, err := nonGlobalZoneMemoryCapacity()
		if err != nil {
			return nil, err
		}
		result.Total = cap
	}

	return result, nil
}

func SwapMemory() (*SwapMemoryStat, error) {
	return SwapMemoryWithContext(context.Background())
}

func SwapMemoryWithContext(ctx context.Context) (*SwapMemoryStat, error) {
	return nil, common.ErrNotImplementedError
}

func zoneName() (string, error) {
	zonename, err := exec.LookPath("zonename")
	if err != nil {
		return "", err
	}

	ctx := context.Background()
	out, err := invoke.CommandWithContext(ctx, zonename)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(out)), nil
}

var globalZoneMemoryCapacityMatch = regexp.MustCompile(`memory size: ([\d]+) Megabytes`)

func globalZoneMemoryCapacity() (uint64, error) {
	prtconf, err := exec.LookPath("prtconf")
	if err != nil {
		return 0, err
	}

	ctx := context.Background()
	out, err := invoke.CommandWithContext(ctx, prtconf)
	if err != nil {
		return 0, err
	}

	match := globalZoneMemoryCapacityMatch.FindAllStringSubmatch(string(out), -1)
	if len(match) != 1 {
		return 0, errors.New("memory size not contained in output of /usr/sbin/prtconf")
	}

	totalMB, err := strconv.ParseUint(match[0][1], 10, 64)
	if err != nil {
		return 0, err
	}

	return totalMB * 1024 * 1024, nil
}

var kstatMatch = regexp.MustCompile(`([^\s]+)[\s]+([^\s]*)`)

func nonGlobalZoneMemoryCapacity() (uint64, error) {
	kstat, err := exec.LookPath("kstat")
	if err != nil {
		return 0, err
	}

	ctx := context.Background()
	out, err := invoke.CommandWithContext(ctx, kstat, "-p", "-c", "zone_memory_cap", "memory_cap:*:*:physcap")
	if err != nil {
		return 0, err
	}

	kstats := kstatMatch.FindAllStringSubmatch(string(out), -1)
	if len(kstats) != 1 {
		return 0, fmt.Errorf("expected 1 kstat, found %d", len(kstats))
	}

	memSizeBytes, err := strconv.ParseUint(kstats[0][2], 10, 64)
	if err != nil {
		return 0, err
	}

	return memSizeBytes, nil
}

const swapsCommand = "swap"

// The blockSize as reported by `swap -l`. See https://docs.oracle.com/cd/E23824_01/html/821-1459/fsswap-52195.html
const blockSize = 512

// swapctl column indexes
const (
	nameCol = 0
	// devCol = 1
	// swaploCol = 2
	totalBlocksCol = 3
	freeBlocksCol  = 4
)

func SwapDevices() ([]*SwapDevice, error) {
	return SwapDevicesWithContext(context.Background())
}

func SwapDevicesWithContext(ctx context.Context) ([]*SwapDevice, error) {
	swapsCommandPath, err := exec.LookPath(swapsCommand)
	if err != nil {
		return nil, fmt.Errorf("could not find command %q: %w", swapCommand, err)
	}
	output, err := invoke.CommandWithContext(swapsCommandPath, "-l")
	if err != nil {
		return nil, fmt.Errorf("could not execute %q: %w", swapsCommand, err)
	}

	return parseSwapsCommandOutput(string(output))
}

func parseSwapsCommandOutput(output string) ([]*SwapDevice, error) {
	lines := strings.Split(output, "\n")
	if len(lines) == 0 {
		return nil, fmt.Errorf("could not parse output of %q: no lines in %q", swapsCommand, output)
	}

	// Check header headerFields are as expected.
	headerFields := strings.Fields(lines[0])
	if len(headerFields) < freeBlocksCol {
		return nil, fmt.Errorf("couldn't parse %q: too few fields in header %q", swapsCommand, lines[0])
	}
	if headerFields[nameCol] != "swapfile" {
		return nil, fmt.Errorf("couldn't parse %q: expected %q to be %q", swapsCommand, headerFields[nameCol], "swapfile")
	}
	if headerFields[totalBlocksCol] != "blocks" {
		return nil, fmt.Errorf("couldn't parse %q: expected %q to be %q", swapsCommand, headerFields[totalBlocksCol], "blocks")
	}
	if headerFields[freeBlocksCol] != "free" {
		return nil, fmt.Errorf("couldn't parse %q: expected %q to be %q", swapsCommand, headerFields[freeBlocksCol], "free")
	}

	var swapDevices []*SwapDevice
	for _, line := range lines[1:] {
		if line == "" {
			continue // the terminal line is typically empty
		}
		fields := strings.Fields(line)
		if len(fields) < freeBlocksCol {
			return nil, fmt.Errorf("couldn't parse %q: too few fields", swapsCommand)
		}

		totalBlocks, err := strconv.ParseUint(fields[totalBlocksCol], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("couldn't parse 'Size' column in %q: %w", swapsCommand, err)
		}

		freeBlocks, err := strconv.ParseUint(fields[freeBlocksCol], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("couldn't parse 'Used' column in %q: %w", swapsCommand, err)
		}

		swapDevices = append(swapDevices, &SwapDevice{
			Name:      fields[nameCol],
			UsedBytes: (totalBlocks - freeBlocks) * blockSize,
			FreeBytes: freeBlocks * blockSize,
		})
	}

	return swapDevices, nil
}
