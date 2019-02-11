// +build openbsd

package cpu

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/shirou/gopsutil/internal/common"
	"golang.org/x/sys/unix"
)

// sys/sched.h
var (
	CPUser    = 0
	CPNice    = 1
	CPSys     = 2
	CPIntr    = 3
	CPIdle    = 4
	CPUStates = 5
)

// sys/sysctl.h
const (
	CTLKern     = 1  // "high kernel": proc, limits
	KernCptime  = 40 // KERN_CPTIME
	KernCptime2 = 71 // KERN_CPTIME2
)

var ClocksPerSec = float64(128)

func init() {
	func() {
		getconf, err := exec.LookPath("/usr/bin/getconf")
		if err != nil {
			return
		}
		out, err := invoke.Command(getconf, "CLK_TCK")
		// ignore errors
		if err == nil {
			i, err := strconv.ParseFloat(strings.TrimSpace(string(out)), 64)
			if err == nil {
				ClocksPerSec = float64(i)
			}
		}
	}()
	func() {
		v, err := unix.Sysctl("kern.osrelease") // can't reuse host.PlatformInformation because of circular import
		if err != nil {
			return
		}
		v = strings.ToLower(v)
		version, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return
		}
		if version >= 6.4 {
			CPIntr = 4
			CPIdle = 5
			CPUStates = 6
		}
	}()
}

func Times(percpu bool) ([]TimesStat, error) {
	return TimesWithContext(context.Background(), percpu)
}

func TimesWithContext(ctx context.Context, percpu bool) ([]TimesStat, error) {
	var ret []TimesStat

	var ncpu int
	if percpu {
		ncpu, _ = Counts(true)
	} else {
		ncpu = 1
	}

	for i := 0; i < ncpu; i++ {
		var cpuTimes = make([]int64, CPUStates)
		var mib []int32
		if percpu {
			mib = []int32{CTLKern, KernCptime}
		} else {
			mib = []int32{CTLKern, KernCptime2, int32(i)}
		}
		buf, _, err := common.CallSyscall(mib)
		if err != nil {
			return ret, err
		}

		br := bytes.NewReader(buf)
		err = binary.Read(br, binary.LittleEndian, &cpuTimes)
		if err != nil {
			return ret, err
		}
		c := TimesStat{
			User:   float64(cpuTimes[CPUser]) / ClocksPerSec,
			Nice:   float64(cpuTimes[CPNice]) / ClocksPerSec,
			System: float64(cpuTimes[CPSys]) / ClocksPerSec,
			Idle:   float64(cpuTimes[CPIdle]) / ClocksPerSec,
			Irq:    float64(cpuTimes[CPIntr]) / ClocksPerSec,
		}
		if !percpu {
			c.CPU = "cpu-total"
		} else {
			c.CPU = fmt.Sprintf("cpu%d", i)
		}
		ret = append(ret, c)
	}

	return ret, nil
}

// Returns only one (minimal) CPUInfoStat on OpenBSD
func Info() ([]InfoStat, error) {
	return InfoWithContext(context.Background())
}

func InfoWithContext(ctx context.Context) ([]InfoStat, error) {
	var ret []InfoStat
	var err error

	c := InfoStat{}

	var u32 uint32
	if u32, err = unix.SysctlUint32("hw.cpuspeed"); err != nil {
		return nil, err
	}
	c.Mhz = float64(u32)

	if u32, err = unix.SysctlUint32("hw.ncpuonline"); err != nil {
		return nil, err
	}
	c.Cores = int32(u32)

	if c.ModelName, err = unix.Sysctl("hw.model"); err != nil {
		return nil, err
	}

	return append(ret, c), nil
}
