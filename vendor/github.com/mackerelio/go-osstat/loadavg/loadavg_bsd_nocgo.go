//go:build (darwin || freebsd || netbsd || openbsd) && !cgo
// +build darwin freebsd netbsd openbsd
// +build !cgo

package loadavg

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

func get() (*Stats, error) {
	ret, err := unix.SysctlRaw("vm.loadavg")
	if err != nil {
		return nil, fmt.Errorf("failed in sysctl vm.loadavg: %s", err)
	}
	return collectLoadavgStats(ret)
}

// loadavg in sys/sysctl.h
type loadStruct struct {
	Ldavg  [3]uint32
	Fscale uint64
}

// Reference: sys/sysctl.h
func collectLoadavgStats(out []byte) (*Stats, error) {
	if len(out) != 24 {
		return nil, fmt.Errorf("unexpected output of sysctl vm.loadavg: %v (len: %d)", out, len(out))
	}
	load := *(*loadStruct)(unsafe.Pointer(&out[0]))
	return &Stats{
		Loadavg1:  float64(load.Ldavg[0]) / float64(load.Fscale),
		Loadavg5:  float64(load.Ldavg[1]) / float64(load.Fscale),
		Loadavg15: float64(load.Ldavg[2]) / float64(load.Fscale),
	}, nil
}
