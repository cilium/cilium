//go:build linux && !cgo
// +build linux,!cgo

package loadavg

import (
	"fmt"
	"io"
	"os"
)

func get() (*Stats, error) {
	// Reference: man 5 proc, loadavg_proc_show in Linux source code
	file, err := os.Open("/proc/loadavg")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return collectLoadavgStats(file)
}

func collectLoadavgStats(out io.Reader) (*Stats, error) {
	var loadavg Stats
	ret, err := fmt.Fscanf(out, "%f %f %f", &loadavg.Loadavg1, &loadavg.Loadavg5, &loadavg.Loadavg15)
	if err != nil || ret != 3 {
		return nil, fmt.Errorf("unexpected format of /proc/loadavg")
	}
	return &loadavg, nil
}
