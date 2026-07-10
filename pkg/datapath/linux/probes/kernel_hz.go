// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package probes

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"time"
)

// Available CONFIG_HZ values, sorted from highest to lowest.
var hzValues = []uint16{1000, 300, 250, 100}

// KernelHZ attempts to estimate the kernel's CONFIG_HZ compile-time value by
// making snapshots of the kernel timestamp with a time interval in between.
//
// Blocks for at least 100ms while the measurement is in progress. Can block
// significantly longer under some hypervisors like VirtualBox due to buggy
// clocks, interrupt coalescing and low timer resolution.
func KernelHZ() (uint16, error) {
	f, err := os.Open("/proc/schedstat")
	if err != nil {
		return 0, err
	}
	defer f.Close()

	// Measure the kernel timestamp at least 100ms apart, giving kernel timer and
	// wall clock ample opportunity to advance for adequate sample size.
	j1, err := readSchedstat(f)
	if err != nil {
		return 0, err
	}

	// On some platforms, this can put the goroutine to sleep for significantly
	// longer than 100ms. Do not rely on readings being anywhere near 100ms apart.
	time.Sleep(time.Millisecond * 100)

	j2, err := readSchedstat(f)
	if err != nil {
		return 0, err
	}

	hz, err := j1.interpolate(j2)
	if err != nil {
		return 0, fmt.Errorf("interpolating hz value: %w", err)
	}

	return nearest(hz, hzValues)
}

// Jiffies returns the kernel's internal timestamp in jiffies read from
// /proc/schedstat.
func Jiffies() (uint64, error) {
	f, err := os.Open("/proc/schedstat")
	if err != nil {
		return 0, err
	}
	defer f.Close()

	k, err := readSchedstat(f)
	if err != nil {
		return 0, err
	}

	return k.k, nil
}

// readSchedstat expects to read /proc/schedstat and returns the first line
// matching 'timestamp %d'. Upon return, f is rewound to allow reuse.
//
// Should not be called concurrently.
func readSchedstat(f io.ReadSeeker) (ktime, error) {
	// Rewind the file when done so the next call gets fresh data.
	defer func() { _, _ = f.Seek(0, 0) }()

	var j uint64
	var t = time.Now()

	s := bufio.NewScanner(f)
	for s.Scan() {
		if _, err := fmt.Sscanf(s.Text(), "timestamp %d", &j); err == nil {
			return ktime{j, t}, nil
		}
	}

	return ktime{}, errors.New("no kernel timestamp found")
}

type ktime struct {
	k uint64
	t time.Time
}

// interpolate returns the amount of jiffies (ktime) that would have elapsed if
// both ktimes were measured exactly 1 second apart. Using linear interpolation,
// the delta between both kernel timestamps is adjusted based on the elapsed
// wall time between both measurements.
func (old ktime) interpolate(new ktime) (uint16, error) {
	if old.t.After(new.t) {
		return 0, fmt.Errorf("old wall time %v is more recent than %v", old.t, new.t)
	}
	if old.k > new.k {
		return 0, fmt.Errorf("old kernel timer %d is higher than %d", old.k, new.k)
	}

	// Jiffy and duration delta.
	kd := new.k - old.k
	td := new.t.Sub(old.t)

	// Linear interpolation to represent elapsed jiffies as a per-second value.
	hz := float64(kd) / td.Seconds()
	hz = math.Round(hz)
	if hz > math.MaxUint16 {
		return 0, fmt.Errorf("interpolated hz value would overflow uint16: %f", hz)
	}

	return uint16(hz), nil
}

// nearest returns the entry from values that's closest to in. If in has an
// equal distance to multiple values, the value that appears the earliest in
// values wins. Returns error if values is empty.
func nearest(in uint16, values []uint16) (uint16, error) {
	if len(values) == 0 {
		return 0, errors.New("values cannot be empty")
	}

	var out uint16
	min := ^uint16(0)
	for _, v := range values {
		// Get absolute distance between in and v.
		d := uint16(in - v)
		if in < v {
			d = v - in
		}

		// Check if the distance to the current number is smaller than to the
		// previous number.
		if d < min {
			min = d
			out = v
		}
	}

	return out, nil
}
