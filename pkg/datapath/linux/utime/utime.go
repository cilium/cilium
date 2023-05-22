// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utime

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"time"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/maps/configmap"
)

const (
	btimeInfoFilepath = "/proc/stat"
	nClockSamples     = 10

	// Number of bits to shift a monotonic 64-bit nanosecond clock for utime unit.  Dividing
	// nanoseconds by 2^9 yields roughly half microsecond accuracy but avoids expensive 64-bit
	// divisions in the datapath.  With this shift the range of an u64 is ~300000 years
	// instead of ~600 years if left at nanoseconds.
	// With this shift full seconds can be multiplied by 1e9>>9 to get utime units.
	// Must be kept in sync with `UTIME_SHIFT` in datapath (bpf/lib/utime.h), any changes to
	// this will have an upgrade impact.
	utimeShift = 9
	// 10^9 has 9 trailing zeroes also in binary, so they can be shifted off without any loss
	// of accuracy.
	secsToUtimeMultiplier = 1_000_000_000 >> utimeShift // integer value (1953125)
	// utime numerical limits in seconds
	minSeconds = 0
	maxSeconds = 1 << (64 + utimeShift) / 1_000_000_000 // 2^(64+9)/10^9
)

// Unix epoch time value on 2^9/10^9 second accuracy. This accuracy
// is chosen so that the timing is reasonably accurate for expiry times, but does not require 64-bit
// division of a monotonic clock value in the datapath, as it is a rather slow operation.
type UTime uint64

func ToUTime(secs int64, nanos int) UTime {
	return UTime(secs)*secsToUtimeMultiplier + UTime(nanos)>>utimeShift
}

func TimeToUTime(t time.Time) UTime {
	return ToUTime(t.Unix(), t.Nanosecond())
}

func (t UTime) Time() time.Time {
	secs := t / secsToUtimeMultiplier
	usecs := t % secsToUtimeMultiplier
	return time.Unix(int64(secs), int64(usecs<<utimeShift))
}

func (t UTime) String() string {
	return t.Time().String()
}

type utimeController struct {
	configMap configmap.Map
	offset    UTime
}

func (u *utimeController) sync() error {
	offset := getCurrentUTimeOffset()
	if offset != u.offset {
		if err := u.configMap.Update(configmap.UTimeOffset, uint64(offset)); err != nil {
			return fmt.Errorf("failed to update utime offset: %w", err)
		}
		u.offset = offset
	}
	return nil
}

// getCurrentUTimeOffset returns the current time offset to be configured for the datapath
func getCurrentUTimeOffset() UTime {
	// boottime is in seconds since Unix epoch, delta is clock drift in nanoseconds
	boottime, err := getBoottime()
	if err != nil {
		log.WithError(err).Errorf("Error getting boot time from %s", btimeInfoFilepath)
	}
	return TimeToUTime(boottime)
}

// getBoottime returns the kernel boot time.
// We parse it from /proc/stat. GetBoottime() should be invoked only occasionally.
func getBoottime() (t time.Time, err error) {
	var boottime int64
	var delta int64
	stat, err := os.Open(btimeInfoFilepath)
	if err != nil {
		return t, err
	}
	defer stat.Close()
	scanner := bufio.NewScanner(stat)
	for scanner.Scan() {
		n, _ := fmt.Sscanf(scanner.Text(), "btime %d\n", &boottime)
		if n == 1 {
			break
		}
	}
	err = scanner.Err()
	if err != nil {
		return t, err
	}

	// get an estimated difference between monotonic and boot clocks, that accounts for
	// the lost suspend time in the monotonic clock.
	// Linux 5.8 has bpf helper for ktime_get_boot_ns that does not need this, so we can
	// get rid of this block when Linux 5.8 is the oldest supported kernel.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	// Keep the minimum difference out of 10 samples to estimate the drift between boottime and
	// monotonic clocks at the time this call.
	for i := 0; i < nClockSamples; i++ {
		var monotonicTimespec unix.Timespec
		err = unix.ClockGettime(unix.CLOCK_MONOTONIC, &monotonicTimespec)
		if err != nil {
			return t, err
		}
		var bootTimespec unix.Timespec
		err = unix.ClockGettime(unix.CLOCK_BOOTTIME, &bootTimespec)
		if err != nil {
			return t, err
		}
		bNano := bootTimespec.Nano()
		mNano := monotonicTimespec.Nano()
		if bNano > mNano {
			diff := bNano - mNano
			if delta == int64(0) || diff < delta {
				delta = diff
			}
		}
	}
	return time.Unix(boottime, delta), nil
}
