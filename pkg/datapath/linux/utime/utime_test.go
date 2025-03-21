// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package utime

import (
	"runtime"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

func TestUTime(t *testing.T) {
	require.Equal(t, 9_444_732_965_739, maxSeconds)
	// Loop through the numeric range of utime in seconds incrementing by a large prime to keep
	// the runtime bounded.
	for i := int64(minSeconds); i <= maxSeconds; i += 9999889 {
		// Get time.Time from i as both seconds and microseconds
		now := time.Unix(i, i%1000000000)
		// Convert to uTime
		uTime := TimeToUTime(now)
		// Convert back to time.Time()
		tUTime := uTime.Time()
		// Assert that they are the same on the microsecond accuracy
		require.Equal(t, time.Duration(0), now.Sub(tUTime).Truncate(time.Microsecond))
	}
}

func TestGetBoottime(t *testing.T) {
	boottime, err := getBoottime()
	require.NoError(t, err)
	logger := hivetest.Logger(t)
	logger.Info("Adjusted boot time",
		logfields.BootTime, boottime.String(),
	)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var timespec unix.Timespec
	err = unix.ClockGettime(unix.CLOCK_MONOTONIC, &timespec)
	timeNow := time.Now()

	require.NoError(t, err)
	now := boottime.Add(time.Duration(timespec.Nano()))
	diff := timeNow.Sub(now)

	// Local testing showed a difference of less than a second,
	// fail test if more than 5 seconds
	require.Less(t, diff, (time.Second * 5))

	// There should be non-zero nanosecond component in boottime that accounts for the time the
	// boottime and monotonic clocks in all cases, as the boottime clock is sampled after the
	// monotonic clock. This will flake if that delta is an exact number of seconds, but this
	// should be unlikely.
	require.Positive(t, boottime.Nanosecond())
}
