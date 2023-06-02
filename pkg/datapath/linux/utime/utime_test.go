// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package utime

import (
	"runtime"
	"testing"
	"time"

	. "github.com/cilium/checkmate"
	"golang.org/x/sys/unix"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type utimeSuite struct{}

var _ = Suite(&utimeSuite{})

func (s *utimeSuite) TestUTime(c *C) {
	c.Assert(maxSeconds, Equals, 9_444_732_965_739)
	// Loop through the numeric range of utime in seconds incrementing by a large prime to keep
	// the runtime bounded.
	for i := int64(minSeconds); i <= maxSeconds; i += 9999889 {
		// Get time.Time from i as both seconds and microseconds
		now := time.Unix(i, i%1000000000)
		// Convert to uTime
		uTime := TimeToUTime(now)
		// Convert back to time.Time()
		t := uTime.Time()
		// Assert that they are the same on the microsecond accuracy
		c.Assert(now.Sub(t).Truncate(time.Microsecond), Equals, time.Duration(0))
	}
}

func (s *utimeSuite) TestGetBoottime(c *C) {
	boottime, err := getBoottime()
	log.Infof("Adjusted boot time: %s", boottime)
	c.Assert(err, IsNil)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var timespec unix.Timespec
	err = unix.ClockGettime(unix.CLOCK_MONOTONIC, &timespec)
	timeNow := time.Now()

	c.Assert(err, IsNil)
	now := boottime.Add(time.Duration(timespec.Nano()))
	diff := timeNow.Sub(now)

	// Local testing showed a difference of less than a second,
	// fail test if more than 5 seconds
	c.Assert(diff < (time.Second*5), Equals, true)

	// There should be non-zero nanosecond component in boottime that accounts for the time the
	// boottime and monotonic clocks in all cases, as the boottime clock is sampled after the
	// monotonic clock. This will flake if that delta is an exact number of seconds, but this
	// should be unlikely.
	c.Assert(boottime.Nanosecond() > 0, Equals, true)
}
