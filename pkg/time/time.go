// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// package time is a wrapper for the stdlib time library that aliases most
// underlying types, but allows overrides for testing purposes.
//
// Synced to go-1.20.7.
package time

import (
	"time"
)

const (
	Layout      = time.Layout
	ANSIC       = time.ANSIC
	UnixDate    = time.UnixDate
	RubyDate    = time.RubyDate
	RFC822      = time.RFC822
	RFC822Z     = time.RFC822Z
	RFC850      = time.RFC850
	RFC1123     = time.RFC1123
	RFC1123Z    = time.RFC1123Z
	RFC3339     = time.RFC3339
	RFC3339Nano = time.RFC3339Nano
	Kitchen     = time.Kitchen
	Stamp       = time.Stamp
	StampMilli  = time.StampMilli
	StampMicro  = time.StampMicro
	StampNano   = time.StampNano
	DateTime    = time.DateTime
	DateOnly    = time.DateOnly
	TimeOnly    = time.TimeOnly

	Nanosecond  = time.Nanosecond
	Microsecond = time.Microsecond
	Millisecond = time.Millisecond
	Second      = time.Second
	Minute      = time.Minute
	Hour        = time.Hour
)

var (
	ParseDuration          = time.ParseDuration
	Since                  = time.Since
	Until                  = time.Until
	FixedZone              = time.FixedZone
	LoadLocation           = time.LoadLocation
	LoadLocationFromTZData = time.LoadLocationFromTZData
	Date                   = time.Date
	Now                    = time.Now
	Parse                  = time.Parse
	ParseInLocation        = time.ParseInLocation
	UTC                    = time.UTC
	Unix                   = time.Unix
	UnixMicro              = time.UnixMicro
	UnixMilli              = time.UnixMilli
)

type (
	Duration   = time.Duration
	Location   = time.Location
	Month      = time.Month
	ParseError = time.ParseError
	Ticker     = time.Ticker
	Time       = time.Time
	Timer      = time.Timer
	Weekday    = time.Weekday
)

var (
	MaxInternalTimerDelay time.Duration
)

// After overrides the stdlib time.After to enforce maximum sleepiness via
// option.MaxInternalTimerDelay.
func After(d Duration) <-chan Time {
	if MaxInternalTimerDelay > 0 && d > MaxInternalTimerDelay {
		d = MaxInternalTimerDelay
	}
	return time.After(d)
}

// Sleep overrides the stdlib time.Sleep to enforce maximum sleepiness via
// option.MaxInternalTimerDelay.
func Sleep(d time.Duration) {
	if MaxInternalTimerDelay > 0 && d > MaxInternalTimerDelay {
		d = MaxInternalTimerDelay
	}
	time.Sleep(d)
}

// Tick overrides the stdlib time.Tick to enforce maximum sleepiness via
// option.MaxInternalTimerDelay.
func Tick(d Duration) <-chan time.Time {
	return NewTicker(d).C
}

// NewTicker overrides the stdlib time.NewTicker to enforce maximum sleepiness
// via option.MaxInternalTimerDelay.
func NewTicker(d Duration) *time.Ticker {
	if MaxInternalTimerDelay > 0 && d > MaxInternalTimerDelay {
		d = MaxInternalTimerDelay
	}
	return time.NewTicker(d)
}

// NewTimer overrides the stdlib time.NewTimer to enforce maximum sleepiness
// via option.MaxInternalTimerDelay.
func NewTimer(d Duration) *time.Timer {
	if MaxInternalTimerDelay > 0 && d > MaxInternalTimerDelay {
		d = MaxInternalTimerDelay
	}
	return time.NewTimer(d)
}

// NewTimerWithoutMaxDelay returns a time.NewTimer without enforcing maximum
// sleepiness. This function should only be used in cases where the timer firing
// early impacts correctness. If in doubt, you probably should use NewTimer.
func NewTimerWithoutMaxDelay(d Duration) *time.Timer {
	return time.NewTimer(d)
}

// AfterFunc overrides the stdlib time.AfterFunc to enforce maximum sleepiness
// via option.MaxInternalTimerDelay.
func AfterFunc(d Duration, f func()) *time.Timer {
	if MaxInternalTimerDelay > 0 && d > MaxInternalTimerDelay {
		d = MaxInternalTimerDelay
	}
	return time.AfterFunc(d, f)
}
