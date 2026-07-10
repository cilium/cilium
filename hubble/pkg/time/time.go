// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package time

import (
	"fmt"
	"strings"
	"time"
)

const (
	// YearMonthDay is a time format similar to RFC3339 with day granularity
	// instead of second.
	YearMonthDay = "2006-01-02"
	// YearMonthDayHour is a time format similar to RFC3339 with hour
	// granularity instead of second.
	YearMonthDayHour = "2006-01-02T15Z07:00"
	// YearMonthDayHourMinute is a time format similar to RFC3339 with minute
	// granularity instead of second.
	YearMonthDayHourMinute = "2006-01-02T15:04Z07:00"
	// RFC3339Milli is a time format layout for use in time.Format and
	// time.Parse. It follows the RFC3339 format with millisecond precision.
	RFC3339Milli = "2006-01-02T15:04:05.999Z07:00"
	// RFC3339Micro is a time format layout for use in time.Format and
	// time.Parse. It follows the RFC3339 format with microsecond precision.
	RFC3339Micro = "2006-01-02T15:04:05.999999Z07:00"
)

var (
	// Now is a hijackable function for time.Now() that makes unit testing a lot
	// easier for stuff that relies on relative time.
	Now = time.Now
)

// layouts is a set of supported time format layouts. Format that only apply to
// local times should not be added to this list.
var layouts = []string{
	YearMonthDay,
	YearMonthDayHour,
	YearMonthDayHourMinute,
	time.RFC3339,
	time.RFC3339Nano,
	RFC3339Milli,
	RFC3339Micro,
	time.RFC1123Z,
}

// FromString takes as input a string in either RFC3339 or time.Duration
// format in the past and converts it to a time.Time.
func FromString(input string) (time.Time, error) {
	// try as relative duration first
	d, err := time.ParseDuration(input)
	if err == nil {
		return Now().Add(-d), nil
	}

	for _, layout := range layouts {
		t, err := time.Parse(layout, input)
		if err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf(
		"failed to convert %s to time", input,
	)
}

// FormatNames are the valid time format names accepted by this package.
var FormatNames = []string{
	"YearMonthDay",
	"YearMonthDayHour",
	"YearMonthDayHourMinute",
	"StampMilli",
	"RFC3339",
	"RFC3339Milli",
	"RFC3339Micro",
	"RFC3339Nano",
	"RFC1123Z",
}

// FormatNameToLayout returns the time format layout for the time format name.
func FormatNameToLayout(name string) string {
	switch strings.ToLower(name) {
	case "yearmonthday":
		return YearMonthDay
	case "yearmonthdayhour":
		return YearMonthDayHour
	case "yearmonthdayhourminute":
		return YearMonthDayHourMinute
	case "rfc3339":
		return time.RFC3339
	case "rfc3339milli":
		return RFC3339Milli
	case "rfc3339micro":
		return RFC3339Micro
	case "rfc3339nano":
		return time.RFC3339Nano
	case "rfc1123z":
		return time.RFC1123Z
	case "stampmilli":
		fallthrough
	default:
		return time.StampMilli
	}
}
