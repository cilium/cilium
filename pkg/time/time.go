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
	After                  = time.After
	Sleep                  = time.Sleep
	Tick                   = time.Tick
	ParseDuration          = time.ParseDuration
	Since                  = time.Since
	Until                  = time.Until
	FixedZone              = time.FixedZone
	LoadLocation           = time.LoadLocation
	LoadLocationFromTZData = time.LoadLocationFromTZData
	NewTicker              = time.NewTicker
	Date                   = time.Date
	Now                    = time.Now
	Parse                  = time.Parse
	ParseInLocation        = time.ParseInLocation
	Unix                   = time.Unix
	UnixMicro              = time.UnixMicro
	UnixMilli              = time.UnixMilli
	AfterFunc              = time.AfterFunc
	NewTimer               = time.NewTimer
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
