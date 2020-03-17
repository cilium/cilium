// Copyright 2015, Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package logutil

import (
	"time"

	logutilpb "github.com/youtube/vitess/go/vt/proto/logutil"
)

// This file contains a few functions to help with proto3.

// ProtoToTime converts a logutilpb.Time to a time.Time.
// proto3 will eventually support timestamps, at which point we'll retire
// this.
//
// A nil pointer is like the empty timestamp.
func ProtoToTime(ts *logutilpb.Time) time.Time {
	if ts == nil {
		// treat nil like the empty Timestamp
		return time.Unix(0, 0).UTC()
	}
	return time.Unix(ts.Seconds, int64(ts.Nanoseconds)).UTC()
}

// TimeToProto converts the time.Time to a logutilpb.Time.
func TimeToProto(t time.Time) *logutilpb.Time {
	seconds := t.Unix()
	nanos := int64(t.Sub(time.Unix(seconds, 0)))
	return &logutilpb.Time{
		Seconds:     seconds,
		Nanoseconds: int32(nanos),
	}
}

// EventStream is an interface used by RPC clients when the streaming
// RPC returns a stream of log events.
type EventStream interface {
	// Recv returns the next event in the logs.
	// If there are no more, it will return io.EOF.
	Recv() (*logutilpb.Event, error)
}
