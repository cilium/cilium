// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package format

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/monitor/payload"
)

// TestMatch validates the endpoint filtering logic backing the cilium-dbg
// monitor `--from`, `--to` and `--related-to` flags, as well as the event
// type filter (`--type`).
func TestMatch(t *testing.T) {
	const (
		srcEP uint16 = 10
		dstEP uint16 = 20
		other uint16 = 30
	)

	tests := []struct {
		name       string
		eventTypes monitorAPI.MessageTypeFilter
		fromSource Uint16Flags
		toDst      Uint16Flags
		related    Uint16Flags
		want       bool
	}{
		{
			name: "no filters matches everything",
			want: true,
		},
		{
			name:       "--from matches source endpoint",
			fromSource: Uint16Flags{srcEP},
			want:       true,
		},
		{
			name:       "--from does not match other endpoints",
			fromSource: Uint16Flags{other},
			want:       false,
		},
		{
			name:       "--from does not match destination endpoint",
			fromSource: Uint16Flags{dstEP},
			want:       false,
		},
		{
			name:  "--to matches destination endpoint",
			toDst: Uint16Flags{dstEP},
			want:  true,
		},
		{
			name:  "--to does not match other endpoints",
			toDst: Uint16Flags{other},
			want:  false,
		},
		{
			name:  "--to does not match source endpoint",
			toDst: Uint16Flags{srcEP},
			want:  false,
		},
		{
			name:    "--related-to matches source endpoint",
			related: Uint16Flags{srcEP},
			want:    true,
		},
		{
			name:    "--related-to matches destination endpoint",
			related: Uint16Flags{dstEP},
			want:    true,
		},
		{
			name:    "--related-to does not match other endpoints",
			related: Uint16Flags{other},
			want:    false,
		},
		{
			name:       "--type matches event type",
			eventTypes: monitorAPI.MessageTypeFilter{monitorAPI.MessageTypeDrop},
			want:       true,
		},
		{
			name:       "--type filters out other event types",
			eventTypes: monitorAPI.MessageTypeFilter{monitorAPI.MessageTypeDebug},
			want:       false,
		},
		{
			name:       "--type and --from both match",
			eventTypes: monitorAPI.MessageTypeFilter{monitorAPI.MessageTypeDrop},
			fromSource: Uint16Flags{srcEP},
			want:       true,
		},
		{
			name:       "--type matches but --from does not",
			eventTypes: monitorAPI.MessageTypeFilter{monitorAPI.MessageTypeDrop},
			fromSource: Uint16Flags{other},
			want:       false,
		},
		{
			name:       "--from and --to both match",
			fromSource: Uint16Flags{srcEP},
			toDst:      Uint16Flags{dstEP},
			want:       true,
		},
		{
			name:       "--from matches but --to does not",
			fromSource: Uint16Flags{srcEP},
			toDst:      Uint16Flags{other},
			want:       false,
		},
		{
			name:       "multiple --from values match any",
			fromSource: Uint16Flags{other, srcEP},
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mf := NewMonitorFormatter(monitorAPI.INFO, nil, &bytes.Buffer{})
			mf.EventTypes = tt.eventTypes
			mf.FromSource = tt.fromSource
			mf.ToDst = tt.toDst
			mf.Related = tt.related

			got := mf.match(monitorAPI.MessageTypeDrop, srcEP, dstEP)
			assert.Equal(t, tt.want, got)
		})
	}
}

// dropNotifyPayload builds a minimal valid DropNotify (version 0) sample with
// the given source endpoint and destination endpoint ID.
func dropNotifyPayload(src uint16, dst uint32) []byte {
	data := make([]byte, 36)
	data[0] = byte(monitorAPI.MessageTypeDrop)       // Type
	data[1] = 130                                    // SubType: drop reason
	binary.NativeEndian.PutUint16(data[2:4], src)    // Source
	binary.NativeEndian.PutUint32(data[4:8], 0xdead) // Hash
	binary.NativeEndian.PutUint32(data[8:12], 0)     // OrigLen
	binary.NativeEndian.PutUint16(data[12:14], 0)    // CapLen
	data[14] = 0                                     // Version
	binary.NativeEndian.PutUint32(data[16:20], 1)    // SrcLabel
	binary.NativeEndian.PutUint32(data[20:24], 2)    // DstLabel
	binary.NativeEndian.PutUint32(data[24:28], dst)  // DstID
	binary.NativeEndian.PutUint16(data[28:30], 42)   // Line
	data[30] = 0                                     // File
	data[31] = 0                                     // ExtError
	binary.NativeEndian.PutUint32(data[32:36], 1)    // Ifindex
	return data
}

// TestFormatSampleFiltering exercises the public FormatEvent path with real
// DropNotify payloads to verify which events are printed depending on the
// configured monitor filters. This replaces the former RuntimeDatapathMonitorTest
// e2e tests ("cilium-dbg monitor check --from/--to/--related-to").
func TestFormatSampleFiltering(t *testing.T) {
	const (
		srcEP uint16 = 10
		dstEP uint32 = 20
		other uint16 = 30
	)

	tests := []struct {
		name      string
		configure func(*MonitorFormatter)
		printed   bool
	}{
		{
			name:      "unfiltered prints event",
			configure: func(mf *MonitorFormatter) {},
			printed:   true,
		},
		{
			name: "--from matching source prints event",
			configure: func(mf *MonitorFormatter) {
				mf.FromSource = Uint16Flags{srcEP}
			},
			printed: true,
		},
		{
			name: "--from other endpoint suppresses event",
			configure: func(mf *MonitorFormatter) {
				mf.FromSource = Uint16Flags{other}
			},
			printed: false,
		},
		{
			name: "--to matching destination prints event",
			configure: func(mf *MonitorFormatter) {
				mf.ToDst = Uint16Flags{uint16(dstEP)}
			},
			printed: true,
		},
		{
			name: "--to other endpoint suppresses event",
			configure: func(mf *MonitorFormatter) {
				mf.ToDst = Uint16Flags{other}
			},
			printed: false,
		},
		{
			name: "--related-to source prints event",
			configure: func(mf *MonitorFormatter) {
				mf.Related = Uint16Flags{srcEP}
			},
			printed: true,
		},
		{
			name: "--related-to destination prints event",
			configure: func(mf *MonitorFormatter) {
				mf.Related = Uint16Flags{uint16(dstEP)}
			},
			printed: true,
		},
		{
			name: "--related-to other endpoint suppresses event",
			configure: func(mf *MonitorFormatter) {
				mf.Related = Uint16Flags{other}
			},
			printed: false,
		},
		{
			name: "--type debug suppresses drop events",
			configure: func(mf *MonitorFormatter) {
				mf.EventTypes = monitorAPI.MessageTypeFilter{monitorAPI.MessageTypeDebug}
			},
			printed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			mf := NewMonitorFormatter(monitorAPI.INFO, nil, &buf)
			tt.configure(mf)

			pl := &payload.Payload{
				Data: dropNotifyPayload(srcEP, dstEP),
				CPU:  0,
				Type: payload.EventSample,
			}
			require.True(t, mf.FormatEvent(pl))

			if tt.printed {
				assert.NotEmpty(t, buf.String(), "expected event to be printed")
				assert.Contains(t, buf.String(), "drop")
				assert.Contains(t, buf.String(), "to endpoint 20")
			} else {
				assert.Empty(t, buf.String(), "expected event to be filtered out")
			}
		})
	}
}

// TestFormatLostEvent verifies that lost event notifications are always
// reported, regardless of filters.
func TestFormatLostEvent(t *testing.T) {
	var buf bytes.Buffer
	mf := NewMonitorFormatter(monitorAPI.INFO, nil, &buf)
	mf.FromSource = Uint16Flags{42} // filters must not apply to lost events

	pl := &payload.Payload{
		Lost: 7,
		CPU:  1,
		Type: payload.RecordLost,
	}
	require.True(t, mf.FormatEvent(pl))
	assert.Contains(t, buf.String(), "Lost 7 events")
}
