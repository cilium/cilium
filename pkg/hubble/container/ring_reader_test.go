// Copyright 2020 Authors of Hubble
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package container

import (
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"

	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/stretchr/testify/assert"
	"go.uber.org/goleak"
)

func TestRingReader_Previous(t *testing.T) {
	ring := NewRing(Capacity15)
	for i := 0; i < 15; i++ {
		ring.Write(&v1.Event{Timestamp: &timestamp.Timestamp{Seconds: int64(i)}})
	}
	tests := []struct {
		start   uint64
		count   int
		want    []*v1.Event
		wantErr error
	}{
		{
			start: 13,
			count: 1,
			want: []*v1.Event{
				{Timestamp: &timestamp.Timestamp{Seconds: 13}},
			},
		}, {
			start: 13,
			count: 2,
			want: []*v1.Event{
				{Timestamp: &timestamp.Timestamp{Seconds: 13}},
				{Timestamp: &timestamp.Timestamp{Seconds: 12}},
			},
		}, {
			start: 5,
			count: 5,
			want: []*v1.Event{
				{Timestamp: &timestamp.Timestamp{Seconds: 5}},
				{Timestamp: &timestamp.Timestamp{Seconds: 4}},
				{Timestamp: &timestamp.Timestamp{Seconds: 3}},
				{Timestamp: &timestamp.Timestamp{Seconds: 2}},
				{Timestamp: &timestamp.Timestamp{Seconds: 1}},
			},
		}, {
			start: 0,
			count: 1,
			want: []*v1.Event{
				{Timestamp: &timestamp.Timestamp{Seconds: 0}},
			},
		}, {
			start: 0,
			count: 1,
			want: []*v1.Event{
				{Timestamp: &timestamp.Timestamp{Seconds: 0}},
			},
		}, {
			start:   14,
			count:   1,
			wantErr: io.EOF,
		},
		{
			start:   ^uint64(0),
			count:   1,
			wantErr: ErrInvalidRead,
		},
	}
	for _, tt := range tests {
		name := fmt.Sprintf("read %d, start at position %d", tt.count, tt.start)
		t.Run(name, func(t *testing.T) {
			reader := NewRingReader(ring, tt.start)
			var got []*v1.Event
			for i := 0; i < tt.count; i++ {
				event, err := reader.Previous()
				if err != tt.wantErr {
					t.Errorf(`"%s" error = %v, wantErr %v`, name, err, tt.wantErr)
				}
				if err != nil {
					return
				}
				got = append(got, event)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRingReader_Next(t *testing.T) {
	ring := NewRing(Capacity15)
	for i := 0; i < 15; i++ {
		ring.Write(&v1.Event{Timestamp: &timestamp.Timestamp{Seconds: int64(i)}})
	}

	tests := []struct {
		start   uint64
		count   int
		want    []*v1.Event
		wantErr error
	}{
		{
			start: 0,
			count: 1,
			want: []*v1.Event{
				{Timestamp: &timestamp.Timestamp{Seconds: 0}},
			},
		}, {
			start: 0,
			count: 2,
			want: []*v1.Event{
				{Timestamp: &timestamp.Timestamp{Seconds: 0}},
				{Timestamp: &timestamp.Timestamp{Seconds: 1}},
			},
		}, {
			start: 5,
			count: 5,
			want: []*v1.Event{
				{Timestamp: &timestamp.Timestamp{Seconds: 5}},
				{Timestamp: &timestamp.Timestamp{Seconds: 6}},
				{Timestamp: &timestamp.Timestamp{Seconds: 7}},
				{Timestamp: &timestamp.Timestamp{Seconds: 8}},
				{Timestamp: &timestamp.Timestamp{Seconds: 9}},
			},
		}, {
			start: 13,
			count: 1,
			want: []*v1.Event{
				{Timestamp: &timestamp.Timestamp{Seconds: 13}},
			},
		}, {
			start:   ^uint64(0),
			count:   1,
			wantErr: ErrInvalidRead,
		}, {
			start:   14,
			count:   1,
			wantErr: io.EOF,
		},
	}
	for _, tt := range tests {
		name := fmt.Sprintf("read %d, start at position %d", tt.count, tt.start)
		t.Run(name, func(t *testing.T) {
			reader := NewRingReader(ring, tt.start)
			var got []*v1.Event
			for i := 0; i < tt.count; i++ {
				event, err := reader.Next()
				if err != tt.wantErr {
					t.Errorf(`"%s" error = %v, wantErr %v`, name, err, tt.wantErr)
				}
				if err != nil {
					return
				}
				got = append(got, event)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRingReader_NextFollow(t *testing.T) {
	defer goleak.VerifyNone(
		t,
		// ignore go routines started by the redirect we do from klog to logrus
		goleak.IgnoreTopFunction("k8s.io/klog.(*loggingT).flushDaemon"),
		goleak.IgnoreTopFunction("k8s.io/klog/v2.(*loggingT).flushDaemon"),
		goleak.IgnoreTopFunction("io.(*pipe).Read"))
	ring := NewRing(Capacity15)
	for i := 0; i < 15; i++ {
		ring.Write(&v1.Event{Timestamp: &timestamp.Timestamp{Seconds: int64(i)}})
	}

	tests := []struct {
		start       uint64
		count       int
		want        []*v1.Event
		wantTimeout bool
	}{
		{
			start: 0,
			count: 1,
			want: []*v1.Event{
				{Timestamp: &timestamp.Timestamp{Seconds: 0}},
			},
		}, {
			start: 0,
			count: 2,
			want: []*v1.Event{
				{Timestamp: &timestamp.Timestamp{Seconds: 0}},
				{Timestamp: &timestamp.Timestamp{Seconds: 1}},
			},
		}, {
			start: 5,
			count: 5,
			want: []*v1.Event{
				{Timestamp: &timestamp.Timestamp{Seconds: 5}},
				{Timestamp: &timestamp.Timestamp{Seconds: 6}},
				{Timestamp: &timestamp.Timestamp{Seconds: 7}},
				{Timestamp: &timestamp.Timestamp{Seconds: 8}},
				{Timestamp: &timestamp.Timestamp{Seconds: 9}},
			},
		}, {
			start: 13,
			count: 1,
			want: []*v1.Event{
				{Timestamp: &timestamp.Timestamp{Seconds: 13}},
			},
		}, {
			start:       14,
			count:       1,
			want:        []*v1.Event{nil},
			wantTimeout: true,
		},
	}
	for _, tt := range tests {
		name := fmt.Sprintf("read %d, start at position %d, expect timeout=%t", tt.count, tt.start, tt.wantTimeout)
		t.Run(name, func(t *testing.T) {
			reader := NewRingReader(ring, tt.start)
			var timedOut bool
			var got []*v1.Event
			for i := 0; i < tt.count; i++ {
				ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
				got = append(got, reader.NextFollow(ctx))
				select {
				case <-ctx.Done():
					timedOut = true
				default:
					assert.NotNil(t, got[i])
				}
				cancel()
			}
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.wantTimeout, timedOut)
		})
	}
}

func TestRingReader_NextFollow_WithEmptyRing(t *testing.T) {
	ring := NewRing(Capacity15)
	reader := NewRingReader(ring, ring.LastWriteParallel())
	ctx, cancel := context.WithCancel(context.Background())
	c := make(chan *v1.Event)
	go func() {
		select {
		case <-ctx.Done():
		case c <- reader.NextFollow(ctx):
		}
	}()
	select {
	case <-c:
		t.Fail()
	case <-time.After(100 * time.Millisecond):
		// the call blocked, we're good
	}
	cancel()
}
