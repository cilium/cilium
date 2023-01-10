// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package container

import (
	"container/list"
	"container/ring"
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"google.golang.org/protobuf/types/known/timestamppb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

func BenchmarkRingWrite(b *testing.B) {
	entry := &v1.Event{}
	s := NewRing(capacity(b.N))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Write(entry)
	}
}

func BenchmarkRingRead(b *testing.B) {
	entry := &v1.Event{}
	s := NewRing(capacity(b.N))
	a := make([]*v1.Event, b.N, b.N)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s.Write(entry)
	}
	b.ResetTimer()
	lastWriteIdx := s.LastWriteParallel()
	for i := 0; i < b.N; i++ {
		a[i], _ = s.read(lastWriteIdx)
		lastWriteIdx--
	}
}

func BenchmarkTimeLibListRead(b *testing.B) {
	entry := &v1.Event{}
	s := list.New()
	a := make([]*v1.Event, b.N, b.N)
	i := 0
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s.PushFront(entry)
	}
	b.ResetTimer()
	for e := s.Front(); e != nil; e = e.Next() {
		a[i], _ = e.Value.(*v1.Event)
	}
}

func BenchmarkTimeLibRingRead(b *testing.B) {
	entry := &v1.Event{}
	s := ring.New(b.N)
	a := make([]*v1.Event, b.N, b.N)
	i := 0
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Value = entry
		s.Next()
	}
	s.Do(func(e interface{}) {
		a[i], _ = e.(*v1.Event)
		i++
	})
}

func TestNewCapacity(t *testing.T) {
	// check all valid values according to the doc string
	// ie: value of n MUST satisfy n=2^i -1 for i = [1, 16]
	for i := 1; i <= 16; i++ {
		n := (1 << i) - 1
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			c, err := NewCapacity(n)
			assert.NoError(t, err)
			assert.Equal(t, capacity(n), c)
		})
	}
	// validate CapacityN constants
	capacityN := []capacity{
		Capacity1,
		Capacity3,
		Capacity7,
		Capacity15,
		Capacity31,
		Capacity63,
		Capacity127,
		Capacity255,
		Capacity511,
		Capacity1023,
		Capacity2047,
		Capacity4095,
		Capacity8191,
		Capacity16383,
		Capacity32767,
		Capacity65535,
	}
	for _, n := range capacityN {
		t.Run(fmt.Sprintf("n=Capacity%d", n.AsInt()), func(t *testing.T) {
			c, err := NewCapacity(n.AsInt())
			assert.NoError(t, err)
			assert.Equal(t, n, c)
		})
	}

	// test invalid values
	for _, n := range []int{-127, -10, 0, 2, 128, 131071} {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			c, err := NewCapacity(n)
			assert.Nil(t, c)
			assert.NotNil(t, err)
		})
	}
}

func TestNewRing(t *testing.T) {
	for i := 1; i <= 16; i++ {
		n := (1 << i) - 1
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			r := NewRing(capacity(n))
			require.NotNil(t, r)
			assert.Equal(t, uint64(0), r.Len())
			assert.Equal(t, uint64(n), r.Cap())
			// fill half the buffer
			for j := 0; j < n/2; j++ {
				r.Write(&v1.Event{})
			}
			assert.Equal(t, uint64(n/2), r.Len())
			assert.Equal(t, uint64(n), r.Cap())
			// fill the buffer to max capacity
			for j := 0; j <= n/2; j++ {
				r.Write(&v1.Event{})
			}
			assert.Equal(t, uint64(n), r.Len())
			assert.Equal(t, uint64(n), r.Cap())
			// write more events
			for j := 0; j < n; j++ {
				r.Write(&v1.Event{})
			}
			assert.Equal(t, uint64(n), r.Len())
			assert.Equal(t, uint64(n), r.Cap())
		})
	}
}

func TestRing_Read(t *testing.T) {
	type fields struct {
		mask     uint64
		cycleExp uint8
		data     []*v1.Event
		write    uint64
	}
	type args struct {
		read uint64
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *v1.Event
		wantErr error
	}{
		{
			name: "normal read for the index 7",
			fields: fields{
				mask:     0x7,
				cycleExp: 0x3, // 7+1=8=2^3
				data: []*v1.Event{
					0x0: {Timestamp: &timestamppb.Timestamp{Seconds: 0}},
					0x1: {Timestamp: &timestamppb.Timestamp{Seconds: 1}},
					0x2: {Timestamp: &timestamppb.Timestamp{Seconds: 2}},
					0x3: {Timestamp: &timestamppb.Timestamp{Seconds: 3}},
					0x4: {Timestamp: &timestamppb.Timestamp{Seconds: 4}},
					0x5: {Timestamp: &timestamppb.Timestamp{Seconds: 5}},
					0x6: {Timestamp: &timestamppb.Timestamp{Seconds: 6}},
					0x7: {Timestamp: &timestamppb.Timestamp{Seconds: 7}},
				},
				// next to be written: 0x9 (idx: 1), last written: 0x8 (idx: 0)
				write: 0x9,
			},
			args: args{
				read: 0x7,
			},
			want:    &v1.Event{Timestamp: &timestamppb.Timestamp{Seconds: 7}},
			wantErr: nil,
		},
		{
			name: "we can't read index 0 since we just wrote into it",
			fields: fields{
				mask:     0x7,
				cycleExp: 0x3, // 7+1=8=2^3
				data: []*v1.Event{
					0x0: {Timestamp: &timestamppb.Timestamp{Seconds: 0}},
					0x1: {Timestamp: &timestamppb.Timestamp{Seconds: 1}},
					0x2: {Timestamp: &timestamppb.Timestamp{Seconds: 2}},
					0x3: {Timestamp: &timestamppb.Timestamp{Seconds: 3}},
					0x4: {Timestamp: &timestamppb.Timestamp{Seconds: 4}},
					0x5: {Timestamp: &timestamppb.Timestamp{Seconds: 5}},
					0x6: {Timestamp: &timestamppb.Timestamp{Seconds: 6}},
					0x7: {Timestamp: &timestamppb.Timestamp{Seconds: 7}},
				},
				// next to be written: 0x9 (idx: 2), last written: 0x8 (idx: 0)
				write: 0x9,
			},
			args: args{
				read: 0x0,
			},
			want: &v1.Event{
				Event: &flowpb.LostEvent{
					Source:        flowpb.LostEventSource_HUBBLE_RING_BUFFER,
					NumEventsLost: 1,
					Cpu:           nil,
				},
			},
			wantErr: nil,
		},
		{
			name: "we can't read index 0x7 since we are one writing cycle ahead",
			fields: fields{
				mask:     0x7,
				cycleExp: 0x3, // 7+1=8=2^3
				data: []*v1.Event{
					0x0: {Timestamp: &timestamppb.Timestamp{Seconds: 0}},
					0x1: {Timestamp: &timestamppb.Timestamp{Seconds: 1}},
					0x2: {Timestamp: &timestamppb.Timestamp{Seconds: 2}},
					0x3: {Timestamp: &timestamppb.Timestamp{Seconds: 3}},
					0x4: {Timestamp: &timestamppb.Timestamp{Seconds: 4}},
					0x5: {Timestamp: &timestamppb.Timestamp{Seconds: 5}},
					0x6: {Timestamp: &timestamppb.Timestamp{Seconds: 6}},
					0x7: {Timestamp: &timestamppb.Timestamp{Seconds: 7}},
				},
				// next to be written: 0x10 (idx: 0), last written: 0x0f (idx: 7)
				write: 0x10,
			},
			args: args{
				// The next possible entry that we can read is 0x10-0x7-0x1 = 0x8 (idx: 0)
				read: 0x7,
			},
			want: &v1.Event{
				Event: &flowpb.LostEvent{
					Source:        flowpb.LostEventSource_HUBBLE_RING_BUFFER,
					NumEventsLost: 1,
					Cpu:           nil,
				},
			},
			wantErr: nil,
		},
		{
			name: "we can read index 0x8 since it's the last entry that we can read in this cycle",
			fields: fields{
				mask:     0x7,
				cycleExp: 0x3, // 7+1=8=2^3
				data: []*v1.Event{
					0x0: {Timestamp: &timestamppb.Timestamp{Seconds: 0}},
					0x1: {Timestamp: &timestamppb.Timestamp{Seconds: 1}},
					0x2: {Timestamp: &timestamppb.Timestamp{Seconds: 2}},
					0x3: {Timestamp: &timestamppb.Timestamp{Seconds: 3}},
					0x4: {Timestamp: &timestamppb.Timestamp{Seconds: 4}},
					0x5: {Timestamp: &timestamppb.Timestamp{Seconds: 5}},
					0x6: {Timestamp: &timestamppb.Timestamp{Seconds: 6}},
					0x7: {Timestamp: &timestamppb.Timestamp{Seconds: 7}},
				},
				// next to be written: 0x10 (idx: 0), last written: 0x0f (idx: 7)
				write: 0x10,
			},
			args: args{
				// The next possible entry that we can read is 0x10-0x7-0x1 = 0x8 (idx: 0)
				read: 0x8,
			},
			want:    &v1.Event{Timestamp: &timestamppb.Timestamp{Seconds: 0}},
			wantErr: nil,
		},
		{
			name: "we overflow write and we are trying to read the previous writes, that we can't",
			fields: fields{
				mask:     0x7,
				cycleExp: 0x3, // 7+1=8=2^3
				data: []*v1.Event{
					0x0: {Timestamp: &timestamppb.Timestamp{Seconds: 0}},
					0x1: {Timestamp: &timestamppb.Timestamp{Seconds: 1}},
					0x2: {Timestamp: &timestamppb.Timestamp{Seconds: 2}},
					0x3: {Timestamp: &timestamppb.Timestamp{Seconds: 3}},
					0x4: {Timestamp: &timestamppb.Timestamp{Seconds: 4}},
					0x5: {Timestamp: &timestamppb.Timestamp{Seconds: 5}},
					0x6: {Timestamp: &timestamppb.Timestamp{Seconds: 6}},
					0x7: {Timestamp: &timestamppb.Timestamp{Seconds: 7}},
				},
				// next to be written: 0x0 (idx: 0), last written: 0xffffffffffffffff (idx: 7)
				write: 0x0,
			},
			args: args{
				// We can't read this index because we might be still writing into it
				// next to be read: ^uint64(0) (idx: 7), last read: 0xfffffffffffffffe (idx: 6)
				read: ^uint64(0),
			},
			want: &v1.Event{
				Event: &flowpb.LostEvent{
					Source:        flowpb.LostEventSource_HUBBLE_RING_BUFFER,
					NumEventsLost: 1,
					Cpu:           nil,
				},
			},
			wantErr: nil,
		},
		{
			name: "we overflow write and we are trying to read the previous writes, that we can",
			fields: fields{
				mask:     0x7,
				cycleExp: 0x3, // 7+1=8=2^3
				data: []*v1.Event{
					0x0: {Timestamp: &timestamppb.Timestamp{Seconds: 0}},
					0x1: {Timestamp: &timestamppb.Timestamp{Seconds: 1}},
					0x2: {Timestamp: &timestamppb.Timestamp{Seconds: 2}},
					0x3: {Timestamp: &timestamppb.Timestamp{Seconds: 3}},
					0x4: {Timestamp: &timestamppb.Timestamp{Seconds: 4}},
					0x5: {Timestamp: &timestamppb.Timestamp{Seconds: 5}},
					0x6: {Timestamp: &timestamppb.Timestamp{Seconds: 6}},
					0x7: {Timestamp: &timestamppb.Timestamp{Seconds: 7}},
				},
				// next to be written: 0x1 (idx: 1), last written: 0x0 (idx: 0)
				write: 0x1,
			},
			args: args{
				// next to be read: ^uint64(0) (idx: 7), last read: 0xfffffffffffffffe (idx: 6)
				read: ^uint64(0),
			},
			want:    &v1.Event{Timestamp: &timestamppb.Timestamp{Seconds: 7}},
			wantErr: nil,
		},
		{
			name: "we overflow write and we are trying to read the 2 previously cycles",
			fields: fields{
				mask:     0x7,
				cycleExp: 0x3, // 7+1=8=2^3
				data: []*v1.Event{
					0x0: {Timestamp: &timestamppb.Timestamp{Seconds: 0}},
					0x1: {Timestamp: &timestamppb.Timestamp{Seconds: 1}},
					0x2: {Timestamp: &timestamppb.Timestamp{Seconds: 2}},
					0x3: {Timestamp: &timestamppb.Timestamp{Seconds: 3}},
					0x4: {Timestamp: &timestamppb.Timestamp{Seconds: 4}},
					0x5: {Timestamp: &timestamppb.Timestamp{Seconds: 5}},
					0x6: {Timestamp: &timestamppb.Timestamp{Seconds: 6}},
					0x7: {Timestamp: &timestamppb.Timestamp{Seconds: 7}},
				},
				// next to be written: 0x8 (idx: 1), last written: 0xffffffffffffffff (idx: 7)
				write: 0x8,
			},
			args: args{
				// next to be read: ^uint64(0)-0x7 (idx: 0), last read: 0xfffffffffffffff7 (idx: 7)
				// read is: ^uint64(0)-0x7 which should represent index 0x0 but
				// with a cycle that was already overwritten
				read: ^uint64(0) - 0x7,
			},
			want: &v1.Event{
				Event: &flowpb.LostEvent{
					Source:        flowpb.LostEventSource_HUBBLE_RING_BUFFER,
					NumEventsLost: 1,
					Cpu:           nil,
				},
			},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Ring{
				mask:      tt.fields.mask,
				data:      tt.fields.data,
				write:     tt.fields.write,
				dataLen:   uint64(len(tt.fields.data)),
				cycleExp:  tt.fields.cycleExp,
				cycleMask: ^uint64(0) >> tt.fields.cycleExp,
			}
			got, got1 := r.read(tt.args.read)
			if tt.want.GetLostEvent() != nil {
				assert.NotNil(t, got)
				assert.NotNil(t, got.GetLostEvent())
				if diff := cmp.Diff(tt.want.GetLostEvent(), got.GetLostEvent(), cmpopts.IgnoreUnexported(flowpb.LostEvent{})); diff != "" {
					t.Errorf("LostEvent mismatch (-want +got):\n%s", diff)
				}
			} else {
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("Ring.read() got = %v, want %v", got, tt.want)
				}
			}
			if !errors.Is(got1, tt.wantErr) {
				t.Errorf("Ring.read() got1 = %v, want %v", got1, tt.wantErr)
			}
		})
	}
}

func TestRing_Write(t *testing.T) {
	type fields struct {
		len   uint64
		data  []*v1.Event
		write uint64
	}
	type args struct {
		event *v1.Event
	}
	tests := []struct {
		name   string
		fields fields
		want   fields
		args   args
	}{
		{
			name: "normal write",
			args: args{
				event: &v1.Event{Timestamp: &timestamppb.Timestamp{Seconds: 5}},
			},
			fields: fields{
				len:   0x3,
				write: 0,
				data: []*v1.Event{
					0x0: {Timestamp: &timestamppb.Timestamp{Seconds: 0}},
					0x1: {Timestamp: &timestamppb.Timestamp{Seconds: 1}},
					0x2: {Timestamp: &timestamppb.Timestamp{Seconds: 2}},
					0x3: {Timestamp: &timestamppb.Timestamp{Seconds: 3}},
				},
			},
			want: fields{
				len:   0x3,
				write: 1,
				data: []*v1.Event{
					{Timestamp: &timestamppb.Timestamp{Seconds: 5}},
					{Timestamp: &timestamppb.Timestamp{Seconds: 1}},
					{Timestamp: &timestamppb.Timestamp{Seconds: 2}},
					{Timestamp: &timestamppb.Timestamp{Seconds: 3}},
				},
			},
		},
		{
			name: "overflow write",
			args: args{
				event: &v1.Event{Timestamp: &timestamppb.Timestamp{Seconds: 5}},
			},
			fields: fields{
				len:   0x3,
				write: ^uint64(0),
				data: []*v1.Event{
					{Timestamp: &timestamppb.Timestamp{Seconds: 0}},
					{Timestamp: &timestamppb.Timestamp{Seconds: 1}},
					{Timestamp: &timestamppb.Timestamp{Seconds: 2}},
					{Timestamp: &timestamppb.Timestamp{Seconds: 3}},
				},
			},
			want: fields{
				len:   0x3,
				write: 0,
				data: []*v1.Event{
					{Timestamp: &timestamppb.Timestamp{Seconds: 0}},
					{Timestamp: &timestamppb.Timestamp{Seconds: 1}},
					{Timestamp: &timestamppb.Timestamp{Seconds: 2}},
					{Timestamp: &timestamppb.Timestamp{Seconds: 5}},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Ring{
				mask:  tt.fields.len,
				data:  tt.fields.data,
				write: tt.fields.write,
			}
			r.Write(tt.args.event)
			want := &Ring{
				mask:  tt.want.len,
				data:  tt.want.data,
				write: tt.want.write,
			}
			reflect.DeepEqual(want, r)
		})
	}
}

func TestRing_LastWriteParallel(t *testing.T) {
	type fields struct {
		len   uint64
		data  []*v1.Event
		write uint64
	}
	tests := []struct {
		name   string
		fields fields
		want   uint64
	}{
		{
			fields: fields{
				len:   0x3,
				write: 2,
				data:  []*v1.Event{},
			},
			want: 0,
		},
		{
			fields: fields{
				len:   0x3,
				write: 1,
				data:  []*v1.Event{},
			},
			want: ^uint64(0),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Ring{
				mask:  tt.fields.len,
				data:  tt.fields.data,
				write: tt.fields.write,
			}
			if got := r.LastWriteParallel(); got != tt.want {
				t.Errorf("Ring.LastWriteParallel() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRing_LastWrite(t *testing.T) {
	type fields struct {
		len   uint64
		data  []*v1.Event
		write uint64
	}
	tests := []struct {
		name   string
		fields fields
		want   uint64
	}{
		{
			fields: fields{
				len:   0x3,
				write: 1,
				data:  []*v1.Event{},
			},
			want: 0,
		},
		{
			fields: fields{
				len:   0x3,
				write: 0,
				data:  []*v1.Event{},
			},
			want: ^uint64(0),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Ring{
				mask:  tt.fields.len,
				data:  tt.fields.data,
				write: tt.fields.write,
			}
			if got := r.LastWrite(); got != tt.want {
				t.Errorf("Ring.LastWrite() = %v, want %v", got, tt.want)
			}
		})
	}
}
func TestRingOldestWrite(t *testing.T) {
	r := NewRing(Capacity3)

	oldestWrite := r.OldestWrite()
	entry, err := r.read(oldestWrite)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if entry.GetLostEvent() == nil {
		t.Errorf("able to read oldest entry without prior write: %s", entry)
	}

	r.Write(&v1.Event{Timestamp: &timestamppb.Timestamp{Seconds: 0}})
	r.Write(&v1.Event{Timestamp: &timestamppb.Timestamp{Seconds: 1}})
	r.Write(&v1.Event{Timestamp: &timestamppb.Timestamp{Seconds: 2}})
	r.Write(&v1.Event{Timestamp: &timestamppb.Timestamp{Seconds: 3}})

	oldestWrite = r.OldestWrite()
	entry, err = r.read(oldestWrite)
	if err != nil {
		t.Errorf("Should be able to read position %x, got %v", oldestWrite, err)
	}
	if entry.Timestamp.Seconds != int64(0) {
		t.Errorf("Read Event should be %+v, got %+v instead (%s)", &timestamppb.Timestamp{Seconds: 0}, entry.Timestamp, entry)
	}

	// this will trigger a wrap-around and overwrite entry 0
	r.Write(&v1.Event{Timestamp: &timestamppb.Timestamp{Seconds: 4}})

	// the previous oldest entry should now be overwritten
	entry, err = r.read(oldestWrite)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if entry.GetLostEvent() == nil {
		t.Errorf("able to read oldest entry even though it has been overwritten: %s", entry)
	}

	// new oldest entry should have timestamp 1
	oldestWrite = r.OldestWrite()
	entry, err = r.read(oldestWrite)
	if err != nil {
		t.Errorf("Should be able to read position %x, got %v", oldestWrite, err)
	}
	if entry.Timestamp.Seconds != int64(1) {
		t.Errorf("Read Event should be %+v, got %+v instead (%s)", &timestamppb.Timestamp{Seconds: 1}, entry.Timestamp, entry)
	}
}

func TestRingFunctionalityInParallel(t *testing.T) {
	r := NewRing(Capacity15)
	if len(r.data) != 0x10 {
		t.Errorf("r.data should have a length of 0x10. Got %x", len(r.data))
	}
	if r.mask != 0xf {
		t.Errorf("r.mask should be 0xf. Got %x", r.mask)
	}
	if r.cycleExp != 4 {
		t.Errorf("r.cycleExp should be 4. Got %x", r.cycleExp)
	}
	if r.cycleMask != 0xfffffffffffffff {
		t.Errorf("r.cycleMask should be 0xfffffffffffffff. Got %x", r.cycleMask)
	}
	lastWrite := r.LastWriteParallel()
	if lastWrite != ^uint64(0)-1 {
		t.Errorf("lastWrite should be %x. Got %x", ^uint64(0)-1, lastWrite)
	}

	r.Write(&v1.Event{Timestamp: &timestamppb.Timestamp{Seconds: 0}})
	lastWrite = r.LastWriteParallel()
	if lastWrite != ^uint64(0) {
		t.Errorf("lastWrite should be %x. Got %x", ^uint64(0), lastWrite)
	}

	r.Write(&v1.Event{Timestamp: &timestamppb.Timestamp{Seconds: 1}})
	lastWrite = r.LastWriteParallel()
	if lastWrite != 0x0 {
		t.Errorf("lastWrite should be 0x0. Got %x", lastWrite)
	}

	entry, err := r.read(lastWrite)
	if err != nil {
		t.Errorf("Should be able to read position %x, got %v", lastWrite, err)
	}
	if entry.Timestamp.Seconds != int64(0) {
		t.Errorf("Read Event should be %+v, got %+v instead", &timestamppb.Timestamp{Seconds: 0}, entry.Timestamp)
	}
	lastWrite--
	lost, _ := r.read(lastWrite)
	if lost.GetLostEvent() == nil {
		t.Errorf("Should not be able to read position %x, got %v", lastWrite, lost)
	}
}

func TestRingFunctionalitySerialized(t *testing.T) {
	r := NewRing(Capacity15)
	if len(r.data) != 0x10 {
		t.Errorf("r.data should have a length of 0x10. Got %x", len(r.data))
	}
	if r.mask != 0xf {
		t.Errorf("r.mask should be 0xf. Got %x", r.mask)
	}
	lastWrite := r.LastWrite()
	if lastWrite != ^uint64(0) {
		t.Errorf("lastWrite should be %x. Got %x", ^uint64(0)-1, lastWrite)
	}

	r.Write(&v1.Event{Timestamp: &timestamppb.Timestamp{Seconds: 0}})
	lastWrite = r.LastWrite()
	if lastWrite != 0x0 {
		t.Errorf("lastWrite should be %x. Got %x", 0x0, lastWrite)
	}

	r.Write(&v1.Event{Timestamp: &timestamppb.Timestamp{Seconds: 1}})
	lastWrite = r.LastWrite()
	if lastWrite != 0x1 {
		t.Errorf("lastWrite should be 0x1. Got %x", lastWrite)
	}

	_, err := r.read(lastWrite)
	if err != io.EOF {
		t.Errorf("Should not be able to read position %x, got %v", lastWrite, err)
	}
	lastWrite--
	entry, err := r.read(lastWrite)
	if err != nil {
		t.Errorf("Should be able to read position %x, got %v", lastWrite, err)
	}
	if entry.Timestamp.Seconds != int64(0) {
		t.Errorf("Read Event should be %+v, got %+v instead", &timestamppb.Timestamp{Seconds: 0}, entry.Timestamp)
	}
}

func TestRing_ReadFrom_Test_1(t *testing.T) {
	defer goleak.VerifyNone(
		t,
		// ignore goroutines started by the redirect we do from klog to logrus
		goleak.IgnoreTopFunction("k8s.io/klog.(*loggingT).flushDaemon"),
		goleak.IgnoreTopFunction("k8s.io/klog/v2.(*loggingT).flushDaemon"),
		goleak.IgnoreTopFunction("io.(*pipe).read"))
	r := NewRing(Capacity15)
	if len(r.data) != 0x10 {
		t.Errorf("r.data should have a length of 0x10. Got %x", len(r.data))
	}
	if r.dataLen != 0x10 {
		t.Errorf("r.dataLen should have a length of 0x10. Got %x", r.dataLen)
	}
	if r.mask != 0xf {
		t.Errorf("r.mask should be 0xf. Got %x", r.mask)
	}
	lastWrite := r.LastWrite()
	if lastWrite != ^uint64(0) {
		t.Errorf("lastWrite should be %x. Got %x", ^uint64(0)-1, lastWrite)
	}

	// Add 5 events
	for i := uint64(0); i < 5; i++ {
		r.Write(&v1.Event{Timestamp: &timestamppb.Timestamp{Seconds: int64(i)}})
		lastWrite = r.LastWrite()
		if lastWrite != i {
			t.Errorf("lastWrite should be %x. Got %x", i, lastWrite)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan *v1.Event, 30)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		r.readFrom(ctx, 0, ch)
		wg.Done()
	}()
	i := int64(0)
	for entry := range ch {
		require.NotNil(t, entry)
		want := &timestamppb.Timestamp{Seconds: i}
		if entry.Timestamp.Seconds != want.Seconds {
			t.Errorf("Read Event should be %+v, got %+v instead", want, entry.Timestamp)
		}
		i++
		if i == 4 {
			break
		}
	}
	// next read must be blocked, since ring was not full
	select {
	case entry := <-ch:
		t.Errorf("Read Event %v received when channel should be empty", entry)
	default:
	}
	cancel()
	wg.Wait()
}

func TestRing_ReadFrom_Test_2(t *testing.T) {
	defer goleak.VerifyNone(
		t,
		// ignore goroutines started by the redirect we do from klog to logrus
		goleak.IgnoreTopFunction("k8s.io/klog.(*loggingT).flushDaemon"),
		goleak.IgnoreTopFunction("k8s.io/klog/v2.(*loggingT).flushDaemon"),
		goleak.IgnoreTopFunction("io.(*pipe).read"))

	r := NewRing(Capacity15)
	if len(r.data) != 0x10 {
		t.Errorf("r.data should have a length of 0x10. Got %x", len(r.data))
	}
	if r.dataLen != 0x10 {
		t.Errorf("r.dataLen should have a length of 0x10. Got %x", r.dataLen)
	}
	if r.mask != 0xf {
		t.Errorf("r.mask should be 0xf. Got %x", r.mask)
	}
	lastWrite := r.LastWrite()
	if lastWrite != ^uint64(0) {
		t.Errorf("lastWrite should be %x. Got %x", ^uint64(0)-1, lastWrite)
	}

	// Add 20 events
	for i := uint64(0); i < 20; i++ {
		r.Write(&v1.Event{Timestamp: &timestamppb.Timestamp{Seconds: int64(i)}})
		lastWrite = r.LastWrite()
		if lastWrite != i {
			t.Errorf("lastWrite should be %x. Got %x", i, lastWrite)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	// We should be able to read from a previous 'cycles' and ReadFrom will
	// be able to catch up with the writer.
	ch := make(chan *v1.Event, 30)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		r.readFrom(ctx, 1, ch)
	}()
	i := int64(1) // ReadFrom
	for event := range ch {
		require.NotNil(t, event)
		// Given the buffer length is 16 and there are no more writes being made,
		// we will receive 15 non-nil events, after that the channel must stall.
		//
		//   ReadFrom +           +----------------valid read------------+  +position possibly being written
		//            |           |                                      |  |  +next position to be written (r.write)
		//            v           V                                      V  V  V
		// write:  0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
		// index:  0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f  0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
		// cycle:  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  1  1  1  1  1  1  1  1  1  1  1  1  1  1  1  1
		switch {
		case i < 4:
			want := &flowpb.LostEvent{
				Source:        flowpb.LostEventSource_HUBBLE_RING_BUFFER,
				NumEventsLost: 1,
				Cpu:           nil,
			}
			if diff := cmp.Diff(want, event.GetLostEvent(), cmpopts.IgnoreUnexported(flowpb.LostEvent{})); diff != "" {
				t.Errorf("LostEvent mismatch (-want +got):\n%s", diff)
			}
		default:
			want := &timestamppb.Timestamp{Seconds: i}
			if diff := cmp.Diff(want, event.Timestamp, cmpopts.IgnoreUnexported(timestamppb.Timestamp{})); diff != "" {
				t.Errorf("Event timestamp mismatch (-want +got):\n%s", diff)
			}
		}
		if i == 18 {
			break
		}
		i++
	}
	// next read must be blocked, since reader is waiting for the writer
	select {
	case entry := <-ch:
		t.Errorf("Read Event %v received when channel should be empty", entry)
	default:
	}

	// Add 20 more events that we read back immediately
	for i := uint64(0); i < 20; i++ {
		r.Write(&v1.Event{Timestamp: &timestamppb.Timestamp{Seconds: int64(20 + i)}})

		want := &timestamppb.Timestamp{Seconds: int64(20 + (i - 1))}
		entry, ok := <-ch
		if !ok {
			t.Errorf("Channel was have been closed, expected %+v", entry)
		}
		if entry.Timestamp.Seconds != want.Seconds {
			t.Errorf("Read Event should be %+v, got %+v instead", want, entry.Timestamp)
		}
	}
	cancel()
	wg.Wait()
}

func TestRing_ReadFrom_Test_3(t *testing.T) {
	defer goleak.VerifyNone(
		t,
		// ignore goroutines started by the redirect we do from klog to logrus
		goleak.IgnoreTopFunction("k8s.io/klog.(*loggingT).flushDaemon"),
		goleak.IgnoreTopFunction("k8s.io/klog/v2.(*loggingT).flushDaemon"),
		goleak.IgnoreTopFunction("io.(*pipe).read"))
	r := NewRing(Capacity15)
	if len(r.data) != 0x10 {
		t.Errorf("r.data should have a length of 0x10. Got %x", len(r.data))
	}
	if r.dataLen != 0x10 {
		t.Errorf("r.dataLen should have a length of 0x10. Got %x", r.dataLen)
	}
	if r.mask != 0xf {
		t.Errorf("r.mask should be 0xf. Got %x", r.mask)
	}
	lastWrite := r.LastWrite()
	if lastWrite != ^uint64(0) {
		t.Errorf("lastWrite should be %x. Got %x", ^uint64(0)-1, lastWrite)
	}

	// Add 20 events
	for i := uint64(0); i < 20; i++ {
		r.Write(&v1.Event{Timestamp: &timestamppb.Timestamp{Seconds: int64(i)}})
		lastWrite = r.LastWrite()
		if lastWrite != i {
			t.Errorf("lastWrite should be %x. Got %x", i, lastWrite)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	// We should be able to read from a previous 'cycles' and ReadFrom will
	// be able to catch up with the writer.
	ch := make(chan *v1.Event, 30)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		r.readFrom(ctx, ^uint64(0)-15, ch)
		wg.Done()
	}()
	i := ^uint64(0) - 15
	for entry := range ch {
		require.NotNil(t, entry)
		// Given the buffer length is 16 and there are no more writes being made,
		// we will receive 15 non-nil events, after that the channel must stall.
		//
		//   ReadFrom +        +-------------------valid read------------+  +position possibly being written
		//            |        |                                         |  |  +next position to be written (r.write)
		//            v        V                                         V  V  V
		// write: f0 f1 //  3  4  5  6  7  8  9  a  b  c  d  e  f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
		// index:  0  1 //  3  4  5  6  7  8  9  a  b  c  d  e  f  0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
		// cycle: ff ff //  0  0  0  0  0  0  0  0  0  0  0  0  0  1  1  1  1  1  1  1  1  1  1  1  1  1  1  1  1
		switch {
		case i < 4, i > 18:
			want := &flowpb.LostEvent{
				Source:        flowpb.LostEventSource_HUBBLE_RING_BUFFER,
				NumEventsLost: 1,
				Cpu:           nil,
			}
			if diff := cmp.Diff(want, entry.GetLostEvent(), cmpopts.IgnoreUnexported(flowpb.LostEvent{})); diff != "" {
				t.Errorf("%d LostEvent mismatch (-want +got):\n%s", i, diff)
			}
		default:
			want := &timestamppb.Timestamp{Seconds: int64(i)}
			if diff := cmp.Diff(want, entry.Timestamp, cmpopts.IgnoreUnexported(timestamppb.Timestamp{})); diff != "" {
				t.Errorf("Event timestamp mismatch (-want +got):\n%s", diff)
			}
		}
		if i == 18 {
			break
		}
		i++
	}
	// next read must be blocked, since reader is waiting for the writer
	select {
	case entry := <-ch:
		t.Errorf("Read Event %v received when channel should be empty", entry)
	default:
	}

	// Add 20 more events that we read back immediately
	for i := uint64(0); i < 20; i++ {
		r.Write(&v1.Event{Timestamp: &timestamppb.Timestamp{Seconds: int64(20 + i)}})

		want := &timestamppb.Timestamp{Seconds: int64(20 + (i - 1))}
		entry, ok := <-ch
		if !ok {
			t.Errorf("Channel was have been closed, expected %+v", entry)
		}
		if entry.Timestamp.Seconds != want.Seconds {
			t.Errorf("Read Event should be %+v, got %+v instead", want, entry.Timestamp)
		}
	}
	cancel()
	wg.Wait()
}
