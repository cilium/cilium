// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package wal

import (
	"bytes"
	"fmt"
	"io"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
)

type TestEvent struct {
	ID   byte
	Data []byte
}

func (e *TestEvent) MarshalBinary() ([]byte, error) {
	var buf []byte
	buf = append(buf, e.ID)
	buf = append(buf, []byte(e.Data)...)
	return buf, nil
}

func (e *TestEvent) UnmarshalBinary(data []byte) error {
	if len(data) < 1 {
		return fmt.Errorf("data too short")
	}
	e.ID = data[0]
	e.Data = data[1:]
	return nil
}

func UnmarshalTestEvent(data []byte) (*TestEvent, error) {
	var e TestEvent
	if err := e.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return &e, nil
}

func TestHappyPath(t *testing.T) {
	logPath := t.TempDir() + "/test.wal"

	w, err := NewWriter[*TestEvent](logPath)
	if err != nil {
		t.Fatalf("failed to create WAL: %v", err)
	}

	events := []*TestEvent{
		{ID: 1, Data: []byte("event1")},
		{ID: 2, Data: []byte("event2")},
		{ID: 3, Data: []byte("event3")},
	}

	for _, event := range events {
		if err := w.Write(event); err != nil {
			t.Fatalf("failed to write event: %v", err)
		}
	}

	if err := w.Close(); err != nil {
		t.Fatalf("failed to close WAL: %v", err)
	}

	iter, err := Read(logPath, UnmarshalTestEvent)
	if err != nil {
		t.Fatalf("failed to read WAL: %v", err)
	}

	var readEvents []*TestEvent
	for e, err := range iter {
		if err != nil {
			t.Fatalf("failed to read event: %v", err)
		}
		readEvents = append(readEvents, e)
	}
	assert.Equal(t, events, readEvents, "read events do not match written events")
}

type TestEventV2 struct {
	Delete bool
	Key    byte
	Data   []byte
}

func (e *TestEventV2) MarshalBinary() ([]byte, error) {
	var buf []byte
	if e.Delete {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}
	buf = append(buf, e.Key)
	buf = append(buf, []byte(e.Data)...)
	return buf, nil
}

func (e *TestEventV2) UnmarshalBinary(data []byte) error {
	if len(data) < 2 {
		return fmt.Errorf("data too short")
	}
	if data[0] == 1 {
		e.Delete = true
	} else {
		e.Delete = false
	}
	e.Key = data[1]
	e.Data = data[2:]
	return nil
}

func UnmarshalTestEventV2(data []byte) (*TestEventV2, error) {
	var e TestEventV2
	if err := e.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return &e, nil
}

func TestCompact(t *testing.T) {
	logPath := t.TempDir() + "/test.wal"

	w, err := NewWriter[*TestEventV2](logPath)
	if err != nil {
		t.Fatalf("failed to create WAL: %v", err)
	}

	events := []*TestEventV2{
		{Delete: false, Key: 1, Data: []byte("value1-abc")},
		{Delete: false, Key: 2, Data: []byte("value2-abc")},
		{Delete: false, Key: 1, Data: []byte("value1-def")},
		{Delete: true, Key: 2},
		{Delete: false, Key: 3, Data: []byte("value3-ghi")},
	}

	for _, event := range events {
		if err := w.Write(event); err != nil {
			t.Fatalf("failed to write event: %v", err)
		}
	}

	postCompEvents := []*TestEventV2{
		{Delete: false, Key: 1, Data: []byte("value1-def")},
		{Delete: false, Key: 3, Data: []byte("value3-ghi")},
	}
	if err := w.Compact(func(yield func(*TestEventV2) bool) {
		for _, e := range postCompEvents {
			if !yield(e) {
				break
			}
		}
	}); err != nil {
		t.Fatalf("failed to compact WAL: %v", err)
	}

	err = w.Write(&TestEventV2{Delete: false, Key: 4, Data: []byte("value4-jkl")})
	assert.NoError(t, err, "failed to write event after compaction")

	if err := w.Close(); err != nil {
		t.Fatalf("failed to close WAL: %v", err)
	}

	iter, err := Read(logPath, UnmarshalTestEventV2)
	if err != nil {
		t.Fatalf("failed to read WAL: %v", err)
	}

	var readEvents []*TestEventV2
	for e, err := range iter {
		if err != nil {
			t.Fatalf("failed to read event: %v", err)
		}
		readEvents = append(readEvents, e)
	}

	expectedEvents := []*TestEventV2{
		{Delete: false, Key: 1, Data: []byte("value1-def")},
		{Delete: false, Key: 3, Data: []byte("value3-ghi")},
		{Delete: false, Key: 4, Data: []byte("value4-jkl")},
	}
	assert.Equal(t, expectedEvents, readEvents, "read events do not match compacted events")
}

type SmallReadsReader struct {
	data []byte
}

func (r *SmallReadsReader) Read(p []byte) (int, error) {
	l := min(len(p), 8, len(r.data))

	copy(p, r.data[:l])
	r.data = r.data[l:]
	if len(r.data) == 0 {
		return l, io.EOF
	}
	return l, nil
}

func TestLVReaderWriter(t *testing.T) {
	var buf bytes.Buffer

	msgs := [][]byte{
		[]byte("hello"),
		[]byte("world"),
		[]byte("this is a test"),
	}

	w := &lvWriter{w: &buf}
	for _, msg := range msgs {
		if err := w.Write(msg); err != nil {
			t.Fatalf("failed to write data: %v", err)
		}
	}

	reader := &SmallReadsReader{data: buf.Bytes()}
	lvReader := &lvReader{r: reader}
	readMsgs := slices.Collect(lvReader.Events())
	assert.Equal(t, msgs, readMsgs, "read messages do not match written messages")
}
