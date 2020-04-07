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
	"testing"

	"github.com/cilium/cilium/pkg/hubble/api/v1"

	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/stretchr/testify/assert"
)

var (
	e0 = &v1.Event{Timestamp: &timestamp.Timestamp{Seconds: 1}}
	e1 = &v1.Event{Timestamp: &timestamp.Timestamp{Seconds: 1, Nanos: 1}}
	e2 = &v1.Event{Timestamp: &timestamp.Timestamp{Seconds: 2}}
	e3 = &v1.Event{Timestamp: &timestamp.Timestamp{Seconds: 3}}
	e4 = &v1.Event{Timestamp: &timestamp.Timestamp{Seconds: 4}}
	e5 = &v1.Event{Timestamp: &timestamp.Timestamp{Seconds: 5}}
)

func TestPriorityQueue(t *testing.T) {
	pq := NewPriorityQueue(42)
	assert.Equal(t, pq.Len(), 0)

	// push some events to the queue
	pq.Push(e1)
	pq.Push(e2)

	// try poping out these 2 events, the oldest one should pop out first
	event := pq.Pop()
	assert.Equal(t, event, e1)
	event = pq.Pop()
	assert.Equal(t, event, e2)

	// calling pop on an empty priority queue should return nil
	assert.Equal(t, pq.Len(), 0)
	event = pq.Pop()
	assert.Nil(t, event)

	// let's push some events in seemingly random order
	pq.Push(e5)
	pq.Push(e3)
	pq.Push(e1)
	pq.Push(e4)
	pq.Push(e2)
	assert.Equal(t, pq.Len(), 5)

	// now, when popped out, they should pop out in chronological order
	event = pq.Pop()
	assert.Equal(t, event, e1)
	event = pq.Pop()
	assert.Equal(t, event, e2)
	event = pq.Pop()
	assert.Equal(t, event, e3)
	event = pq.Pop()
	assert.Equal(t, event, e4)
	event = pq.Pop()
	assert.Equal(t, event, e5)
	assert.Equal(t, pq.Len(), 0)
}

func TestPriorityQueue_WithEventsInTheSameSecond(t *testing.T) {
	pq := NewPriorityQueue(2)
	pq.Push(e1)
	pq.Push(e0)
	assert.Equal(t, pq.Len(), 2)
	event := pq.Pop()
	assert.Equal(t, event, e0)
	event = pq.Pop()
	assert.Equal(t, event, e1)
}

func TestPriorityQueue_WithInitialCapacity0(t *testing.T) {
	pq := NewPriorityQueue(0)
	assert.Equal(t, pq.Len(), 0)
}

func TestPriorityQueue_GrowingOverInitialCapacity(t *testing.T) {
	pq := NewPriorityQueue(1)
	assert.Equal(t, pq.Len(), 0)
	pq.Push(e1)
	pq.Push(e2)
	assert.Equal(t, pq.Len(), 2)
}
