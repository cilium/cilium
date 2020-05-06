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

package queue

import (
	"testing"

	observerpb "github.com/cilium/cilium/api/v1/observer"

	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/stretchr/testify/assert"
)

var (
	resp0 = &observerpb.GetFlowsResponse{Time: &timestamp.Timestamp{Seconds: 1}}
	resp1 = &observerpb.GetFlowsResponse{Time: &timestamp.Timestamp{Seconds: 1, Nanos: 1}}
	resp2 = &observerpb.GetFlowsResponse{Time: &timestamp.Timestamp{Seconds: 2}}
	resp3 = &observerpb.GetFlowsResponse{Time: &timestamp.Timestamp{Seconds: 3}}
	resp4 = &observerpb.GetFlowsResponse{Time: &timestamp.Timestamp{Seconds: 4}}
	resp5 = &observerpb.GetFlowsResponse{Time: &timestamp.Timestamp{Seconds: 5}}
)

func TestPriorityQueue(t *testing.T) {
	pq := NewPriorityQueue(42)
	assert.Equal(t, pq.Len(), 0)

	// push some objects to the queue
	pq.Push(resp1)
	pq.Push(resp2)

	// try poping out these 2 objects, the oldest one should pop out first
	event := pq.Pop()
	assert.Equal(t, event, resp1)
	event = pq.Pop()
	assert.Equal(t, event, resp2)

	// calling pop on an empty priority queue should return nil
	assert.Equal(t, pq.Len(), 0)
	event = pq.Pop()
	assert.Nil(t, event)

	// let's push some objects in seemingly random order
	pq.Push(resp5)
	pq.Push(resp3)
	pq.Push(resp1)
	pq.Push(resp4)
	pq.Push(resp2)
	assert.Equal(t, pq.Len(), 5)

	// now, when popped out, they should pop out in chronological order
	event = pq.Pop()
	assert.Equal(t, event, resp1)
	event = pq.Pop()
	assert.Equal(t, event, resp2)
	event = pq.Pop()
	assert.Equal(t, event, resp3)
	event = pq.Pop()
	assert.Equal(t, event, resp4)
	event = pq.Pop()
	assert.Equal(t, event, resp5)
	assert.Equal(t, pq.Len(), 0)
}

func TestPriorityQueue_WithobjectsInTheSameSecond(t *testing.T) {
	pq := NewPriorityQueue(2)
	pq.Push(resp1)
	pq.Push(resp0)
	assert.Equal(t, pq.Len(), 2)
	event := pq.Pop()
	assert.Equal(t, event, resp0)
	event = pq.Pop()
	assert.Equal(t, event, resp1)
}

func TestPriorityQueue_WithInitialCapacity0(t *testing.T) {
	pq := NewPriorityQueue(0)
	assert.Equal(t, pq.Len(), 0)
}

func TestPriorityQueue_GrowingOverInitialCapacity(t *testing.T) {
	pq := NewPriorityQueue(1)
	assert.Equal(t, pq.Len(), 0)
	pq.Push(resp1)
	pq.Push(resp2)
	assert.Equal(t, pq.Len(), 2)
}
