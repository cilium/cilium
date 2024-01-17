// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/statedb/index"
)

func TestRetries(t *testing.T) {
	objectToKey := func(o any) index.Key {
		return index.Uint64(o.(uint64))
	}
	rq := newRetries(time.Millisecond, 100*time.Millisecond, objectToKey)

	obj1, obj2, obj3 := uint64(1), uint64(2), uint64(3)

	// Add objects to be retried in order. We assume here that 'time.Time' has
	// enough granularity for these to be added with rising retryAt times.
	rq.Add(obj1)
	rq.Add(obj2)
	rq.Add(obj3)

	<-rq.Wait()
	obj, retryAt, ok := rq.Top()
	if assert.True(t, ok) {
		rq.Pop()
		rq.Clear(obj)
		assert.True(t, retryAt.Before(time.Now()), "expected item to be expired")
		assert.Equal(t, obj, obj1)
	}

	<-rq.Wait()
	obj, retryAt, ok = rq.Top()
	if assert.True(t, ok) {
		rq.Pop()
		rq.Clear(obj)
		assert.True(t, retryAt.Before(time.Now()), "expected item to be expired")
		assert.Equal(t, obj, obj2)
	}

	<-rq.Wait()
	obj, retryAt, ok = rq.Top()
	if assert.True(t, ok) {
		rq.Pop()
		assert.True(t, retryAt.Before(time.Now()), "expected item to be expired")
		assert.Equal(t, obj, obj3)
	}

	// Retry 'obj3' and since it was added back without clearing it'll be retried
	// later. Add obj1 and check that 'obj3' has later retry time.
	rq.Add(obj3)
	rq.Add(obj1)

	<-rq.Wait()
	obj, retryAt1, ok := rq.Top()
	if assert.True(t, ok) {
		rq.Pop()
		rq.Clear(obj)
		assert.True(t, retryAt.Before(time.Now()), "expected item to be expired")
		assert.Equal(t, obj, obj1)
	}

	<-rq.Wait()
	obj, retryAt, ok = rq.Top()
	if assert.True(t, ok) {
		rq.Pop()
		rq.Clear(obj)
		assert.True(t, retryAt1.Before(retryAt), "expected obj1 before obj3")
		assert.True(t, retryAt.Before(time.Now()), "expected item to be expired")
		assert.Equal(t, obj, obj3)
	}

	_, _, ok = rq.Top()
	assert.False(t, ok)

	// Test that object can be cleared from the queue without popping it.
	rq.Add(obj1)
	rq.Add(obj2)
	rq.Add(obj3)
	rq.Clear(obj1) // Remove obj1, testing that it'll fix the queue correctly.
	rq.Pop()       // Pop and remove obj2 and clear it to test that Clear doesn't mess with queue
	rq.Clear(obj2)
	obj, _, ok = rq.Top()
	if assert.True(t, ok) {
		rq.Pop()
		rq.Clear(obj)
		assert.Equal(t, obj, obj3)
	}
	_, _, ok = rq.Top()
	assert.False(t, ok)

}
