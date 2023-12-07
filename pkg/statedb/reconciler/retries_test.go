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
	objectToKey := func(o any) []byte {
		return index.Uint64(o.(uint64))
	}
	rq := newRetries(time.Millisecond, time.Millisecond, objectToKey)

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

	// Retry 'obj3'
	rq.Add(obj3)

	<-rq.Wait()
	obj, retryAt, ok = rq.Top()
	if assert.True(t, ok) {
		rq.Pop()
		rq.Clear(obj)
		assert.True(t, retryAt.Before(time.Now()), "expected item to be expired")
		assert.Equal(t, obj, obj3)
	}

	_, _, ok = rq.Top()
	assert.False(t, ok)
}
