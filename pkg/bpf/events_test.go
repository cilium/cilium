// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"fmt"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/container"
)

func TestEventsSubscribe(t *testing.T) {
	assert := assert.New(t)
	eb := &eventsBuffer{
		buffer:   container.NewRingBuffer(0),
		eventTTL: time.Second,
	}
	handle, err := eb.dumpAndSubscribe(nil, true)
	assert.NoError(err)

	// should not block, buffer not full.
	eb.add(&Event{cacheEntry: cacheEntry{Key: IntTestKey(123)}})
	eb.add(&Event{cacheEntry: cacheEntry{Key: IntTestKey(124)}})
	eb.add(&Event{cacheEntry: cacheEntry{Key: IntTestKey(125)}})
	assert.Equal("key=123", (<-handle.C()).Key.String())
	assert.Equal("key=124", (<-handle.C()).Key.String())

	for i := 0; i < eventSubChanBufferSize; i++ {
		assert.False(handle.isClosed(), "should not close until buffer is full")
		assert.Len(eb.subscriptions, 1)
		assert.Len(eb.subscriptions[0].c, i+1)
		eb.add(&Event{cacheEntry: cacheEntry{Key: IntTestKey(i)}})
	}
	time.Sleep(time.Millisecond * 20)
	assert.True(handle.isClosed(), "after filling buffer, should be closed")
	assert.Len(eb.subscriptions, 0)

	handle, err = eb.dumpAndSubscribe(nil, true)
	assert.NoError(err)
	assert.False(handle.isClosed())
	handle.Close()
	handle.Close()
	assert.True(handle.isClosed(), "after calling close, should be closed")
	assert.Equal(0, eb.buffer.Size())
}

type IntTestKey uint32

func (k IntTestKey) String() string            { return fmt.Sprintf("key=%d", k) }
func (k IntTestKey) GetKeyPtr() unsafe.Pointer { panic("not impl") }
func (k IntTestKey) NewValue() MapValue        { panic("not impl") }
func (k IntTestKey) DeepCopyMapKey() MapKey    { panic("not impl") }
