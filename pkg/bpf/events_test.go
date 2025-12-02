// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"fmt"
	"testing"

	"github.com/cilium/hive/hivetest"

	"github.com/stretchr/testify/assert"
)

func TestEventsSubscribe(t *testing.T) {
	eb := newEventsBuffer(hivetest.Logger(t), "test", 32, 0)

	keys := []int{}
	for i := range 32 {
		eb.add(&Event{cacheEntry: cacheEntry{Key: IntTestKey(i)}})
	}

	eb.dumpAndSubscribe(t.Context(), func(e Event) {
		k := e.Key.(IntTestKey)
		keys = append(keys, int(k))
	}, true)

	eb.add(&Event{cacheEntry: cacheEntry{Key: IntTestKey(1000)}})
	eb.add(&Event{cacheEntry: cacheEntry{Key: IntTestKey(1001)}})

	assert.Len(t, keys, 34)
	assert.Equal(t, []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 1000, 1001}, keys)
}

type IntTestKey uint32

func (k IntTestKey) String() string { return fmt.Sprintf("key=%d", k) }
func (k IntTestKey) New() MapKey    { return new(IntTestKey) }
