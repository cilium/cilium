// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nat

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/types"
)

func TestFlushNat(t *testing.T) {
	testutils.PrivilegedTest(t)

	numEntries := 5
	v4NatMap := NewMap(nil, "test_nap_v4", IPv4, 1000)
	err := v4NatMap.OpenOrCreate()
	assert.NoError(t, err)
	v6NatMap := NewMap(nil, "test_nat_v6", IPv6, 1000)
	err = v6NatMap.OpenOrCreate()
	assert.NoError(t, err)
	t.Cleanup(func() {
		v4NatMap.UnpinIfExists()
		v6NatMap.UnpinIfExists()
	})

	// Populate the map with dummy entries
	for i := 1; i <= numEntries; i++ {
		mapKey := &NatKey4{}
		ip := types.IPv4{192, 168, 0, byte(i)}
		mapKey.TupleKey4.SourceAddr = ip
		mapKey.TupleKey4.DestAddr = [4]byte{}
		mapKey.TupleKey4.DestPort = 8000 + uint16(i)
		err := v4NatMap.Update(mapKey, &NatEntry4{})
		assert.NoError(t, err, "failed to insert NAT entry")

		ip6 := types.IPv6{}
		ip6[15] = byte(i)
		mapKey6 := &NatKey6{}
		mapKey6.TupleKey6.SourceAddr = ip6
		mapKey6.TupleKey6.DestAddr = [16]byte{}
		mapKey6.TupleKey6.DestPort = 8000 + uint16(i)
		err = v6NatMap.Update(mapKey6.ToNetwork(), &NatEntry6{})
		assert.NoError(t, err)
	}

	// Verify entry count before flush.
	var count int
	assert.NoError(t, v4NatMap.DumpWithCallback(func(_ bpf.MapKey, _ bpf.MapValue) { count++ }))
	assert.Equal(t, numEntries, count)
	// Verify entry count after flush.
	deleted := v4NatMap.Flush()
	assert.Equal(t, numEntries, deleted)
	// Confirm the map is empty after flush.
	count = 0
	assert.NoError(t, v4NatMap.DumpWithCallback(func(_ bpf.MapKey, _ bpf.MapValue) { count++ }))
	assert.Equal(t, 0, count)

	assert.NoError(t, v6NatMap.DumpWithCallback(func(_ bpf.MapKey, _ bpf.MapValue) { count++ }))
	assert.Equal(t, numEntries, count)
	deleted = v6NatMap.Flush()
	assert.Equal(t, numEntries, deleted)
	count = 0
	assert.NoError(t, v6NatMap.DumpWithCallback(func(_ bpf.MapKey, _ bpf.MapValue) { count++ }))
	assert.Equal(t, 0, count)
}
