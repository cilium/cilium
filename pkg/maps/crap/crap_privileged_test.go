// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package crap

import (
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestPrivilegedCrapMap(t *testing.T) {
	testutils.PrivilegedTest(t)

	logger := hivetest.Logger(t)
	bpf.CheckOrMountFS(logger, "")
	require.NoError(t, rlimit.RemoveMemlock())

	crapMap := CreatePrivatePolicyMap(hivetest.Lifecycle(t), nil)

	dstIP1 := netip.MustParseAddr("1.1.1.1")
	dstIP2 := netip.MustParseAddr("2.2.2.2")
	podIP1 := netip.MustParseAddr("10.0.0.1")
	podIP2 := netip.MustParseAddr("10.0.0.2")

	require.NoError(t, crapMap.UpdateCrapMapping(dstIP1, podIP1))
	require.NoError(t, crapMap.Update(NewKey(dstIP2), NewVal(podIP2)))

	val, err := crapMap.Lookup(&CrapKey{DestIP: NewKey(dstIP1).DestIP})
	require.NoError(t, err)
	assert.True(t, val.Match(podIP1))

	val, err = crapMap.Lookup(&CrapKey{DestIP: NewKey(dstIP2).DestIP})
	require.NoError(t, err)
	assert.True(t, val.Match(podIP2))

	entries := map[CrapKey]CrapVal{}
	require.NoError(t, crapMap.IterateWithCallback(func(key *CrapKey, val *CrapVal) {
		entries[*key] = *val
	}))
	assert.Len(t, entries, 2)
	entry1 := entries[NewKey(dstIP1)]
	entry2 := entries[NewKey(dstIP2)]
	assert.True(t, (&entry1).Match(podIP1))
	assert.True(t, (&entry2).Match(podIP2))

	require.NoError(t, crapMap.RemoveCrapMapping(dstIP1))
	require.NoError(t, crapMap.Delete(&CrapKey{DestIP: NewKey(dstIP2).DestIP}))

	_, err = crapMap.Lookup(&CrapKey{DestIP: NewKey(dstIP1).DestIP})
	assert.ErrorIs(t, err, ebpf.ErrKeyNotExist)

	_, err = crapMap.Lookup(&CrapKey{DestIP: NewKey(dstIP2).DestIP})
	assert.ErrorIs(t, err, ebpf.ErrKeyNotExist)
}
