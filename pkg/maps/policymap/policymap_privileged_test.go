// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"os"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"

	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/u8proto"
)

func setupPolicyMapPrivilegedTestSuite(tb testing.TB) *PolicyMap {
	testutils.PrivilegedTest(tb)

	bpf.CheckOrMountFS("")

	if err := rlimit.RemoveMemlock(); err != nil {
		tb.Fatal(err)
	}

	testMap := newMap("cilium_policy_v2_test")

	_ = os.RemoveAll(bpf.MapPath("cilium_policy_v2_test"))
	err := testMap.CreateUnpinned()
	require.NoError(tb, err)

	tb.Cleanup(func() {
		err := testMap.DeleteAll()
		require.NoError(tb, err)
	})

	return testMap
}

func TestPolicyMapDumpToSlice(t *testing.T) {
	testMap := setupPolicyMapPrivilegedTestSuite(t)

	fooKey := NewKey(1, 1, 1, 1, SinglePortPrefixLen)
	err := testMap.AllowKey(fooKey, 42, policyTypes.AuthTypeSpire.AsDerivedRequirement(), 0)
	require.NoError(t, err)

	dump, err := testMap.DumpToSlice()
	require.NoError(t, err)
	require.Len(t, dump, 1)

	require.EqualValues(t, fooKey, dump[0].Key)

	require.False(t, dump[0].PolicyEntry.AuthRequirement.IsExplicit())
	require.Equal(t, policyTypes.AuthType(1), dump[0].PolicyEntry.AuthRequirement.AuthType())
	require.Equal(t, policyTypes.ProxyPortPriority(42), dump[0].PolicyEntry.ProxyPortPriority)

	// Special case: allow-all entry
	barEntry := NewKey(0, 0, 0, 0, 0)
	err = testMap.AllowKey(barEntry, 0, policyTypes.AuthRequirement(0), 0)
	require.NoError(t, err)

	dump, err = testMap.DumpToSlice()
	require.NoError(t, err)
	require.Len(t, dump, 2)
}

func TestDeleteNonexistentKey(t *testing.T) {
	testMap := setupPolicyMapPrivilegedTestSuite(t)
	key := NewKey(trafficdirection.Ingress, 27, u8proto.TCP, 80, SinglePortPrefixLen)
	err := testMap.Map.Delete(&key)
	require.Error(t, err)
	var errno unix.Errno
	require.ErrorAs(t, err, &errno)
	require.Equal(t, unix.ENOENT, errno)
}

func TestDenyPolicyMapDumpToSlice(t *testing.T) {
	testMap := setupPolicyMapPrivilegedTestSuite(t)

	fooKey := NewKey(1, 1, 1, 1, SinglePortPrefixLen)
	fooEntry := newDenyEntry(fooKey)
	err := testMap.DenyKey(fooKey)
	require.NoError(t, err)

	dump, err := testMap.DumpToSlice()
	require.NoError(t, err)
	require.Len(t, dump, 1)

	require.EqualValues(t, fooKey, dump[0].Key)
	require.EqualValues(t, fooEntry, dump[0].PolicyEntry)

	// Special case: deny-all entry
	barKey := NewKey(0, 0, 0, 0, 0)
	err = testMap.DenyKey(barKey)
	require.NoError(t, err)

	dump, err = testMap.DumpToSlice()
	require.NoError(t, err)
	require.Len(t, dump, 2)
}
