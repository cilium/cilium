// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package authmap

import (
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/utime"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/testutils"
)

func setup(tb testing.TB) {
	testutils.PrivilegedTest(tb)

	bpf.CheckOrMountFS(hivetest.Logger(tb), "")
	err := rlimit.RemoveMemlock()
	require.NoError(tb, err)
}

func TestAuthMap(t *testing.T) {
	setup(t)
	authMap := newMap(hivetest.Logger(t), 10)
	err := authMap.init()
	require.NoError(t, err)
	defer authMap.bpfMap.Unpin()

	testKey := AuthKey{
		LocalIdentity:  1,
		RemoteIdentity: 2,
		RemoteNodeID:   1,
		AuthType:       1, // policy.AuthTypeNull
	}

	_, err = authMap.Lookup(testKey)
	require.ErrorIs(t, err, ebpf.ErrKeyNotExist)

	err = authMap.Update(testKey, 10)
	require.NoError(t, err)

	info, err := authMap.Lookup(testKey)
	require.NoError(t, err)
	require.Equal(t, utime.UTime(10), info.Expiration)

	err = authMap.Update(testKey, 20)
	require.NoError(t, err)

	info, err = authMap.Lookup(testKey)
	require.NoError(t, err)
	require.Equal(t, utime.UTime(20), info.Expiration)

	err = authMap.Delete(testKey)
	require.NoError(t, err)

	_, err = authMap.Lookup(testKey)
	require.ErrorIs(t, err, ebpf.ErrKeyNotExist)
}
