// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package authmap

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/utime"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/testutils"
)

func setup(tb testing.TB) {
	testutils.PrivilegedTest(tb)

	bpf.CheckOrMountFS("")
	err := rlimit.RemoveMemlock()
	require.NoError(tb, err)
}

func TestAuthMap(t *testing.T) {
	setup(t)
	authMap := newMap(10)
	err := authMap.init()
	require.Nil(t, err)
	defer authMap.bpfMap.Unpin()

	testKey := AuthKey{
		LocalIdentity:  1,
		RemoteIdentity: 2,
		RemoteNodeID:   1,
		AuthType:       1, // policy.AuthTypeNull
	}

	_, err = authMap.Lookup(testKey)
	require.Equal(t, true, errors.Is(err, ebpf.ErrKeyNotExist))

	err = authMap.Update(testKey, 10)
	require.Nil(t, err)

	info, err := authMap.Lookup(testKey)
	require.Nil(t, err)
	require.Equal(t, utime.UTime(10), info.Expiration)

	err = authMap.Update(testKey, 20)
	require.Nil(t, err)

	info, err = authMap.Lookup(testKey)
	require.Nil(t, err)
	require.Equal(t, utime.UTime(20), info.Expiration)

	err = authMap.Delete(testKey)
	require.Nil(t, err)

	_, err = authMap.Lookup(testKey)
	require.Equal(t, true, errors.Is(err, ebpf.ErrKeyNotExist))
}
