// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package allocator

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/idpool"
)

func TestLocalKeys(t *testing.T) {
	k := newLocalKeys(hivetest.Logger(t))
	key, val := TestAllocatorKey("foo"), idpool.ID(200)
	key2, val2 := TestAllocatorKey("bar"), idpool.ID(300)

	v := k.use(key.GetKey())
	require.Equal(t, idpool.NoID, v)

	v, firstUse, err := k.allocate(key.GetKey(), key, val) // refcnt=1
	require.NoError(t, err)
	require.Equal(t, val, v)
	require.True(t, firstUse)

	require.NoError(t, k.verify(key.GetKey()))

	v = k.use(key.GetKey()) // refcnt=2
	require.Equal(t, val, v)
	k.release(key.GetKey()) // refcnt=1

	v, firstUse, err = k.allocate(key.GetKey(), key, val) // refcnt=2
	require.NoError(t, err)
	require.Equal(t, val, v)
	require.False(t, firstUse)

	v, firstUse, err = k.allocate(key2.GetKey(), key2, val2) // refcnt=1
	require.NoError(t, err)
	require.Equal(t, val2, v)
	require.True(t, firstUse)

	// only one of the two keys is verified yet
	ids := k.getVerifiedIDs()
	require.Len(t, ids, 1)

	// allocate with different value must fail
	_, _, err = k.allocate(key2.GetKey(), key2, val)
	require.Error(t, err)

	k.release(key.GetKey()) // refcnt=1
	v = k.use(key.GetKey()) // refcnt=2
	require.Equal(t, val, v)

	k.release(key.GetKey()) // refcnt=1
	k.release(key.GetKey()) // refcnt=0
	v = k.use(key.GetKey())
	require.Equal(t, idpool.NoID, v)

	k.release(key2.GetKey()) // refcnt=0
	v = k.use(key2.GetKey())
	require.Equal(t, idpool.NoID, v)
}
