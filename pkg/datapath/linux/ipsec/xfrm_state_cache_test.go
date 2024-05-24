// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipsec

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"

	baseclocktest "k8s.io/utils/clock/testing"
)

func TestXfrmStateListCache(t *testing.T) {
	setupIPSecSuitePrivileged(t)

	backupOption := option.Config.EnableIPSecXfrmStateCaching
	defer func() {
		option.Config.EnableIPSecXfrmStateCaching = backupOption
	}()
	option.Config.EnableIPSecXfrmStateCaching = true

	fakeClock := baseclocktest.NewFakeClock(time.Now())
	xfrmStateCache := newTestableXfrmStateListCache(
		time.Second,
		fakeClock,
	)

	require.True(t, xfrmStateCache.isExpired(), "Cache should be expired in the beginning")

	cleanIPSecStatesAndPolicies(t)
	state := initDummyXfrmState()
	err := createDummyXfrmState(state)
	require.NoError(t, err)

	// Make sure that cache is correctly fetched in the beginning
	stateList, err := xfrmStateCache.XfrmStateList()
	require.NoError(t, err)
	require.Len(t, stateList, 1)
	require.Equal(t, state.Spi, stateList[0].Spi)

	cleanIPSecStatesAndPolicies(t)
	// Check that cache does not expire instantly
	stateList, err = xfrmStateCache.XfrmStateList()
	require.NoError(t, err)
	require.Len(t, stateList, 1)

	// Move time by half second and make sure cache still did not expire
	fakeClock.Step(time.Millisecond * 500)
	require.False(t, xfrmStateCache.isExpired(), "Cache should not be expired before timeout")
	stateList, err = xfrmStateCache.XfrmStateList()
	require.NoError(t, err)
	require.Len(t, stateList, 1)

	// Invalidate cache by moving time by 501 more miliseconds
	fakeClock.Step(time.Millisecond * 501)
	require.True(t, xfrmStateCache.isExpired(), "Cache should be expired after timeout")
	stateList, err = xfrmStateCache.XfrmStateList()
	require.NoError(t, err)
	require.Len(t, stateList, 0)

	// Create new xfrm state and check that cache is atomatically updated
	require.True(t, xfrmStateCache.isExpired(), "Cache should be expired when list is empty")
	err = xfrmStateCache.XfrmStateAdd(state)
	require.NoError(t, err)
	require.True(t, xfrmStateCache.isExpired(), "Cache should be expired after adding new state")
	stateList, err = xfrmStateCache.XfrmStateList()
	require.NoError(t, err)
	require.Len(t, stateList, 1)
	require.Equal(t, stateList[0].OutputMark.Value, uint32(linux_defaults.RouteMarkDecrypt))

	// Update xfrm state and check that cache is automatically updated
	require.False(t, xfrmStateCache.isExpired(), "Cache should not be expired before timeout")
	// Switch to encrypt as this is the only value we update
	state.OutputMark.Value = linux_defaults.RouteMarkEncrypt
	err = xfrmStateCache.XfrmStateUpdate(state)
	require.NoError(t, err)
	require.True(t, xfrmStateCache.isExpired(), "Cache should be expired after updating state")
	stateList, err = xfrmStateCache.XfrmStateList()
	require.NoError(t, err)
	require.Len(t, stateList, 1)
	require.Equal(t, stateList[0].OutputMark.Value, uint32(linux_defaults.RouteMarkEncrypt))

	// Delete xfrm state and check that cache is automatically updated
	require.False(t, xfrmStateCache.isExpired(), "Cache should not be expired before timeout")
	err = xfrmStateCache.XfrmStateDel(state)
	require.NoError(t, err)
	require.True(t, xfrmStateCache.isExpired(), "Cache should be expired after deleting state")
	stateList, err = xfrmStateCache.XfrmStateList()
	require.NoError(t, err)
	require.Len(t, stateList, 0)
}

func TestXfrmStateListCacheDisabled(t *testing.T) {
	setupIPSecSuitePrivileged(t)

	backupOption := option.Config.EnableIPSecXfrmStateCaching
	defer func() {
		option.Config.EnableIPSecXfrmStateCaching = backupOption
	}()
	option.Config.EnableIPSecXfrmStateCaching = false

	xfrmStateCache := newTestableXfrmStateListCache(
		time.Second,
		baseclocktest.NewFakeClock(time.Now()),
	)

	state := initDummyXfrmState()
	err := createDummyXfrmState(state)
	require.NoError(t, err)

	require.True(t, xfrmStateCache.isExpired(), "Cache should be expired in the beginning")
	// Make sure that cache is correctly fetched in the beginning
	stateList, err := xfrmStateCache.XfrmStateList()
	require.NoError(t, err)
	require.Len(t, stateList, 1)

	// And is still expired
	require.True(t, xfrmStateCache.isExpired(), "Cache should be stil expired as it's disabled")
}
