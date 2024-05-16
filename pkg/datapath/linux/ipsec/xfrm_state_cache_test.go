// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipsec

import (
	"time"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/option"

	baseclocktest "k8s.io/utils/clock/testing"
)

func (p *IPSecSuitePrivileged) TestXfrmStateListCache(c *C) {
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

	c.Assert(xfrmStateCache.isExpired(), Equals, true)

	cleanIPSecStatesAndPolicies(c)
	state := initDummyXfrmState()
	err := createDummyXfrmState(state)
	c.Assert(err, IsNil)

	// Make sure that cache is correctly fetched in the beginning
	stateList, err := xfrmStateCache.XfrmStateList()
	c.Assert(err, IsNil)
	c.Assert(len(stateList), Equals, 1)
	c.Assert(state.Spi, Equals, stateList[0].Spi)

	cleanIPSecStatesAndPolicies(c)
	// Check that cache does not expire instantly
	stateList, err = xfrmStateCache.XfrmStateList()
	c.Assert(err, IsNil)
	c.Assert(len(stateList), Equals, 1)

	// Move time by half second and make sure cache still did not expire
	fakeClock.Step(time.Millisecond * 500)
	c.Assert(xfrmStateCache.isExpired(), Equals, false)
	stateList, err = xfrmStateCache.XfrmStateList()
	c.Assert(err, IsNil)
	c.Assert(len(stateList), Equals, 1)

	// Invalidate cache by moving time by 501 more miliseconds
	fakeClock.Step(time.Millisecond * 501)
	c.Assert(xfrmStateCache.isExpired(), Equals, true)
	stateList, err = xfrmStateCache.XfrmStateList()
	c.Assert(err, IsNil)
	c.Assert(len(stateList), Equals, 0)

	// Create new xfrm state and check that cache is utomatically updated
	// It is expired as for empty xfrm list netlink.XfrmStateList returns nil pointer
	c.Assert(xfrmStateCache.isExpired(), Equals, true)
	err = xfrmStateCache.XfrmStateAdd(state)
	c.Assert(err, IsNil)
	c.Assert(xfrmStateCache.isExpired(), Equals, true)
	stateList, err = xfrmStateCache.XfrmStateList()
	c.Assert(err, IsNil)
	c.Assert(len(stateList), Equals, 1)
	c.Assert(stateList[0].OutputMark.Value, Equals, uint32(linux_defaults.RouteMarkDecrypt))

	// Update xfrm state and check that cache is automatically updated
	c.Assert(xfrmStateCache.isExpired(), Equals, false)
	// Switch to encrypt as this is the only value we update
	state.OutputMark.Value = linux_defaults.RouteMarkEncrypt
	err = xfrmStateCache.XfrmStateUpdate(state)
	c.Assert(err, IsNil)
	c.Assert(xfrmStateCache.isExpired(), Equals, true)
	stateList, err = xfrmStateCache.XfrmStateList()
	c.Assert(err, IsNil)
	c.Assert(len(stateList), Equals, 1)
	c.Assert(stateList[0].OutputMark.Value, Equals, uint32(linux_defaults.RouteMarkEncrypt))

	// Delete xfrm state and check that cache is automatically updated
	c.Assert(xfrmStateCache.isExpired(), Equals, false)
	err = xfrmStateCache.XfrmStateDel(state)
	c.Assert(err, IsNil)
	c.Assert(xfrmStateCache.isExpired(), Equals, true)
	stateList, err = xfrmStateCache.XfrmStateList()
	c.Assert(err, IsNil)
	c.Assert(len(stateList), Equals, 0)
}

func (p *IPSecSuitePrivileged) TestXfrmStateListCacheDisabled(c *C) {
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
	c.Assert(err, IsNil)

	c.Assert(xfrmStateCache.isExpired(), Equals, true)
	// Make sure that cache is correctly fetched in the beginning
	stateList, err := xfrmStateCache.XfrmStateList()
	c.Assert(err, IsNil)
	c.Assert(len(stateList), Equals, 1)

	// And is still expired
	c.Assert(xfrmStateCache.isExpired(), Equals, true)
}
