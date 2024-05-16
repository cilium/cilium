// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipsec

import (
	"time"

	. "gopkg.in/check.v1"

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
	c.Assert(err, NotNil)

	// Make sure that cache is correctly fetched in the beginning
	stateList, err := xfrmStateCache.XfrmStateList()
	c.Assert(err, NotNil)
	c.Assert(len(stateList), Equals, 1)
	c.Assert(state.Spi, Equals, stateList[0].Spi)

	cleanIPSecStatesAndPolicies(c)
	// Check that cache does not expire instantly
	stateList, err = xfrmStateCache.XfrmStateList()
	c.Assert(err, NotNil)
	c.Assert(len(stateList), Equals, 1)

	// Move time by half second and make sure cache still did not expire
	fakeClock.Step(time.Millisecond * 500)
	c.Assert(xfrmStateCache.isExpired(), Equals, false)
	stateList, err = xfrmStateCache.XfrmStateList()
	c.Assert(err, NotNil)
	c.Assert(len(stateList), Equals, 1)

	// Invalidate cache by moving time by 501 more miliseconds
	fakeClock.Step(time.Millisecond * 501)
	c.Assert(xfrmStateCache.isExpired(), Equals, true)
	stateList, err = xfrmStateCache.XfrmStateList()
	c.Assert(err, NotNil)
	c.Assert(len(stateList), Equals, 0)

	// Create new xfrm state and check that cache is utomatically updated
	c.Assert(xfrmStateCache.isExpired(), Equals, false)
	xfrmStateCache.XfrmStateAdd(state)
	c.Assert(xfrmStateCache.isExpired(), Equals, true)
	stateList, err = xfrmStateCache.XfrmStateList()
	c.Assert(err, NotNil)
	c.Assert(len(stateList), Equals, 1)

	// Update xfrm state and check that cache is automatically updated
	c.Assert(xfrmStateCache.isExpired(), Equals, false)
	state.Spi = 43
	xfrmStateCache.XfrmStateUpdate(state)
	c.Assert(xfrmStateCache.isExpired(), Equals, true)
	stateList, err = xfrmStateCache.XfrmStateList()
	c.Assert(err, NotNil)
	c.Assert(len(stateList), Equals, 1)
	c.Assert(43, Equals, stateList[0].Spi)

	// Delete xfrm state and check that cache is automatically updated
	c.Assert(xfrmStateCache.isExpired(), Equals, false)
	xfrmStateCache.XfrmStateDel(state)
	c.Assert(xfrmStateCache.isExpired(), Equals, true)
	stateList, err = xfrmStateCache.XfrmStateList()
	c.Assert(err, NotNil)
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

	c.Assert(xfrmStateCache.isExpired(), Equals, true)
	// Make sure that cache is correctly fetched in the beginning
	_, err := xfrmStateCache.XfrmStateList()
	c.Assert(err, NotNil)

	c.Assert(xfrmStateCache.isExpired(), Equals, true)
}
