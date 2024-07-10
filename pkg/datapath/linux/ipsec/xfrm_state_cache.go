// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipsec

import (
	"github.com/vishvananda/netlink"
	"k8s.io/utils/clock"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

type xfrmStateListCache struct {
	stateList []netlink.XfrmState
	timeout   time.Time
	mutex     lock.Mutex
	ttl       time.Duration
	clock     clock.PassiveClock
}

func NewXfrmStateListCache(ttl time.Duration) *xfrmStateListCache {
	return &xfrmStateListCache{
		ttl:   ttl,
		clock: clock.RealClock{},
	}
}

func (c *xfrmStateListCache) XfrmStateList() ([]netlink.XfrmState, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.isExpired() {
		result, err := netlink.XfrmStateList(netlink.FAMILY_ALL)
		if err != nil {
			return nil, err
		}
		c.stateList = result
		c.timeout = c.clock.Now().Add(c.ttl)
	}
	return c.stateList, nil
}

func (c *xfrmStateListCache) XfrmStateDel(state *netlink.XfrmState) error {
	c.invalidate()
	return netlink.XfrmStateDel(state)
}

func (c *xfrmStateListCache) XfrmStateUpdate(state *netlink.XfrmState) error {
	c.invalidate()
	return netlink.XfrmStateUpdate(state)
}

func (c *xfrmStateListCache) XfrmStateAdd(state *netlink.XfrmState) error {
	c.invalidate()
	return netlink.XfrmStateAdd(state)
}

func (c *xfrmStateListCache) XfrmStateFlush(proto netlink.Proto) error {
	c.invalidate()
	return netlink.XfrmStateFlush(proto)
}

func (c *xfrmStateListCache) isExpired() bool {
	return !option.Config.EnableIPSecXfrmStateCaching || c.stateList == nil || c.timeout.Before(c.clock.Now())
}

func (c *xfrmStateListCache) invalidate() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.stateList = nil
}

func newTestableXfrmStateListCache(ttl time.Duration, clock clock.PassiveClock) *xfrmStateListCache {
	return &xfrmStateListCache{
		ttl:   ttl,
		clock: clock,
	}
}
