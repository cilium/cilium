// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"sync"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/identity"
)

type DummyEndpoint struct {
	rev      uint64
	Endpoint // Implement methods of the interface that need to mock out real behavior.
}

func (d *DummyEndpoint) GetSecurityIdentity() (*identity.Identity, error) {
	return nil, nil
}

func (d *DummyEndpoint) PolicyRevisionBumpEvent(rev uint64) {
	d.rev = rev
}

func (d *DummyEndpoint) RLockAlive() error {
	return nil
}

func (d *DummyEndpoint) RUnlock() {
}

func (ds *PolicyTestSuite) TestNewEndpointSet(c *C) {
	d := &DummyEndpoint{}
	epSet := NewEndpointSet(map[Endpoint]struct{}{
		d: {},
	})
	c.Assert(epSet.Len(), Equals, 1)
	epSet.Delete(d)
	c.Assert(epSet.Len(), Equals, 0)
}

func (ds *PolicyTestSuite) TestForEachGo(c *C) {
	var wg sync.WaitGroup

	d0 := &DummyEndpoint{}
	d1 := &DummyEndpoint{}

	epSet := NewEndpointSet(map[Endpoint]struct{}{
		d0: {},
		d1: {},
	})
	epSet.ForEachGo(&wg, func(e Endpoint) {
		e.PolicyRevisionBumpEvent(100)
	})

	wg.Wait()

	c.Assert(d0.rev, Equals, uint64(100))
	c.Assert(d1.rev, Equals, uint64(100))
}

func (ds *PolicyTestSuite) BenchmarkForEachGo(c *C) {
	m := make(map[Endpoint]struct{}, c.N)
	for i := uint64(0); i < uint64(c.N); i++ {
		m[&DummyEndpoint{rev: i}] = struct{}{}
	}
	epSet := NewEndpointSet(m)

	c.StartTimer()
	var wg sync.WaitGroup
	epSet.ForEachGo(&wg, func(e Endpoint) {
		e.PolicyRevisionBumpEvent(100)
	})
	wg.Wait()
	c.StopTimer()
}
