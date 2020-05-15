// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package policy

import (
	"sync"

	"github.com/cilium/cilium/pkg/identity"

	. "gopkg.in/check.v1"
)

type DummyEndpoint struct {
	rev uint64
}

func (d *DummyEndpoint) GetID16() uint16 {
	return 0
}

func (d *DummyEndpoint) IsHost() bool {
	return false
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

func (ds *PolicyTestSuite) TestForEach(c *C) {
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
