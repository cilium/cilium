// Copyright 2016-2017 Authors of Cilium
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

package policy

import (
	"sync"

	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"

	. "gopkg.in/check.v1"
)

func (s *PolicyTestSuite) TestReservedID(c *C) {
	i1 := GetReservedID("host")
	c.Assert(i1, Equals, NumericIdentity(1))
	c.Assert(i1.String(), Equals, "host")

	i2 := GetReservedID("world")
	c.Assert(i2, Equals, NumericIdentity(2))
	c.Assert(i2.String(), Equals, "world")

	i2 = GetReservedID("cluster")
	c.Assert(i2, Equals, NumericIdentity(3))
	c.Assert(i2.String(), Equals, "cluster")

	c.Assert(GetReservedID("unknown"), Equals, IdentityUnknown)
	unknown := NumericIdentity(700)
	c.Assert(unknown.String(), Equals, "700")
}

type IdentityAllocatorSuite struct{}

type IdentityAllocatorEtcdSuite struct {
	IdentityAllocatorSuite
}

var _ = Suite(&IdentityAllocatorEtcdSuite{})

func (e *IdentityAllocatorEtcdSuite) SetUpTest(c *C) {
	kvstore.SetupDummy("etcd")
}

type IdentityAllocatorConsulSuite struct {
	IdentityAllocatorSuite
}

var _ = Suite(&IdentityAllocatorConsulSuite{})

func (e *IdentityAllocatorConsulSuite) SetUpTest(c *C) {
	kvstore.SetupDummy("consul")
}

type dummyOwner struct{}

func (d dummyOwner) TriggerPolicyUpdates(force bool) *sync.WaitGroup {
	return nil
}

func (ias *IdentityAllocatorSuite) TestAllocator(c *C) {
	lbls1 := labels.NewLabelsFromSortedList("id=foo;user=anna;blah=%%//!!")
	lbls2 := labels.NewLabelsFromSortedList("id=bar;user=anna")
	lbls3 := labels.NewLabelsFromSortedList("id=bar;user=susan")

	InitIdentityAllocator(dummyOwner{})
	defer identityAllocator.DeleteAllKeys()

	id1a, isNew, err := AllocateIdentity(lbls1)
	c.Assert(id1a, Not(IsNil))
	c.Assert(err, IsNil)
	c.Assert(isNew, Equals, true)

	id1b, isNew, err := AllocateIdentity(lbls1)
	c.Assert(id1b, Not(IsNil))
	c.Assert(isNew, Equals, false)
	c.Assert(err, IsNil)
	c.Assert(id1a.ID, Equals, id1b.ID)

	c.Assert(id1a.Release(), IsNil)
	c.Assert(id1b.Release(), IsNil)

	id1b, isNew, err = AllocateIdentity(lbls1)
	c.Assert(id1b, Not(IsNil))
	c.Assert(err, IsNil)
	// the value key should not have been removed so the same ID should be
	// assigned again the it should not be marked as new
	c.Assert(isNew, Equals, false)
	c.Assert(id1a.ID, Equals, id1b.ID)

	id2, isNew, err := AllocateIdentity(lbls2)
	c.Assert(id2, Not(IsNil))
	c.Assert(isNew, Equals, true)
	c.Assert(err, IsNil)
	c.Assert(id1a.ID, Not(Equals), id2.ID)

	id3, isNew, err := AllocateIdentity(lbls3)
	c.Assert(id3, Not(IsNil))
	c.Assert(isNew, Equals, true)
	c.Assert(err, IsNil)
	c.Assert(id1a.ID, Not(Equals), id3.ID)
	c.Assert(id2.ID, Not(Equals), id3.ID)

	c.Assert(id1b.Release(), IsNil)
	c.Assert(id2.Release(), IsNil)
	c.Assert(id3.Release(), IsNil)
}
