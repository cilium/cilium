// Copyright 2016-2018 Authors of Cilium
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

package cache

import (
	"context"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"

	. "gopkg.in/check.v1"
)

func (s *IdentityCacheTestSuite) TestAllocateIdentityReserved(c *C) {
	var (
		lbls  labels.Labels
		i     *identity.Identity
		isNew bool
		err   error
	)

	lbls = labels.Labels{
		labels.IDNameHost: labels.NewLabel(labels.IDNameHost, "", labels.LabelSourceReserved),
	}
	c.Assert(IdentityAllocationIsLocal(lbls), Equals, true)
	i, isNew, err = AllocateIdentity(context.Background(), lbls)
	c.Assert(err, IsNil)
	c.Assert(i.ID, Equals, identity.ReservedIdentityHost)
	c.Assert(isNew, Equals, false)

	lbls = labels.Labels{
		labels.IDNameWorld: labels.NewLabel(labels.IDNameWorld, "", labels.LabelSourceReserved),
	}
	c.Assert(IdentityAllocationIsLocal(lbls), Equals, true)
	i, isNew, err = AllocateIdentity(context.Background(), lbls)
	c.Assert(err, IsNil)
	c.Assert(i.ID, Equals, identity.ReservedIdentityWorld)
	c.Assert(isNew, Equals, false)

	c.Assert(IdentityAllocationIsLocal(labels.LabelHealth), Equals, true)
	i, isNew, err = AllocateIdentity(context.Background(), labels.LabelHealth)
	c.Assert(err, IsNil)
	c.Assert(i.ID, Equals, identity.ReservedIdentityHealth)
	c.Assert(isNew, Equals, false)

	lbls = labels.Labels{
		labels.IDNameInit: labels.NewLabel(labels.IDNameInit, "", labels.LabelSourceReserved),
	}
	c.Assert(IdentityAllocationIsLocal(lbls), Equals, true)
	i, isNew, err = AllocateIdentity(context.Background(), lbls)
	c.Assert(err, IsNil)
	c.Assert(i.ID, Equals, identity.ReservedIdentityInit)
	c.Assert(isNew, Equals, false)

	lbls = labels.Labels{
		labels.IDNameUnmanaged: labels.NewLabel(labels.IDNameUnmanaged, "", labels.LabelSourceReserved),
	}
	c.Assert(IdentityAllocationIsLocal(lbls), Equals, true)
	i, isNew, err = AllocateIdentity(context.Background(), lbls)
	c.Assert(err, IsNil)
	c.Assert(i.ID, Equals, identity.ReservedIdentityUnmanaged)
	c.Assert(isNew, Equals, false)
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

func (d dummyOwner) UpdateIdentities(added, deleted IdentityCache) {}

func (d dummyOwner) GetNodeSuffix() string {
	return "foo"
}

func (ias *IdentityAllocatorSuite) TestGetIdentityCache(c *C) {
	InitIdentityAllocator(dummyOwner{})
	defer Close()
	defer IdentityAllocator.DeleteAllKeys()

	cache := GetIdentityCache()
	_, ok := cache[identity.ReservedCiliumKVStore]
	c.Assert(ok, Equals, true)
}

func (ias *IdentityAllocatorSuite) TestAllocator(c *C) {
	lbls1 := labels.NewLabelsFromSortedList("id=foo;user=anna;blah=%%//!!")
	lbls2 := labels.NewLabelsFromSortedList("id=bar;user=anna")
	lbls3 := labels.NewLabelsFromSortedList("id=bar;user=susan")

	InitIdentityAllocator(dummyOwner{})
	defer Close()
	defer IdentityAllocator.DeleteAllKeys()

	id1a, isNew, err := AllocateIdentity(context.Background(), lbls1)
	c.Assert(id1a, Not(IsNil))
	c.Assert(err, IsNil)
	c.Assert(isNew, Equals, true)

	// reuse the same identity
	id1b, isNew, err := AllocateIdentity(context.Background(), lbls1)
	c.Assert(id1b, Not(IsNil))
	c.Assert(isNew, Equals, false)
	c.Assert(err, IsNil)
	c.Assert(id1a.ID, Equals, id1b.ID)

	released, err := Release(context.Background(), id1a)
	c.Assert(err, IsNil)
	c.Assert(released, Equals, false)
	released, err = Release(context.Background(), id1b)
	c.Assert(err, IsNil)
	c.Assert(released, Equals, true)

	id1b, isNew, err = AllocateIdentity(context.Background(), lbls1)
	c.Assert(id1b, Not(IsNil))
	c.Assert(err, IsNil)
	// the value key should not have been removed so the same ID should be
	// assigned again the it should not be marked as new
	c.Assert(isNew, Equals, false)
	c.Assert(id1a.ID, Equals, id1b.ID)

	identity := LookupIdentityByID(id1b.ID)
	c.Assert(identity, Not(IsNil))
	c.Assert(lbls1, checker.DeepEquals, identity.Labels)

	id2, isNew, err := AllocateIdentity(context.Background(), lbls2)
	c.Assert(id2, Not(IsNil))
	c.Assert(isNew, Equals, true)
	c.Assert(err, IsNil)
	c.Assert(id1a.ID, Not(Equals), id2.ID)

	id3, isNew, err := AllocateIdentity(context.Background(), lbls3)
	c.Assert(id3, Not(IsNil))
	c.Assert(isNew, Equals, true)
	c.Assert(err, IsNil)
	c.Assert(id1a.ID, Not(Equals), id3.ID)
	c.Assert(id2.ID, Not(Equals), id3.ID)

	released, err = Release(context.Background(), id1b)
	c.Assert(err, IsNil)
	c.Assert(released, Equals, true)
	released, err = Release(context.Background(), id2)
	c.Assert(err, IsNil)
	c.Assert(released, Equals, true)
	released, err = Release(context.Background(), id3)
	c.Assert(err, IsNil)
	c.Assert(released, Equals, true)
}

func (ias *IdentityAllocatorSuite) TestLocalAllocationr(c *C) {
	lbls1 := labels.NewLabelsFromSortedList("cidr:192.0.2.3/32")

	InitIdentityAllocator(dummyOwner{})
	defer Close()
	defer IdentityAllocator.DeleteAllKeys()

	id, isNew, err := AllocateIdentity(context.Background(), lbls1)
	c.Assert(id, Not(IsNil))
	c.Assert(err, IsNil)
	c.Assert(isNew, Equals, true)
	c.Assert(id.ID.HasLocalScope(), Equals, true)

	// reuse the same identity
	id, isNew, err = AllocateIdentity(context.Background(), lbls1)
	c.Assert(id, Not(IsNil))
	c.Assert(err, IsNil)
	c.Assert(isNew, Equals, false)

	cache := GetIdentityCache()
	c.Assert(cache[id.ID], Not(IsNil))

	released, err := Release(context.Background(), id)
	c.Assert(err, IsNil)
	c.Assert(released, Equals, false)
	released, err = Release(context.Background(), id)
	c.Assert(err, IsNil)
	c.Assert(released, Equals, true)

	cache = GetIdentityCache()
	c.Assert(cache[id.ID], IsNil)

	id, isNew, err = AllocateIdentity(context.Background(), lbls1)
	c.Assert(id, Not(IsNil))
	c.Assert(err, IsNil)
	c.Assert(isNew, Equals, true)
	c.Assert(id.ID.HasLocalScope(), Equals, true)

	released, err = Release(context.Background(), id)
	c.Assert(err, IsNil)
	c.Assert(released, Equals, true)
}
