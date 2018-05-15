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

package identity

import (
	"sync"
	"testing"

	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type IdentityTestSuite struct{}

var _ = Suite(&IdentityTestSuite{})

func (s *IdentityTestSuite) TestReservedID(c *C) {
	i := GetReservedID("host")
	c.Assert(i, Equals, NumericIdentity(1))
	c.Assert(i.String(), Equals, "host")

	i = GetReservedID("world")
	c.Assert(i, Equals, NumericIdentity(2))
	c.Assert(i.String(), Equals, "world")

	i = GetReservedID("cluster")
	c.Assert(i, Equals, NumericIdentity(3))
	c.Assert(i.String(), Equals, "cluster")

	i = GetReservedID("health")
	c.Assert(i, Equals, NumericIdentity(4))
	c.Assert(i.String(), Equals, "health")

	i = GetReservedID("init")
	c.Assert(i, Equals, NumericIdentity(5))
	c.Assert(i.String(), Equals, "init")

	c.Assert(GetReservedID("unknown"), Equals, IdentityUnknown)
	unknown := NumericIdentity(700)
	c.Assert(unknown.String(), Equals, "700")
}

func (s *IdentityTestSuite) TestIsReservedIdentity(c *C) {
	c.Assert(ReservedIdentityCluster.IsReservedIdentity(), Equals, true)
	c.Assert(ReservedIdentityHealth.IsReservedIdentity(), Equals, true)
	c.Assert(ReservedIdentityHost.IsReservedIdentity(), Equals, true)
	c.Assert(ReservedIdentityWorld.IsReservedIdentity(), Equals, true)
	c.Assert(ReservedIdentityInit.IsReservedIdentity(), Equals, true)

	c.Assert(NumericIdentity(123456).IsReservedIdentity(), Equals, false)
}

func (s *IdentityTestSuite) TestAllocateIdentityReserved(c *C) {
	var (
		lbls  labels.Labels
		i     *Identity
		isNew bool
		err   error
	)

	lbls = labels.Labels{
		labels.IDNameHost: labels.NewLabel(labels.IDNameHost, "", labels.LabelSourceReserved),
	}
	c.Assert(IdentityAllocationIsLocal(lbls), Equals, true)
	i, isNew, err = AllocateIdentity(lbls)
	c.Assert(err, IsNil)
	c.Assert(i.ID, Equals, ReservedIdentityHost)
	c.Assert(isNew, Equals, false)

	lbls = labels.Labels{
		labels.IDNameWorld: labels.NewLabel(labels.IDNameWorld, "", labels.LabelSourceReserved),
	}
	c.Assert(IdentityAllocationIsLocal(lbls), Equals, true)
	i, isNew, err = AllocateIdentity(lbls)
	c.Assert(err, IsNil)
	c.Assert(i.ID, Equals, ReservedIdentityWorld)
	c.Assert(isNew, Equals, false)

	lbls = labels.Labels{
		labels.IDNameCluster: labels.NewLabel(labels.IDNameCluster, "", labels.LabelSourceReserved),
	}
	c.Assert(IdentityAllocationIsLocal(lbls), Equals, true)
	i, isNew, err = AllocateIdentity(lbls)
	c.Assert(err, IsNil)
	c.Assert(i.ID, Equals, ReservedIdentityCluster)
	c.Assert(isNew, Equals, false)

	lbls = labels.Labels{
		labels.IDNameHealth: labels.NewLabel(labels.IDNameHealth, "", labels.LabelSourceReserved),
	}
	c.Assert(IdentityAllocationIsLocal(lbls), Equals, true)
	i, isNew, err = AllocateIdentity(lbls)
	c.Assert(err, IsNil)
	c.Assert(i.ID, Equals, ReservedIdentityHealth)
	c.Assert(isNew, Equals, false)

	lbls = labels.Labels{
		labels.IDNameInit: labels.NewLabel(labels.IDNameInit, "", labels.LabelSourceReserved),
	}
	c.Assert(IdentityAllocationIsLocal(lbls), Equals, true)
	i, isNew, err = AllocateIdentity(lbls)
	c.Assert(err, IsNil)
	c.Assert(i.ID, Equals, ReservedIdentityInit)
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

func (d dummyOwner) TriggerPolicyUpdates(force bool) *sync.WaitGroup {
	return nil
}

func (d dummyOwner) GetNodeSuffix() string {
	return "foo"
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

	err = id1a.Release()
	c.Assert(err, IsNil)
	err = id1b.Release()
	c.Assert(err, IsNil)

	id1b, isNew, err = AllocateIdentity(lbls1)
	c.Assert(id1b, Not(IsNil))
	c.Assert(err, IsNil)
	// the value key should not have been removed so the same ID should be
	// assigned again the it should not be marked as new
	c.Assert(isNew, Equals, false)
	c.Assert(id1a.ID, Equals, id1b.ID)

	identity := LookupIdentityByID(id1b.ID)
	c.Assert(identity, Not(IsNil))
	c.Assert(lbls1, DeepEquals, identity.Labels)

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

	err = id1b.Release()
	c.Assert(err, IsNil)
	err = id2.Release()
	c.Assert(err, IsNil)
	err = id3.Release()
	c.Assert(err, IsNil)
}
