// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nat

import (
	"testing"

	. "github.com/cilium/checkmate"

	"github.com/cilium/ebpf/rlimit"

	"github.com/cilium/cilium/pkg/bpf"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

type PerClusterNATMapPrivilegedTestSuite struct{}

var _ = Suite(&PerClusterNATMapPrivilegedTestSuite{})

const (
	testPerClusterNATMapNamePrefix = "test_cilium_per_cluster_nat_"
)

func Test(t *testing.T) {
	TestingT(t)
}

func (k *PerClusterNATMapPrivilegedTestSuite) SetUpSuite(c *C) {
	testutils.PrivilegedTest(c)

	bpf.CheckOrMountFS("")
	err := rlimit.RemoveMemlock()
	c.Assert(err, IsNil)
}

func (k *PerClusterNATMapPrivilegedTestSuite) SetUpTest(c *C) {
	InitPerClusterNATMaps(testPerClusterNATMapNamePrefix, true, true, option.NATMapEntriesGlobalDefault)
}

func (k *PerClusterNATMapPrivilegedTestSuite) TearDownTest(c *C) {
	PerClusterNATMaps.Cleanup()
}

func (k *PerClusterNATMapPrivilegedTestSuite) TestPerClusterCtMap(c *C) {
	om, err := newPerClusterNATMap(testPerClusterNATMapNamePrefix+perClusterNATIPv4OuterMapSuffix, true, option.NATMapEntriesGlobalDefault)
	c.Assert(err, IsNil)

	defer om.Unpin()
	defer om.Close()

	// ClusterID 0 should never be used
	err = om.updateClusterNATMap(0)
	c.Assert(err, NotNil)
	_, err = om.getClusterNATMap(0)
	c.Assert(err, NotNil)
	err = om.deleteClusterNATMap(0)
	c.Assert(err, NotNil)

	// ClusterID beyond the ClusterIDMax should never be used
	err = om.updateClusterNATMap(cmtypes.ClusterIDMax + 1)
	c.Assert(err, NotNil)
	_, err = om.getClusterNATMap(cmtypes.ClusterIDMax + 1)
	c.Assert(err, NotNil)
	err = om.deleteClusterNATMap(cmtypes.ClusterIDMax + 1)
	c.Assert(err, NotNil)

	// Basic update
	err = om.updateClusterNATMap(1)
	c.Assert(err, IsNil)

	// After update, outer map should be updated with the inner map
	v, err := om.Lookup(&PerClusterNATMapKey{1})
	c.Assert(err, IsNil)
	c.Assert(v, Not(Equals), 0)

	// Basic Get
	im, err := om.getClusterNATMap(1)
	c.Assert(im, NotNil)
	c.Assert(err, IsNil)

	im.Close()

	// Getting nonexistent entry returns error
	_, err = om.getClusterNATMap(2)
	c.Assert(err, NotNil)

	// Basic delete
	err = om.deleteClusterNATMap(1)
	c.Assert(err, IsNil)

	// After delete, outer map shouldn't contain the inner map
	_, err = om.Lookup(&PerClusterNATMapKey{1})
	c.Assert(err, NotNil)
}

func (k *PerClusterNATMapPrivilegedTestSuite) TestPerClusterNATMaps(c *C) {
	gm, err := newPerClusterNATMaps(testPerClusterNATMapNamePrefix, true, true, option.NATMapEntriesGlobalDefault)
	c.Assert(err, IsNil)

	defer gm.Cleanup()

	// ClusterID 0 should never be used
	err = gm.UpdateClusterNATMaps(0)
	c.Assert(err, NotNil)
	err = gm.DeleteClusterNATMaps(0)
	c.Assert(err, NotNil)
	_, err = gm.GetClusterNATMap(0, true)
	c.Assert(err, NotNil)

	// ClusterID beyond the ClusterIDMax should never be used
	err = gm.UpdateClusterNATMaps(cmtypes.ClusterIDMax + 1)
	c.Assert(err, NotNil)
	err = gm.DeleteClusterNATMaps(cmtypes.ClusterIDMax + 1)
	c.Assert(err, NotNil)
	_, err = gm.GetClusterNATMap(cmtypes.ClusterIDMax+1, true)
	c.Assert(err, NotNil)

	// Basic update
	err = gm.UpdateClusterNATMaps(1)
	c.Assert(err, IsNil)

	err = gm.UpdateClusterNATMaps(cmtypes.ClusterIDMax)
	c.Assert(err, IsNil)

	for _, om := range []*PerClusterNATMap{gm.v4Map, gm.v6Map} {
		// After update, outer map should be updated with the inner map
		v, err := om.Lookup(&PerClusterNATMapKey{1})
		c.Assert(err, IsNil)
		c.Assert(v, Not(Equals), 0)
		v, err = om.Lookup(&PerClusterNATMapKey{cmtypes.ClusterIDMax})
		c.Assert(err, IsNil)
		c.Assert(v, Not(Equals), 0)
	}

	// Basic get
	im, err := gm.GetClusterNATMap(1, true)
	c.Assert(err, IsNil)
	im.Close()

	im, err = gm.GetClusterNATMap(1, false)
	c.Assert(err, IsNil)
	im.Close()

	im, err = gm.GetClusterNATMap(cmtypes.ClusterIDMax, true)
	c.Assert(err, IsNil)
	im.Close()

	im, err = gm.GetClusterNATMap(cmtypes.ClusterIDMax, false)
	c.Assert(err, IsNil)
	im.Close()

	// Basic delete
	err = gm.DeleteClusterNATMaps(1)
	c.Assert(err, IsNil)

	err = gm.DeleteClusterNATMaps(cmtypes.ClusterIDMax)
	c.Assert(err, IsNil)

	_, err = gm.v4Map.Lookup(&PerClusterNATMapKey{1})
	c.Assert(err, NotNil)

	_, err = gm.v6Map.Lookup(&PerClusterNATMapKey{1})
	c.Assert(err, NotNil)

	_, err = gm.v4Map.Lookup(&PerClusterNATMapKey{cmtypes.ClusterIDMax})
	c.Assert(err, NotNil)

	_, err = gm.v6Map.Lookup(&PerClusterNATMapKey{cmtypes.ClusterIDMax})
	c.Assert(err, NotNil)

	for _, om := range []*PerClusterNATMap{gm.v4Map, gm.v6Map} {
		// After delete, outer map shouldn't contain the maps
		_, err := om.Lookup(&PerClusterNATMapKey{1})
		c.Assert(err, NotNil)
		_, err = om.Lookup(&PerClusterNATMapKey{cmtypes.ClusterIDMax})
		c.Assert(err, NotNil)
	}
}
