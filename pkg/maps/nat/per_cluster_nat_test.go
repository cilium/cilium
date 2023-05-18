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
	testutils.PrivilegedCheck(c)

	bpf.CheckOrMountFS("")
	err := rlimit.RemoveMemlock()
	c.Assert(err, IsNil)
}

func (k *PerClusterNATMapPrivilegedTestSuite) SetUpTest(c *C) {
	InitPerClusterNATMaps(true, true, option.NATMapEntriesGlobalDefault)
}

func (k *PerClusterNATMapPrivilegedTestSuite) TearDownTest(c *C) {
	PerClusterNATMaps.Cleanup()
}

func (k *PerClusterNATMapPrivilegedTestSuite) TestPerClusterCtMap(c *C) {
	om, err := newPerClusterNATMap(testPerClusterNATMapNamePrefix+"v4", true, option.NATMapEntriesGlobalDefault)
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
	cluster1MapName := innerMapNamePrefix4 + "1"
	err = om.updateClusterNATMap(1)
	c.Assert(err, IsNil)

	// After update, outer map should be updated with the inner map
	v, err := om.Lookup(&PerClusterNATMapKey{1})
	c.Assert(err, IsNil)
	c.Assert(v, Not(Equals), 0)

	// Inner map should be closed and only exist on the bpffs
	c.Assert(bpf.GetMap(cluster1MapName), IsNil)
	fd, err := bpf.ObjGet(bpf.MapPath(cluster1MapName))
	c.Assert(err, IsNil)
	c.Assert(fd, Not(Equals), 0)

	// Basic Get
	im, err := om.getClusterNATMap(1)
	c.Assert(im, NotNil)
	c.Assert(err, IsNil)

	im.Close()

	// Getting unexisting entry returns nil, nil
	im, err = om.getClusterNATMap(2)
	c.Assert(im, IsNil)
	c.Assert(err, IsNil)

	// Basic delete
	err = om.deleteClusterNATMap(1)
	c.Assert(err, IsNil)

	// After delete, outer map shouldn't contain the inner map
	_, err = om.Lookup(&PerClusterNATMapKey{1})
	c.Assert(err, NotNil)

	// Inner map shouldn't exist on the bpffs
	_, err = bpf.ObjGet(bpf.MapPath(cluster1MapName))
	c.Assert(err, NotNil)
}

func (k *PerClusterNATMapPrivilegedTestSuite) TestPerClusterNATMaps(c *C) {
	gm, err := newPerClusterNATMaps(true, true, option.NATMapEntriesGlobalDefault)
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

	for _, om := range []*PerClusterNATMap{gm.v4Map, gm.v6Map} {
		// After update, outer map should be updated with the inner map
		v, err := om.Lookup(&PerClusterNATMapKey{1})
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

	// Basic delete
	err = gm.DeleteClusterNATMaps(1)
	c.Assert(err, IsNil)

	_, err = gm.v4Map.Lookup(&PerClusterNATMapKey{1})
	c.Assert(err, NotNil)

	_, err = gm.v6Map.Lookup(&PerClusterNATMapKey{1})
	c.Assert(err, NotNil)

	for _, om := range []*PerClusterNATMap{gm.v4Map, gm.v6Map} {
		// After delete, outer map shouldn't contain the maps
		_, err := om.Lookup(&PerClusterNATMapKey{1})
		c.Assert(err, NotNil)
	}
}
