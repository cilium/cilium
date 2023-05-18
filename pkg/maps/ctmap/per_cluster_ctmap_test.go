// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ctmap

import (
	. "github.com/cilium/checkmate"

	"github.com/cilium/ebpf/rlimit"

	"github.com/cilium/cilium/pkg/bpf"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/testutils"
)

type PerClusterCTMapPrivilegedTestSuite struct{}

var _ = Suite(&PerClusterCTMapPrivilegedTestSuite{})

const (
	testPerClusterCTMapNamePrefix = "test_cilium_per_cluster_ct_"
)

func (k *PerClusterCTMapPrivilegedTestSuite) SetUpSuite(c *C) {
	testutils.PrivilegedCheck(c)

	bpf.CheckOrMountFS("")
	err := rlimit.RemoveMemlock()
	c.Assert(err, IsNil)
}

func (k *PerClusterCTMapPrivilegedTestSuite) SetUpTest(c *C) {
	// Prepare all per-cluster ctmaps
	if err := InitPerClusterCTMaps(testPerClusterCTMapNamePrefix, true, true); err != nil {
		panic(err)
	}
}

func (k *PerClusterCTMapPrivilegedTestSuite) TearDownTest(c *C) {
	PerClusterCTMaps.Cleanup()
}

func (k *PerClusterCTMapPrivilegedTestSuite) Benchmark_PerClusterCTMapUpdate(c *C) {
	c.StopTimer()

	om, err := newPerClusterCTMap(testPerClusterCTMapNamePrefix+"tcp4", mapTypeIPv4TCPGlobal)
	c.Assert(err, IsNil)

	defer om.Unpin()
	defer om.Close()

	c.StartTimer()

	for i := 0; i < c.N; i++ {
		err = om.updateClusterCTMap(1)
		c.Assert(err, IsNil)
	}

	c.StopTimer()
}

func (k *PerClusterCTMapPrivilegedTestSuite) Benchmark_PerClusterCTMapLookup(c *C) {
	c.StopTimer()

	om, err := newPerClusterCTMap(testPerClusterCTMapNamePrefix+"tcp4", mapTypeIPv4TCPGlobal)
	c.Assert(err, IsNil)

	defer om.Unpin()
	defer om.Close()

	err = om.updateClusterCTMap(1)
	c.Assert(err, IsNil)

	c.StartTimer()

	key := &PerClusterCTMapKey{1}
	for i := 0; i < c.N; i++ {
		_, err = om.Lookup(key)
		c.Assert(err, IsNil)
	}

	c.StopTimer()
}

func (k *PerClusterCTMapPrivilegedTestSuite) TestPerClusterCTMap(c *C) {
	om, err := newPerClusterCTMap(testPerClusterCTMapNamePrefix+"tcp4", mapTypeIPv4TCPGlobal)
	c.Assert(err, IsNil)

	defer om.Unpin()
	defer om.Close()

	// ClusterID 0 should never be used
	err = om.updateClusterCTMap(0)
	c.Assert(err, NotNil)

	// ClusterID beyond the ClusterIDMax should never be used
	err = om.updateClusterCTMap(cmtypes.ClusterIDMax + 1)
	c.Assert(err, NotNil)

	// Basic update
	cluster1MapName := om.innerMapNamePrefix + "1"
	err = om.updateClusterCTMap(1)
	c.Assert(err, IsNil)

	// After update, outer map should be updated with the inner map
	v, err := om.Lookup(&PerClusterCTMapKey{1})
	c.Assert(err, IsNil)
	c.Assert(v, Not(Equals), 0)

	// Inner map should exist on the bpffs
	fd, err := bpf.ObjGet(bpf.MapPath(cluster1MapName))
	c.Assert(err, IsNil)
	c.Assert(fd, Not(Equals), 0)

	// Inner map should not exist on the global registry
	c.Assert(bpf.GetMap(cluster1MapName), IsNil)

	// Basic Get
	im, err := om.getClusterMap(1)
	c.Assert(im, NotNil)
	c.Assert(err, IsNil)

	im.Close()

	// Getting unexisting entry returns nil, nil
	im, err = om.getClusterMap(2)
	c.Assert(im, IsNil)
	c.Assert(err, IsNil)

	// Basic all get
	ims, err := om.getAllClusterMaps()
	c.Assert(len(ims), Equals, 1)
	c.Assert(err, IsNil)

	for _, im := range ims {
		im.Close()
	}

	// Basic delete
	err = om.deleteClusterCTMap(1)
	c.Assert(err, IsNil)

	// After delete, outer map shouldn't contain the inner map
	_, err = om.Lookup(&PerClusterCTMapKey{1})
	c.Assert(err, NotNil)

	// Inner map shouldn't exist on the bpffs
	_, err = bpf.ObjGet(bpf.MapPath(cluster1MapName))
	c.Assert(err, NotNil)
}

func (k *PerClusterCTMapPrivilegedTestSuite) TestPerClusterCTMaps(c *C) {
	gm, err := newPerClusterCTMaps(testPerClusterCTMapNamePrefix, true, true)
	c.Assert(err, IsNil)

	defer gm.Cleanup()

	// ClusterID 0 should never be used
	err = gm.UpdateClusterCTMaps(0)
	c.Assert(err, NotNil)

	// ClusterID beyond the ClusterIDMax should never be used
	err = gm.UpdateClusterCTMaps(cmtypes.ClusterIDMax + 1)
	c.Assert(err, NotNil)

	// Basic Update
	err = gm.UpdateClusterCTMaps(1)
	c.Assert(err, IsNil)

	for _, om := range []*PerClusterCTMap{gm.tcp4, gm.tcp6, gm.any4, gm.any6} {
		// After update, outer map should be updated with the inner map
		v, err := om.Lookup(&PerClusterCTMapKey{1})
		c.Assert(err, IsNil)
		c.Assert(v, Not(Equals), 0)
	}

	// Basic all get
	ims, err := gm.GetAllClusterCTMaps()
	c.Assert(err, IsNil)
	c.Assert(len(ims), Equals, 4)

	for _, im := range ims {
		im.Close()
	}

	// Basic delete
	err = gm.DeleteClusterCTMaps(1)
	c.Assert(err, IsNil)

	for _, om := range []*PerClusterCTMap{gm.tcp4, gm.tcp6, gm.any4, gm.any6} {
		// After delete, outer map shouldn't contain the maps
		_, err := om.Lookup(&PerClusterCTMapKey{1})
		c.Assert(err, NotNil)
	}
}
