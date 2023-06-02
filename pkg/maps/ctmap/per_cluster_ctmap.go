// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ctmap

import (
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/pkg/bpf"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/lock"
)

// Global map that contains all per-cluster CT maps. The actual
// implementations are either perClusterCTMaps for real deployment
// and privileged tests or dummyPerClusterCTMaps for unprivileged
// testing.
var PerClusterCTMaps PerClusterCTMapper

const (
	perClusterCTMapMaxEntries = cmtypes.ClusterIDMax + 1

	PerClusterCTOuterMapPrefix   = "cilium_per_cluster_ct_"
	perClusterTCP4OuterMapSuffix = "tcp4"
	perClusterANY4OuterMapSuffix = "any4"
	perClusterTCP6OuterMapSuffix = "tcp6"
	perClusterANY6OuterMapSuffix = "any6"
)

// An interface to interact with all per-cluster CT maps
type PerClusterCTMapper interface {
	// Update all per-cluster CT maps for cluster with clusterID.
	UpdateClusterCTMaps(clusterID uint32) error
	// Delete all per-cluster CT maps for cluster with clusterID.
	DeleteClusterCTMaps(clusterID uint32) error
	// Get all per-cluster CT maps for cluster with clusterID.
	GetClusterCTMaps(clusterID uint32) []*Map
	// Get all per-cluster CT maps
	GetAllClusterCTMaps() ([]*Map, error)
	// Cleanup all per-cluster CT maps
	Cleanup()
}

// A "real" set of per-cluster CT maps. It implements PerClusterCTMapper.
type perClusterCTMaps struct {
	lock.RWMutex
	ipv4 bool
	ipv6 bool
	tcp4 *PerClusterCTMap
	any4 *PerClusterCTMap
	tcp6 *PerClusterCTMap
	any6 *PerClusterCTMap
}

// A "dummy" set of per-cluster CT maps for testing. It implements PerClusterCTMapper.
type dummyPerClusterCTMaps struct {
	lock.RWMutex
	ipv4 bool
	ipv6 bool
	tcp4 map[uint32]struct{}
	any4 map[uint32]struct{}
	tcp6 map[uint32]struct{}
	any6 map[uint32]struct{}
}

// PerClusterCTMap is a special conntrack map created when we
// enable cluster-aware addressing. As the name says, it is
// per-cluster and tracks the connection from/to specific
// remote clusters. It is implemented as an array-of-maps which
// its index is a ClusterID.
//
// Why can't we use global CT maps? That's because we currently
// don't have a good way of extending CT map's key without breaking
// user's connection. Thus, instead of extending existing CT map
// key with ClusterID, we chose to create CT map per-cluster. When
// we have a good way of extending global CT maps in the future, we
// should retire this entire file.
type PerClusterCTMap struct {
	*bpf.Map
	m mapType
}

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type PerClusterCTMapKey struct {
	ClusterID uint32
}

func (k *PerClusterCTMapKey) String() string            { return strconv.FormatUint(uint64(k.ClusterID), 10) }
func (k *PerClusterCTMapKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *PerClusterCTMapKey) NewValue() bpf.MapValue    { return &PerClusterCTMapVal{} }

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type PerClusterCTMapVal struct {
	Fd uint32
}

func (v *PerClusterCTMapVal) String() string              { return fmt.Sprintf("fd=%d", v.Fd) }
func (v *PerClusterCTMapVal) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

// Init a "real" global per-cluster CT maps
func InitPerClusterCTMaps(outerMapNamePrefix string, ipv4, ipv6 bool) error {
	m, err := newPerClusterCTMaps(outerMapNamePrefix, ipv4, ipv6)
	if err != nil {
		return err
	}

	PerClusterCTMaps = m

	return nil
}

func newPerClusterCTMaps(outerMapNamePrefix string, ipv4, ipv6 bool) (*perClusterCTMaps, error) {
	var err error

	gm := &perClusterCTMaps{
		ipv4: ipv4,
		ipv6: ipv6,
	}

	defer func() {
		if err != nil {
			for _, om := range []*PerClusterCTMap{gm.tcp4, gm.any4, gm.tcp6, gm.any6} {
				if om != nil {
					om.Unpin()
					om.Close()
				}
			}
		}
	}()

	if ipv4 {
		gm.tcp4, err = newPerClusterCTMap(outerMapNamePrefix+perClusterTCP4OuterMapSuffix, mapTypeIPv4TCPGlobal)
		if err != nil {
			return nil, err
		}

		gm.any4, err = newPerClusterCTMap(outerMapNamePrefix+perClusterANY4OuterMapSuffix, mapTypeIPv4AnyGlobal)
		if err != nil {
			return nil, err
		}
	}

	if ipv6 {
		gm.tcp6, err = newPerClusterCTMap(outerMapNamePrefix+perClusterTCP6OuterMapSuffix, mapTypeIPv6TCPGlobal)
		if err != nil {
			return nil, err
		}

		gm.any6, err = newPerClusterCTMap(outerMapNamePrefix+perClusterANY6OuterMapSuffix, mapTypeIPv6AnyGlobal)
		if err != nil {
			return nil, err
		}
	}

	return gm, nil
}

func getInnerMapName(outerMapName string, clusterID uint32) string {
	return outerMapName + "_" + strconv.FormatUint(uint64(clusterID), 10)
}

func (gm *perClusterCTMaps) UpdateClusterCTMaps(clusterID uint32) error {
	if err := cmtypes.ValidateClusterID(clusterID); err != nil {
		return err
	}

	gm.Lock()
	defer gm.Unlock()

	if gm.ipv4 {
		if err := gm.tcp4.updateClusterCTMap(clusterID); err != nil {
			return err
		}

		if err := gm.any4.updateClusterCTMap(clusterID); err != nil {
			return err
		}
	}

	if gm.ipv6 {
		if err := gm.tcp6.updateClusterCTMap(clusterID); err != nil {
			return err
		}

		if err := gm.any6.updateClusterCTMap(clusterID); err != nil {
			return err
		}
	}

	return nil
}

func (gm *perClusterCTMaps) DeleteClusterCTMaps(clusterID uint32) error {
	if err := cmtypes.ValidateClusterID(clusterID); err != nil {
		return err
	}

	gm.Lock()
	defer gm.Unlock()

	if gm.ipv4 {
		if err := gm.tcp4.deleteClusterCTMap(clusterID); err != nil {
			return err
		}

		if err := gm.any4.deleteClusterCTMap(clusterID); err != nil {
			return err
		}
	}

	if gm.ipv6 {
		if err := gm.tcp6.deleteClusterCTMap(clusterID); err != nil {
			return err
		}

		if err := gm.any6.deleteClusterCTMap(clusterID); err != nil {
			return err
		}
	}

	return nil
}

func (gm *perClusterCTMaps) GetClusterCTMaps(clusterID uint32) []*Map {
	var (
		err error
		im  *Map
	)

	ret := []*Map{}

	gm.RLock()
	defer gm.RUnlock()

	defer func() {
		if err != nil {
			for _, im := range ret {
				im.Unpin()
				im.Close()
			}
		}
	}()

	if gm.ipv4 {
		if im, err = gm.tcp4.getClusterMap(clusterID); err != nil {
			return []*Map{}
		} else {
			ret = append(ret, im)
		}
		if im, err = gm.any4.getClusterMap(clusterID); err != nil {
			return []*Map{}
		} else {
			ret = append(ret, im)
		}
	}

	if gm.ipv6 {
		if im, err = gm.tcp6.getClusterMap(clusterID); err != nil {
			return []*Map{}
		} else {
			ret = append(ret, im)
		}
		if im, err = gm.any6.getClusterMap(clusterID); err != nil {
			return []*Map{}
		} else {
			ret = append(ret, im)
		}
	}

	return ret
}

func (gm *perClusterCTMaps) GetAllClusterCTMaps() ([]*Map, error) {
	var err error
	ret := []*Map{}

	gm.RLock()
	defer gm.RUnlock()

	defer func() {
		if err != nil {
			for _, im := range ret {
				im.Close()
			}
		}
	}()

	if gm.ipv4 {
		if ims, err := gm.tcp4.getAllClusterMaps(); err != nil {
			return nil, err
		} else {
			ret = append(ret, ims...)
		}
		if ims, err := gm.any4.getAllClusterMaps(); err != nil {
			return nil, err
		} else {
			ret = append(ret, ims...)
		}
	}

	if gm.ipv6 {
		if ims, err := gm.tcp6.getAllClusterMaps(); err != nil {
			return nil, err
		} else {
			ret = append(ret, ims...)
		}
		if ims, err := gm.any6.getAllClusterMaps(); err != nil {
			return nil, err
		} else {
			ret = append(ret, ims...)
		}
	}

	return ret, nil
}

func (gm *perClusterCTMaps) Cleanup() {
	if gm.ipv4 {
		gm.tcp4.cleanup()
		gm.any4.cleanup()
		gm.tcp4 = nil
		gm.any4 = nil
	}
	if gm.ipv6 {
		gm.tcp6.cleanup()
		gm.any6.cleanup()
		gm.tcp6 = nil
		gm.any6 = nil
	}
}

// Init a "dummy" global per-cluster CT maps
func InitDummyPerClusterCTMaps(ipv4, ipv6 bool) {
	PerClusterCTMaps = newDummyPerClusterCTMaps(ipv4, ipv6)
}

func newDummyPerClusterCTMaps(ipv4, ipv6 bool) *dummyPerClusterCTMaps {
	gm := &dummyPerClusterCTMaps{
		ipv4: ipv4,
		ipv6: ipv6,
	}

	if ipv4 {
		gm.tcp4 = make(map[uint32]struct{})
		gm.any4 = make(map[uint32]struct{})
	}

	if ipv6 {
		gm.tcp6 = make(map[uint32]struct{})
		gm.any6 = make(map[uint32]struct{})
	}

	return gm
}

func (gm *dummyPerClusterCTMaps) UpdateClusterCTMaps(clusterID uint32) error {
	if err := cmtypes.ValidateClusterID(clusterID); err != nil {
		return err
	}

	gm.Lock()
	defer gm.Unlock()

	if gm.ipv4 {
		gm.tcp4[clusterID] = struct{}{}
		gm.any4[clusterID] = struct{}{}
	}

	if gm.ipv6 {
		gm.tcp6[clusterID] = struct{}{}
		gm.any6[clusterID] = struct{}{}
	}

	return nil
}

func (gm *dummyPerClusterCTMaps) DeleteClusterCTMaps(clusterID uint32) error {
	if err := cmtypes.ValidateClusterID(clusterID); err != nil {
		return err
	}

	gm.Lock()
	defer gm.Unlock()

	if gm.ipv4 {
		delete(gm.tcp4, clusterID)
		delete(gm.any4, clusterID)
	}

	if gm.ipv6 {
		delete(gm.tcp6, clusterID)
		delete(gm.any6, clusterID)
	}

	return nil
}

func (gm *dummyPerClusterCTMaps) GetClusterCTMaps(clusterID uint32) []*Map {
	ims := []*Map{}

	if err := cmtypes.ValidateClusterID(clusterID); err != nil {
		return []*Map{}
	}

	gm.Lock()
	defer gm.Unlock()

	if gm.ipv4 {
		if _, ok := gm.tcp4[clusterID]; ok {
			ims = append(ims, &Map{})
		}
		if _, ok := gm.any4[clusterID]; ok {
			ims = append(ims, &Map{})
		}
	}

	if gm.ipv6 {
		if _, ok := gm.tcp6[clusterID]; ok {
			ims = append(ims, &Map{})
		}
		if _, ok := gm.any6[clusterID]; ok {
			ims = append(ims, &Map{})
		}
	}

	return ims
}

func (gm *dummyPerClusterCTMaps) GetAllClusterCTMaps() ([]*Map, error) {
	ims := []*Map{}

	gm.RLock()
	defer gm.RUnlock()

	for i := uint32(1); i <= cmtypes.ClusterIDMax; i++ {
		if gm.ipv4 {
			if _, ok := gm.tcp4[i]; ok {
				ims = append(ims, &Map{})
			}
			if _, ok := gm.any4[i]; ok {
				ims = append(ims, &Map{})
			}
		}
		if gm.ipv6 {
			if _, ok := gm.tcp6[i]; ok {
				ims = append(ims, &Map{})
			}
			if _, ok := gm.any6[i]; ok {
				ims = append(ims, &Map{})
			}
		}
	}

	return ims, nil
}

func (gm *dummyPerClusterCTMaps) Cleanup() {
	gm.RLock()
	defer gm.RUnlock()

	if gm.ipv4 {
		gm.tcp4 = nil
		gm.any4 = nil
	}

	if gm.ipv6 {
		gm.tcp6 = nil
		gm.any6 = nil
	}

	return
}

func newPerClusterCTMap(name string, m mapType) (*PerClusterCTMap, error) {
	inner := &ebpf.MapSpec{
		Type:       ebpf.LRUHash,
		KeySize:    uint32(mapInfo[m].keySize),
		ValueSize:  uint32(mapInfo[m].valueSize),
		MaxEntries: uint32(mapInfo[m].maxEntries),
	}

	om := bpf.NewMapWithInnerSpec(
		name,
		bpf.MapTypeArrayOfMaps,
		&PerClusterCTMapKey{},
		&PerClusterCTMapVal{},
		perClusterCTMapMaxEntries,
		0,
		inner,
		bpf.ConvertKeyValue,
	)

	if err := om.OpenOrCreate(); err != nil {
		return nil, err
	}

	return &PerClusterCTMap{
		Map: om,
		m:   m,
	}, nil
}

func (om *PerClusterCTMap) newInnerMap(clusterID uint32) *Map {
	name := getInnerMapName(om.Name(), clusterID)
	im := newMap(name, om.m)
	im.clusterID = clusterID
	return im
}

func (om *PerClusterCTMap) updateClusterCTMap(clusterID uint32) error {
	if clusterID == 0 || clusterID > cmtypes.ClusterIDMax {
		return fmt.Errorf("invalid clusterID %d, clusterID should be 1 - %d", clusterID, cmtypes.ClusterIDMax)
	}

	im := om.newInnerMap(clusterID)

	if err := im.OpenOrCreate(); err != nil {
		return err
	}

	// Close the file descriptor, but won't unpin because we don't want to
	// lookup outer map (lookup of map-in-map is slow because it involves
	// RCU synchronization) and want to open inner map from bpffs.
	defer im.Close()

	if err := om.Update(
		&PerClusterCTMapKey{clusterID},
		&PerClusterCTMapVal{uint32(im.FD())},
	); err != nil {
		return err
	}

	return nil
}

func (om *PerClusterCTMap) deleteClusterCTMap(clusterID uint32) error {
	if clusterID == 0 || clusterID > cmtypes.ClusterIDMax {
		return fmt.Errorf("invalid clusterID %d, clusterID should be 1 - %d", clusterID, cmtypes.ClusterIDMax)
	}

	im := om.newInnerMap(clusterID)

	if err := im.Open(); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}

	// Release opened file descriptor and bpffs entry
	im.Close()
	im.Unpin()

	// Detach inner map from outer map. At this point, no
	// one should have the reference of the inner map after
	// this call.
	if _, err := om.SilentDelete(&PerClusterCTMapKey{clusterID}); err != nil {
		return err
	}

	return nil
}

func (om *PerClusterCTMap) getClusterMap(clusterID uint32) (*Map, error) {
	if clusterID == 0 || clusterID > cmtypes.ClusterIDMax {
		return nil, fmt.Errorf("invalid clusterID %d, clusterID should be 1 - %d", clusterID, cmtypes.ClusterIDMax)
	}

	im := om.newInnerMap(clusterID)

	if err := im.Open(); err != nil {
		return nil, fmt.Errorf("open inner map: %w", err)
	}

	// Callers are responsible for closing returned map
	return im, nil
}

func (om *PerClusterCTMap) getAllClusterMaps() ([]*Map, error) {
	var (
		err error
		im  *Map
	)

	innerMaps := []*Map{}

	defer func() {
		if err != nil {
			for _, im := range innerMaps {
				im.Close()
			}
		}
	}()

	for i := uint32(1); i <= cmtypes.ClusterIDMax; i++ {
		im, err = om.getClusterMap(i)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return nil, err
		}
		innerMaps = append(innerMaps, im)
	}

	return innerMaps, nil
}

func (om *PerClusterCTMap) cleanup() {
	for i := uint32(1); i <= cmtypes.ClusterIDMax; i++ {
		om.deleteClusterCTMap(i)
	}
	om.Unpin()
	om.Close()
}
