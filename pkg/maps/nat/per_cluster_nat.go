// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nat

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/lock"
)

const (
	mapNamePerClusterSnat4Global = "cilium_per_cluster_snat_v4_external"
	mapNamePerClusterSnat6Global = "cilium_per_cluster_snat_v6_external"
	innerMapNamePrefix4          = MapNameSnat4Global + "_"
	innerMapNamePrefix6          = MapNameSnat6Global + "_"
	perClusterNATMapMaxEntries   = cmtypes.ClusterIDMax + 1
)

// Global interface to interact with IPv4 and v6 NAT maps. We can choose the
// implementation of this at startup time by choosing InitPerClusterNATMaps
// or InitDummyPerClusterNATMaps for initialization.
var PerClusterNATMaps PerClusterNATMapper

// An interface to interact with the global map.
type PerClusterNATMapper interface {
	UpdateClusterNATMaps(clusterID uint32) error
	DeleteClusterNATMaps(clusterID uint32) error
	GetClusterNATMap(clusterID uint32, v4 bool) (*Map, error)
	Cleanup()
}

// A structure that holds per-cluster IPv4 and v6 NAT maps. It implements
// PerClusterNATMapper.
type perClusterNATMaps struct {
	lock.RWMutex
	v4Map *PerClusterNATMap
	v6Map *PerClusterNATMap
}

// A structure that holds dummy IPv4 and v6 NAT maps for testing. It
// implements PerClusterNATMapper.
type dummyPerClusterNATMaps struct {
	lock.RWMutex
	v4Map map[uint32]struct{}
	v6Map map[uint32]struct{}
}

// A map-in-map that holds per-cluster NAT maps.
type PerClusterNATMap struct {
	*bpf.Map
	v4              bool
	innerMapEntries int
}

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type PerClusterNATMapKey struct {
	ClusterID uint32
}

func (k *PerClusterNATMapKey) String() string            { return strconv.FormatUint(uint64(k.ClusterID), 10) }
func (k *PerClusterNATMapKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *PerClusterNATMapKey) NewValue() bpf.MapValue    { return &PerClusterNATMapVal{} }

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type PerClusterNATMapVal struct {
	Fd uint32
}

func (v *PerClusterNATMapVal) String() string              { return fmt.Sprintf("fd=%d", v.Fd) }
func (v *PerClusterNATMapVal) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

func newPerClusterNATMap(name string, v4 bool, innerMapEntries int) (*PerClusterNATMap, error) {
	var (
		keySize uint32
		valSize uint32
	)

	if v4 {
		keySize = uint32(unsafe.Sizeof(NatKey4{}))
		valSize = uint32(unsafe.Sizeof(NatEntry4{}))
	} else {
		keySize = uint32(unsafe.Sizeof(NatKey6{}))
		valSize = uint32(unsafe.Sizeof(NatEntry6{}))
	}

	fd, err := bpf.CreateMap(
		bpf.MapTypeLRUHash,
		keySize,
		valSize,
		uint32(innerMapEntries),
		0, 0,
		name+"_tmp",
	)
	if err != nil {
		return nil, err
	}

	defer syscall.Close(fd)

	om := bpf.NewMap(
		name,
		bpf.MapTypeArrayOfMaps,
		&PerClusterNATMapKey{},
		int(unsafe.Sizeof(PerClusterNATMapKey{})),
		&PerClusterNATMapVal{},
		int(unsafe.Sizeof(PerClusterNATMapVal{})),
		perClusterNATMapMaxEntries,
		0,
		uint32(fd),
		bpf.ConvertKeyValue,
	)

	if _, err := om.OpenOrCreate(); err != nil {
		return nil, err
	}

	return &PerClusterNATMap{
		Map:             om,
		v4:              v4,
		innerMapEntries: innerMapEntries,
	}, nil
}

func (om *PerClusterNATMap) newInnerMap(name string) *Map {
	return NewMap(name, om.v4, om.innerMapEntries)
}

func (om *PerClusterNATMap) getInnerMapName(clusterID uint32) string {
	if om.v4 {
		return innerMapNamePrefix4 + strconv.FormatUint(uint64(clusterID), 10)
	} else {
		return innerMapNamePrefix6 + strconv.FormatUint(uint64(clusterID), 10)
	}
}

func (om *PerClusterNATMap) updateClusterNATMap(clusterID uint32) error {
	if err := cmtypes.ValidateClusterID(clusterID); err != nil {
		return err
	}

	im := om.newInnerMap(om.getInnerMapName(clusterID))

	_, err := im.OpenOrCreate()
	if err != nil {
		return err
	}

	defer im.Close()

	if err := om.Update(
		&PerClusterNATMapKey{clusterID},
		&PerClusterNATMapVal{uint32(im.GetFd())},
	); err != nil {
		return err
	}

	return nil
}

func (om *PerClusterNATMap) deleteClusterNATMap(clusterID uint32) error {
	if err := cmtypes.ValidateClusterID(clusterID); err != nil {
		return err
	}

	im := om.newInnerMap(om.getInnerMapName(clusterID))

	if _, err := im.OpenOrCreate(); err != nil {
		return err
	}

	// Release opened file descriptor and bpffs entry
	im.Close()
	im.Unpin()

	// Detach inner map from outer map. At this point, no
	// one should have the reference of the inner map after
	// this call.
	if _, err := om.SilentDelete(&PerClusterNATMapKey{clusterID}); err != nil {
		return err
	}

	return nil
}

func (om *PerClusterNATMap) getClusterNATMap(clusterID uint32) (*Map, error) {
	if err := cmtypes.ValidateClusterID(clusterID); err != nil {
		return nil, err
	}

	im := om.newInnerMap(om.getInnerMapName(clusterID))

	if err := im.Open(); err != nil {
		if pathErr, ok := err.(*os.PathError); ok && errors.Is(pathErr.Err, unix.ENOENT) {
			return nil, nil
		}
	}

	return im, nil
}

func (om *PerClusterNATMap) cleanup() {
	for i := uint32(1); i < perClusterNATMapMaxEntries; i++ {
		om.deleteClusterNATMap(i)
	}
	om.Unpin()
	om.Close()
}

func InitPerClusterNATMaps(ipv4, ipv6 bool, innerMapEntries int) error {
	gm, err := newPerClusterNATMaps(ipv4, ipv6, innerMapEntries)
	if err != nil {
		return err
	}

	PerClusterNATMaps = gm

	return nil
}

func newPerClusterNATMaps(ipv4, ipv6 bool, innerMapEntries int) (*perClusterNATMaps, error) {
	var err error

	gm := &perClusterNATMaps{}

	defer func() {
		if err != nil {
			for _, om := range []*PerClusterNATMap{gm.v4Map, gm.v6Map} {
				if om != nil {
					om.Unpin()
					om.Close()
				}
			}
		}
	}()

	if ipv4 {
		gm.v4Map, err = newPerClusterNATMap(mapNamePerClusterSnat4Global, true, innerMapEntries)
		if err != nil {
			return nil, err
		}
	}

	if ipv6 {
		gm.v6Map, err = newPerClusterNATMap(mapNamePerClusterSnat6Global, false, innerMapEntries)
		if err != nil {
			return nil, err
		}
	}

	return gm, nil
}

func (gm *perClusterNATMaps) UpdateClusterNATMaps(clusterID uint32) error {
	gm.Lock()
	defer gm.Unlock()

	if gm.v4Map != nil {
		if err := gm.v4Map.updateClusterNATMap(clusterID); err != nil {
			return err
		}
	}

	if gm.v6Map != nil {
		if err := gm.v6Map.updateClusterNATMap(clusterID); err != nil {
			return err
		}
	}

	return nil
}

func (gm *perClusterNATMaps) DeleteClusterNATMaps(clusterID uint32) error {
	gm.Lock()
	defer gm.Unlock()

	if gm.v4Map != nil {
		if err := gm.v4Map.deleteClusterNATMap(clusterID); err != nil {
			return err
		}
	}

	if gm.v6Map != nil {
		if err := gm.v6Map.deleteClusterNATMap(clusterID); err != nil {
			return err
		}
	}

	return nil
}

func (gm *perClusterNATMaps) GetClusterNATMap(clusterID uint32, v4 bool) (*Map, error) {
	gm.RLock()
	defer gm.RUnlock()

	if v4 {
		if im, err := gm.v4Map.getClusterNATMap(clusterID); err != nil {
			return nil, err
		} else {
			return im, nil
		}
	} else {
		if im, err := gm.v6Map.getClusterNATMap(clusterID); err != nil {
			return nil, err
		} else {
			return im, nil
		}
	}
}

func (gm *perClusterNATMaps) Cleanup() {
	gm.Lock()
	defer gm.Unlock()

	if gm.v4Map != nil {
		gm.v4Map.cleanup()
	}

	if gm.v6Map != nil {
		gm.v6Map.cleanup()
	}
}

func InitDummyPerClusterNATMaps(ipv4, ipv6 bool, innerMapEntries int) error {
	gm, err := newDummyPerClusterNATMaps(ipv4, ipv6, innerMapEntries)
	if err != nil {
		return err
	}

	PerClusterNATMaps = gm

	return nil
}

func newDummyPerClusterNATMaps(ipv4, ipv6 bool, innerMapEntries int) (*dummyPerClusterNATMaps, error) {
	gm := &dummyPerClusterNATMaps{}

	if ipv4 {
		gm.v4Map = make(map[uint32]struct{})
	}

	if ipv6 {
		gm.v6Map = make(map[uint32]struct{})
	}

	return gm, nil
}

func (gm *dummyPerClusterNATMaps) UpdateClusterNATMaps(clusterID uint32) error {
	gm.Lock()
	defer gm.Unlock()

	if gm.v4Map != nil {
		gm.v4Map[clusterID] = struct{}{}
	}

	if gm.v6Map != nil {
		gm.v6Map[clusterID] = struct{}{}
	}

	return nil
}

func (gm *dummyPerClusterNATMaps) DeleteClusterNATMaps(clusterID uint32) error {
	gm.Lock()
	defer gm.Unlock()

	if gm.v4Map != nil {
		delete(gm.v4Map, clusterID)
	}

	if gm.v6Map != nil {
		delete(gm.v6Map, clusterID)
	}

	return nil
}

func (gm *dummyPerClusterNATMaps) GetClusterNATMap(clusterID uint32, v4 bool) (*Map, error) {
	gm.RLock()
	defer gm.RUnlock()

	if v4 {
		if _, ok := gm.v4Map[clusterID]; ok {
			return &Map{}, nil
		}
		return nil, nil
	} else {
		if _, ok := gm.v6Map[clusterID]; ok {
			return &Map{}, nil
		}
		return nil, nil
	}
}

func (gm *dummyPerClusterNATMaps) Cleanup() {
	for i := uint32(1); i < perClusterNATMapMaxEntries; i++ {
		gm.DeleteClusterNATMaps(i)
	}
	gm.v4Map = nil
	gm.v6Map = nil
}
