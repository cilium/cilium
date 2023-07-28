// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nat

import (
	"errors"
	"fmt"
	"strconv"
	"unsafe"

	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/pkg/bpf"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/lock"
)

const (
	perClusterOuterMapPrefix = "cilium_per_cluster_snat_"
	perClusterIPv4OuterMap   = perClusterOuterMapPrefix + "v4_external"
	perClusterIPv6OuterMap   = perClusterOuterMapPrefix + "v6_external"
	perClusterMapMaxEntries  = cmtypes.ClusterIDMax + 1
)

// ClusterOuterMapName returns the name of the outer per-cluster NAT map
// for the given IP family. It can be overwritten for testing purposes.
var ClusterOuterMapName = clusterOuterMapName

func clusterOuterMapName(family IPFamily) string {
	if family == IPv4 {
		return perClusterIPv4OuterMap
	}
	return perClusterIPv6OuterMap
}

func ClusterOuterMapNameTestOverride(prefix string) {
	ClusterOuterMapName = func(family IPFamily) string {
		return prefix + "_" + clusterOuterMapName(family)
	}
}

// ClusterInnerMapName returns the name of the inner per-cluster NAT map
// for the given IP family and cluster ID.
func ClusterInnerMapName(family IPFamily, clusterID uint32) string {
	return ClusterOuterMapName(family) + "_" + strconv.FormatUint(uint64(clusterID), 10)
}

var _ PerClusterNATMapper = (*perClusterNATMaps)(nil)

// An interface to manage the per-cluster NAT maps.
type PerClusterNATMapper interface {
	// Create enforces the presence of the outer per-cluster NAT maps.
	OpenOrCreate() error
	// Close closes the outer per-cluster NAT maps handlers.
	Close() error

	// CreateClusterNATMaps enforces the presence of the inner maps for
	// the given cluster ID. It must be called after that OpenOrCreate()
	// has returned successfully.
	CreateClusterNATMaps(clusterID uint32) error
	// DeleteClusterNATMaps deletes the inner maps for the given cluster ID.
	// It must be called after that OpenOrCreate() has returned successfully.
	DeleteClusterNATMaps(clusterID uint32) error
}

// NewPerClusterNATMaps returns a new instance of the per-cluster NAT maps manager.
func NewPerClusterNATMaps(ipv4, ipv6 bool) *perClusterNATMaps {
	return newPerClusterNATMaps(ipv4, ipv6, maxEntries())
}

// GetClusterNATMap returns the per-cluster map for the given cluster ID. The
// returned map needs to be opened by the caller, and it is not guaranteed to exist.
func GetClusterNATMap(clusterID uint32, family IPFamily) (*Map, error) {
	maps := NewPerClusterNATMaps(family == IPv4, family == IPv6)
	return maps.getClusterNATMap(clusterID, family)
}

// CleanupPerClusterNATMaps deletes the per-cluster NAT maps, including the inner ones.
func CleanupPerClusterNATMaps(ipv4, ipv6 bool) error {
	maps := NewPerClusterNATMaps(ipv4, ipv6)
	return maps.cleanup()
}

// A structure that holds per-cluster IPv4 and v6 NAT maps. It implements
// PerClusterNATMapper.
type perClusterNATMaps struct {
	lock.RWMutex
	v4Map *perClusterNATMap
	v6Map *perClusterNATMap
}

// A map-in-map that holds per-cluster NAT maps.
type perClusterNATMap struct {
	*bpf.Map
	family          IPFamily
	innerMapEntries int
}

type PerClusterNATMapKey struct {
	ClusterID uint32
}

func (k *PerClusterNATMapKey) String() string  { return strconv.FormatUint(uint64(k.ClusterID), 10) }
func (n *PerClusterNATMapKey) New() bpf.MapKey { return &PerClusterNATMapKey{} }

type PerClusterNATMapVal struct {
	Fd uint32
}

func (v *PerClusterNATMapVal) String() string    { return fmt.Sprintf("fd=%d", v.Fd) }
func (n *PerClusterNATMapVal) New() bpf.MapValue { return &PerClusterNATMapVal{} }

func newPerClusterNATMap(family IPFamily, innerMapEntries int) *perClusterNATMap {
	var (
		keySize uint32
		valSize uint32
	)

	if family == IPv4 {
		keySize = uint32(unsafe.Sizeof(NatKey4{}))
		valSize = uint32(unsafe.Sizeof(NatEntry4{}))
	} else {
		keySize = uint32(unsafe.Sizeof(NatKey6{}))
		valSize = uint32(unsafe.Sizeof(NatEntry6{}))
	}

	inner := &ebpf.MapSpec{
		Type:       ebpf.LRUHash,
		KeySize:    keySize,
		ValueSize:  valSize,
		MaxEntries: uint32(innerMapEntries),
	}

	om := bpf.NewMapWithInnerSpec(
		ClusterOuterMapName(family),
		ebpf.ArrayOfMaps,
		&PerClusterNATMapKey{},
		&PerClusterNATMapVal{},
		perClusterMapMaxEntries,
		0,
		inner,
	)

	return &perClusterNATMap{
		Map:             om,
		family:          family,
		innerMapEntries: innerMapEntries,
	}
}

func (om *perClusterNATMap) newInnerMap(clusterID uint32) *Map {
	return NewMap(ClusterInnerMapName(om.family, clusterID), om.family, om.innerMapEntries)
}

func (om *perClusterNATMap) createClusterNATMap(clusterID uint32) error {
	im := om.newInnerMap(clusterID)
	if err := im.OpenOrCreate(); err != nil {
		return fmt.Errorf("create inner map: %w", err)
	}

	defer im.Close()

	if err := om.Update(
		&PerClusterNATMapKey{clusterID},
		&PerClusterNATMapVal{uint32(im.FD())},
	); err != nil {
		return fmt.Errorf("update outer map: %w", err)
	}

	return nil
}

func (om *perClusterNATMap) deleteClusterNATMap(clusterID uint32) error {
	im := om.newInnerMap(clusterID)
	if err := im.Unpin(); err != nil {
		return fmt.Errorf("delete inner map: %w", err)
	}

	// Detach inner map from outer map. At this point, no
	// one should have the reference of the inner map after
	// this call.
	if _, err := om.SilentDelete(&PerClusterNATMapKey{clusterID}); err != nil {
		return fmt.Errorf("update outer map: %w", err)
	}

	return nil
}

func (om *perClusterNATMap) cleanup() error {
	var errs []error

	for id := uint32(1); id <= cmtypes.ClusterIDMax; id++ {
		im := om.newInnerMap(id)
		if err := im.Unpin(); err != nil {
			errs = append(errs, fmt.Errorf("delete inner map for cluster ID %v: %w", id, err))
		}
	}

	if err := om.Unpin(); err != nil {
		errs = append(errs, fmt.Errorf("delete outer map: %w", err))
	}

	return errors.Join(errs...)
}

func newPerClusterNATMaps(ipv4, ipv6 bool, innerMapEntries int) *perClusterNATMaps {
	var gm perClusterNATMaps

	if ipv4 {
		gm.v4Map = newPerClusterNATMap(IPv4, innerMapEntries)
	}

	if ipv6 {
		gm.v6Map = newPerClusterNATMap(IPv6, innerMapEntries)
	}

	return &gm
}

func (gm *perClusterNATMaps) OpenOrCreate() (err error) {
	return gm.foreach(
		func(om *perClusterNATMap) error { return om.OpenOrCreate() },
	)
}

func (gm *perClusterNATMaps) Close() (err error) {
	return gm.foreach(
		func(om *perClusterNATMap) error { return om.Close() },
	)
}

func (gm *perClusterNATMaps) CreateClusterNATMaps(clusterID uint32) error {
	if err := cmtypes.ValidateClusterID(clusterID); err != nil {
		return err
	}

	return gm.foreach(
		func(om *perClusterNATMap) error { return om.createClusterNATMap(clusterID) },
	)
}

func (gm *perClusterNATMaps) DeleteClusterNATMaps(clusterID uint32) error {
	if err := cmtypes.ValidateClusterID(clusterID); err != nil {
		return err
	}

	return gm.foreach(func(om *perClusterNATMap) error {
		return om.deleteClusterNATMap(clusterID)
	})
}

func (gm *perClusterNATMaps) getClusterNATMap(clusterID uint32, family IPFamily) (*Map, error) {
	if err := cmtypes.ValidateClusterID(clusterID); err != nil {
		return nil, err
	}

	gm.RLock()
	defer gm.RUnlock()

	if family == IPv4 && gm.v4Map == nil || family == IPv6 && gm.v6Map == nil {
		return nil, fmt.Errorf("IP family %s not enabled", family)
	}

	if family == IPv4 {
		return gm.v4Map.newInnerMap(clusterID), nil
	}

	return gm.v6Map.newInnerMap(clusterID), nil
}

func (gm *perClusterNATMaps) cleanup() error {
	return gm.foreach(func(om *perClusterNATMap) error {
		return om.cleanup()
	})
}

func (gm *perClusterNATMaps) foreach(fn func(om *perClusterNATMap) error) error {
	gm.Lock()
	defer gm.Unlock()

	var errs []error

	// Attempt to perform the given operation on all maps, and collect all
	// errors that are encountered. We do not implement a rollback mechanism
	// in case of failures to keep the overall logic simple, as it is likely
	// that the consumer of the different methods will nonetheless retry again
	// the same operation on error. Hence, the rollback would only introduce
	// additional churn, and it might not be even possible in certain cases
	// (e.g., for deletion operations, to restore the previous state).
	for _, om := range []*perClusterNATMap{gm.v4Map, gm.v6Map} {
		if om != nil {
			if err := fn(om); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", om.family, err))
			}
		}
	}

	return errors.Join(errs...)
}
