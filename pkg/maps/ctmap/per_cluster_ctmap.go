// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ctmap

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"

	"github.com/cilium/ebpf"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/bpf"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/lock"
)

const (
	perClusterCTOuterMapPrefix = "cilium_per_cluster_ct_"
)

// ClusterOuterMapName returns the name of the outer per-cluster CT map
// for the given type. It can be overwritten for testing purposes.
var ClusterOuterMapName = clusterOuterMapName

func clusterOuterMapName(typ mapType) string {
	return perClusterCTOuterMapPrefix + typ.name()
}

func ClusterOuterMapNameTestOverride(prefix string) {
	ClusterOuterMapName = func(typ mapType) string {
		return prefix + "_" + clusterOuterMapName(typ)
	}
}

// ClusterInnerMapName returns the name of the inner per-cluster NAT map
// for the given IP family and cluster ID.
func ClusterInnerMapName(typ mapType, clusterID uint32) string {
	return ClusterOuterMapName(typ) + "_" + strconv.FormatUint(uint64(clusterID), 10)
}

var _ PerClusterCTMapper = (*perClusterCTMaps)(nil)

// An interface to manage the per-cluster CT maps.
type PerClusterCTMapper interface {
	// Create enforces the presence of the outer per-cluster CT maps.
	OpenOrCreate() error
	// Close closes the outer per-cluster CT maps handlers.
	Close() error

	// CreateClusterNATMaps enforces the presence of the inner maps for
	// the given cluster ID. It must be called after that OpenOrCreate()
	// has returned successfully.
	CreateClusterCTMaps(clusterID uint32) error
	// DeleteClusterNATMaps deletes the inner maps for the given cluster ID.
	// It must be called after that OpenOrCreate() has returned successfully.
	DeleteClusterCTMaps(clusterID uint32) error

	// GetClusterCTMaps returns the per-cluster maps for each known cluster ID.
	// The returned maps need to be opened by the caller.
	GetAllClusterCTMaps() []*Map
}

// GetClusterCTMaps returns the per-cluster maps for the given cluster ID. The
// returned maps need to be opened by the caller, and are not guaranteed to exist.
func GetClusterCTMaps(clusterID uint32, ipv4, ipv6 bool) ([]*Map, error) {
	maps := NewPerClusterCTMaps(ipv4, ipv6)
	return maps.getClusterCTMaps(clusterID)
}

// CleanupPerClusterCTMaps deletes the per-cluster CT maps, including the inner ones.
func CleanupPerClusterCTMaps(ipv4, ipv6 bool) error {
	maps := NewPerClusterCTMaps(ipv4, ipv6)
	return maps.cleanup()
}

// A "real" set of per-cluster CT maps. It implements PerClusterCTMapper.
type perClusterCTMaps struct {
	lock.RWMutex

	tcp4 *PerClusterCTMap
	any4 *PerClusterCTMap
	tcp6 *PerClusterCTMap
	any6 *PerClusterCTMap

	// clusterIDs tracks the inner CT maps that have been created,
	// to optimize the GetAllClusterCTMaps implementation.
	clusterIDs sets.Set[uint32]
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

type PerClusterCTMapKey struct {
	ClusterID uint32
}

func (k *PerClusterCTMapKey) String() string  { return strconv.FormatUint(uint64(k.ClusterID), 10) }
func (k *PerClusterCTMapKey) New() bpf.MapKey { return &PerClusterCTMapKey{} }

type PerClusterCTMapVal struct {
	Fd uint32
}

func (v *PerClusterCTMapVal) String() string    { return fmt.Sprintf("fd=%d", v.Fd) }
func (v *PerClusterCTMapVal) New() bpf.MapValue { return &PerClusterCTMapVal{} }

// NewPerClusterCTMaps returns a new instance of the per-cluster CT maps manager.
func NewPerClusterCTMaps(ipv4, ipv6 bool) *perClusterCTMaps {
	gm := perClusterCTMaps{clusterIDs: sets.New[uint32]()}

	if ipv4 {
		gm.tcp4 = newPerClusterCTMap(mapTypeIPv4TCPGlobal)
		gm.any4 = newPerClusterCTMap(mapTypeIPv4AnyGlobal)
	}

	if ipv6 {
		gm.tcp6 = newPerClusterCTMap(mapTypeIPv6TCPGlobal)
		gm.any6 = newPerClusterCTMap(mapTypeIPv6AnyGlobal)
	}

	return &gm
}

func (gm *perClusterCTMaps) OpenOrCreate() (err error) {
	gm.Lock()
	defer gm.Unlock()

	return gm.foreach(
		func(om *PerClusterCTMap) error { return om.OpenOrCreate() },
	)
}

func (gm *perClusterCTMaps) Close() (err error) {
	gm.Lock()
	defer gm.Unlock()

	return gm.foreach(
		func(om *PerClusterCTMap) error { return om.Close() },
	)
}

func (gm *perClusterCTMaps) CreateClusterCTMaps(clusterID uint32) error {
	if err := cmtypes.ValidateClusterID(clusterID); err != nil {
		return err
	}

	gm.Lock()
	defer gm.Unlock()

	// We don't rollback the insertion of the current ClusterID in case the maps
	// creation fails (as we also don't rollback the maps insertion itself).
	// Indeed, this is only used as an optimization when retrieving all maps
	// (for the GC process), and non-existing maps will be automatically skipped.
	gm.clusterIDs.Insert(clusterID)

	return gm.foreach(
		func(om *PerClusterCTMap) error { return om.createClusterCTMap(clusterID) },
	)
}

func (gm *perClusterCTMaps) DeleteClusterCTMaps(clusterID uint32) error {
	if err := cmtypes.ValidateClusterID(clusterID); err != nil {
		return err
	}

	gm.Lock()
	defer gm.Unlock()

	// We don't rollback the deletion of the current ClusterID in case the maps
	// removal fails (as we also don't rollback the maps removal itself).
	// Indeed, this is only used as an optimization when retrieving all maps
	// (for the GC process), and the maps are expected to be deleted at this point.
	gm.clusterIDs.Delete(clusterID)

	return gm.foreach(
		func(om *PerClusterCTMap) error { return om.deleteClusterCTMap(clusterID) },
	)
}

func (gm *perClusterCTMaps) GetAllClusterCTMaps() []*Map {
	gm.Lock()
	defer gm.Unlock()

	var maps []*Map
	for clusterID := range gm.clusterIDs {
		gm.foreach(func(om *PerClusterCTMap) error {
			maps = append(maps, om.newInnerMap(clusterID))
			return nil
		})
	}
	return maps
}

func (gm *perClusterCTMaps) getClusterCTMaps(clusterID uint32) ([]*Map, error) {
	if err := cmtypes.ValidateClusterID(clusterID); err != nil {
		return nil, err
	}

	gm.Lock()
	defer gm.Unlock()

	var maps []*Map
	gm.foreach(func(om *PerClusterCTMap) error {
		maps = append(maps, om.newInnerMap(clusterID))
		return nil
	})

	return maps, nil
}

func (gm *perClusterCTMaps) cleanup() error {
	gm.Lock()
	defer gm.Unlock()

	return gm.foreach(func(om *PerClusterCTMap) error {
		return om.cleanup()
	})
}

func (gm *perClusterCTMaps) foreach(fn func(om *PerClusterCTMap) error) error {
	var errs []error

	// Attempt to perform the given operation on all maps, and collect all
	// errors that are encountered. We do not implement a rollback mechanism
	// in case of failures to keep the overall logic simple, as it is likely
	// that the consumer of the different methods will nonetheless retry again
	// the same operation on error. Hence, the rollback would only introduce
	// additional churn, and it might not be even possible in certain cases
	// (e.g., for deletion operations, to restore the previous state).
	for _, om := range []*PerClusterCTMap{gm.tcp4, gm.any4, gm.tcp6, gm.any6} {
		if om != nil {
			if err := fn(om); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", om.m.name(), err))
			}
		}
	}

	return errors.Join(errs...)
}

func newPerClusterCTMap(m mapType) *PerClusterCTMap {
	keySize := reflect.Indirect(reflect.ValueOf(m.key())).Type().Size()
	inner := &ebpf.MapSpec{
		Type:       ebpf.LRUHash,
		KeySize:    uint32(keySize),
		ValueSize:  uint32(SizeofCtEntry),
		MaxEntries: uint32(m.maxEntries()),
	}

	om := bpf.NewMapWithInnerSpec(
		ClusterOuterMapName(m),
		ebpf.ArrayOfMaps,
		&PerClusterCTMapKey{},
		&PerClusterCTMapVal{},
		int(cmtypes.ClusterIDMax+1),
		0,
		inner,
	)

	return &PerClusterCTMap{
		Map: om,
		m:   m,
	}
}

func (om *PerClusterCTMap) newInnerMap(clusterID uint32) *Map {
	name := ClusterInnerMapName(om.m, clusterID)
	im := newMap(name, om.m)
	im.clusterID = clusterID
	return im
}

func (om *PerClusterCTMap) createClusterCTMap(clusterID uint32) error {
	im := om.newInnerMap(clusterID)
	if err := im.OpenOrCreate(); err != nil {
		return fmt.Errorf("create inner map: %w", err)
	}

	// Close the file descriptor, but won't unpin because we don't want to
	// lookup outer map (lookup of map-in-map is slow because it involves
	// RCU synchronization) and want to open inner map from bpffs.
	defer im.Close()

	if err := om.Update(
		&PerClusterCTMapKey{clusterID},
		&PerClusterCTMapVal{uint32(im.FD())},
	); err != nil {
		return fmt.Errorf("update outer CT map: %w", err)
	}

	return nil
}

func (om *PerClusterCTMap) deleteClusterCTMap(clusterID uint32) error {
	im := om.newInnerMap(clusterID)
	if err := im.Unpin(); err != nil {
		return fmt.Errorf("delete inner map: %w", err)
	}

	// Detach inner map from outer map. At this point, no
	// one should have the reference of the inner map after
	// this call.
	if _, err := om.SilentDelete(&PerClusterCTMapKey{clusterID}); err != nil {
		return fmt.Errorf("update outer map: %w", err)
	}

	return nil
}

func (om *PerClusterCTMap) cleanup() error {
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
