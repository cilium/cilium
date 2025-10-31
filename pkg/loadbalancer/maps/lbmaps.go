// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package maps

import (
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"os"
	"reflect"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/u8proto"
)

type lbmapsParams struct {
	cell.In

	Log          *slog.Logger
	Lifecycle    cell.Lifecycle
	TestConfig   *loadbalancer.TestConfig `optional:"true"`
	MaglevConfig maglev.Config
	Config       loadbalancer.Config
	ExtConfig    loadbalancer.ExternalConfig
}

func newLBMaps(p lbmapsParams) bpf.MapOut[LBMaps] {
	pinned := true

	if p.TestConfig != nil {
		// We're beind tested, use unpinned maps if privileged, otherwise
		// in-memory fake.
		var m LBMaps
		if os.Getuid() == 0 {
			pinned = false
		} else {
			m = NewFakeLBMaps()
			if p.TestConfig.TestFaultProbability > 0.0 {
				m = &FaultyLBMaps{
					impl:               m,
					failureProbability: p.TestConfig.TestFaultProbability,
				}
			}
			return bpf.NewMapOut(m)
		}
	}

	r := &BPFLBMaps{Log: p.Log, Pinned: pinned, Cfg: p.Config, ExtCfg: p.ExtConfig, MaglevCfg: p.MaglevConfig}
	p.Lifecycle.Append(r)
	return bpf.NewMapOut(LBMaps(r))
}

type serviceMaps interface {
	UpdateService(key ServiceKey, value ServiceValue) error
	DeleteService(key ServiceKey) error
	DumpService(cb func(ServiceKey, ServiceValue)) error
}

type backendMaps interface {
	UpdateBackend(BackendKey, BackendValue) error
	DeleteBackend(BackendKey) error
	DumpBackend(cb func(BackendKey, BackendValue)) error
	LookupBackend(BackendKey) (BackendValue, error)
}

type revNatMaps interface {
	UpdateRevNat(RevNatKey, RevNatValue) error
	DeleteRevNat(RevNatKey) error
	DumpRevNat(cb func(RevNatKey, RevNatValue)) error
}

type affinityMaps interface {
	UpdateAffinityMatch(*AffinityMatchKey, *AffinityMatchValue) error
	DeleteAffinityMatch(*AffinityMatchKey) error
	DumpAffinityMatch(cb func(*AffinityMatchKey, *AffinityMatchValue)) error
}

type sourceRangeMaps interface {
	UpdateSourceRange(SourceRangeKey, *SourceRangeValue) error
	DeleteSourceRange(SourceRangeKey) error
	DumpSourceRange(cb func(SourceRangeKey, *SourceRangeValue)) error
}

type maglevMaps interface {
	UpdateMaglev(key MaglevOuterKey, backendIDs []loadbalancer.BackendID, ipv6 bool) error
	DeleteMaglev(key MaglevOuterKey, ipv6 bool) error
	DumpMaglev(cb func(MaglevOuterKey, MaglevOuterVal, MaglevInnerKey, *MaglevInnerVal, bool)) error
}

type sockRevNatMaps interface {
	UpdateSockRevNat(cookie uint64, addr net.IP, port uint16, revNatIndex uint16) error
	DeleteSockRevNat(cookie uint64, addr net.IP, port uint16) error
	ExistsSockRevNat(cookie uint64, addr net.IP, port uint16) bool
	SockRevNat() (*bpf.Map, *bpf.Map)
}

// LBMaps defines the map operations performed by the reconciliation.
// Depending on this interface instead of on the underlying maps allows
// testing the implementation with a fake map or injected errors.
type LBMaps interface {
	serviceMaps
	backendMaps
	revNatMaps
	affinityMaps
	sourceRangeMaps
	maglevMaps
	sockRevNatMaps

	IsEmpty() bool
}

type BPFLBMaps struct {
	// Pinned if true will pin the maps to a file. Tests may turn this off.
	Pinned bool

	Log       *slog.Logger
	Cfg       loadbalancer.Config
	ExtCfg    loadbalancer.ExternalConfig
	MaglevCfg maglev.Config

	service4Map, service6Map         *bpf.Map
	backend4Map, backend6Map         *bpf.Map
	revNat4Map, revNat6Map           *bpf.Map
	affinityMatchMap                 *bpf.Map
	affinity4Map, affinity6Map       *bpf.Map
	sockRevNat4Map, sockRevNat6Map   *bpf.Map
	sourceRange4Map, sourceRange6Map *bpf.Map
	maglev4Map, maglev6Map           *bpf.Map // Inner maps are referenced inside maglev4Map and maglev6Map and can be retrieved by lbmap.MaglevInnerMapFromID.

	maglevInnerMapSpec *ebpf.MapSpec

	openMapsMu lock.Mutex
	openMaps   []*bpf.Map
}

//
// BPF map constructors
//

func NewService4Map(maxEntries int) *bpf.Map {
	return bpf.NewMap(
		Service4MapV2Name,
		ebpf.Hash,
		&Service4Key{},
		&Service4Value{},
		maxEntries,
		0,
	)
}

func NewService6Map(maxEntries int) *bpf.Map {
	return bpf.NewMap(
		Service6MapV2Name,
		ebpf.Hash,
		&Service6Key{},
		&Service6Value{},
		maxEntries,
		0,
	)
}

func NewBackend4Map(maxEntries int) *bpf.Map {
	return bpf.NewMap(
		Backend4MapV3Name,
		ebpf.Hash,
		&Backend4KeyV3{},
		&Backend4ValueV3{},
		maxEntries,
		0,
	)
}

func NewBackend6Map(maxEntries int) *bpf.Map {
	return bpf.NewMap(
		Backend6MapV3Name,
		ebpf.Hash,
		&Backend6KeyV3{},
		&Backend6ValueV3{},
		maxEntries,
		0,
	)
}

func NewRevNat4Map(maxEntries int) *bpf.Map {
	return bpf.NewMap(
		RevNat4MapName,
		ebpf.Hash,
		&RevNat4Key{},
		&RevNat4Value{},
		maxEntries,
		0,
	)
}

func NewRevNat6Map(maxEntries int) *bpf.Map {
	return bpf.NewMap(
		RevNat6MapName,
		ebpf.Hash,
		&RevNat6Key{},
		&RevNat6Value{},
		maxEntries,
		0,
	)
}

func NewAffinityMatchMap(maxEntries int) *bpf.Map {
	return bpf.NewMap(
		AffinityMatchMapName,
		ebpf.Hash,
		&AffinityMatchKey{},
		&AffinityMatchValue{},
		maxEntries,
		0,
	)
}

func newAffinity4Map(maxEntries int) *bpf.Map {
	return bpf.NewMap(
		Affinity4MapName,
		ebpf.LRUHash,
		&Affinity4Key{},
		&AffinityValue{},
		maxEntries,
		0,
	)
}

func newAffinity6Map(maxEntries int) *bpf.Map {
	return bpf.NewMap(
		Affinity6MapName,
		ebpf.LRUHash,
		&Affinity6Key{},
		&AffinityValue{},
		maxEntries,
		0,
	)
}

func NewSourceRange4Map(maxEntries int) *bpf.Map {
	return bpf.NewMap(
		SourceRange4MapName,
		ebpf.LPMTrie,
		&SourceRangeKey4{},
		&SourceRangeValue{},
		maxEntries,
		0,
	)
}

func NewSourceRange6Map(maxEntries int) *bpf.Map {
	return bpf.NewMap(
		SourceRange6MapName,
		ebpf.LPMTrie,
		&SourceRangeKey6{},
		&SourceRangeValue{},
		maxEntries,
		0,
	)
}

func NewSockRevNat4Map(maxEntries int) *bpf.Map {
	return bpf.NewMap(
		SockRevNat4MapName,
		ebpf.LRUHash,
		&SockRevNat4Key{},
		&SockRevNat4Value{},
		maxEntries,
		0,
	)
}

func NewSockRevNat6Map(maxEntries int) *bpf.Map {
	return bpf.NewMap(
		SockRevNat6MapName,
		ebpf.LRUHash,
		&SockRevNat6Key{},
		&SockRevNat6Value{},
		maxEntries,
		0,
	)
}

func NewMaglevOuterMap(name string, maxEntries int, innerSpec *ebpf.MapSpec) *bpf.Map {
	return bpf.NewMapWithInnerSpec(
		name,
		ebpf.HashOfMaps,
		&MaglevOuterKey{},
		&MaglevOuterVal{},
		maxEntries,
		0,
		innerSpec.Copy(),
	)
}

type mapDesc struct {
	target     **bpf.Map // pointer to the field in realLBMaps
	ctor       func(maxEntries int) *bpf.Map
	maxEntries int
}

func (r *BPFLBMaps) allMaps() ([]mapDesc, []mapDesc) {
	newMaglev4 := func(maxEntries int) *bpf.Map {
		return NewMaglevOuterMap(MaglevOuter4MapName, maxEntries, r.maglevInnerMapSpec)
	}
	newMaglev6 := func(maxEntries int) *bpf.Map {
		return NewMaglevOuterMap(MaglevOuter6MapName, maxEntries, r.maglevInnerMapSpec)
	}
	v4Maps := []mapDesc{
		{&r.service4Map, NewService4Map, r.Cfg.LBServiceMapEntries},
		{&r.backend4Map, NewBackend4Map, r.Cfg.LBBackendMapEntries},
		{&r.revNat4Map, NewRevNat4Map, r.Cfg.LBRevNatEntries},
		{&r.maglev4Map, newMaglev4, r.Cfg.LBMaglevMapEntries},
		{&r.sockRevNat4Map, NewSockRevNat4Map, r.Cfg.LBSockRevNatEntries},
		{&r.affinity4Map, newAffinity4Map, r.Cfg.LBAffinityMapEntries},
	}
	v6Maps := []mapDesc{
		{&r.service6Map, NewService6Map, r.Cfg.LBServiceMapEntries},
		{&r.backend6Map, NewBackend6Map, r.Cfg.LBBackendMapEntries},
		{&r.revNat6Map, NewRevNat6Map, r.Cfg.LBRevNatEntries},
		{&r.maglev6Map, newMaglev6, r.Cfg.LBMaglevMapEntries},
		{&r.sockRevNat6Map, NewSockRevNat6Map, r.Cfg.LBSockRevNatEntries},
		{&r.affinity6Map, newAffinity6Map, r.Cfg.LBAffinityMapEntries},
	}
	affinityMap := mapDesc{&r.affinityMatchMap, NewAffinityMatchMap, r.Cfg.LBAffinityMapEntries}
	v4SourceRangeMap := mapDesc{&r.sourceRange4Map, NewSourceRange4Map, r.Cfg.LBSourceRangeMapEntries}
	v6SourceRangeMap := mapDesc{&r.sourceRange6Map, NewSourceRange6Map, r.Cfg.LBSourceRangeMapEntries}

	mapsToCreate := []mapDesc{}
	mapsToDelete := []mapDesc{}

	mapsToCreate = append(mapsToCreate, affinityMap)

	if r.ExtCfg.EnableIPv4 {
		mapsToCreate = append(mapsToCreate, v4SourceRangeMap)
	} else {
		mapsToDelete = append(mapsToDelete, v4SourceRangeMap)
	}
	if r.ExtCfg.EnableIPv6 {
		mapsToCreate = append(mapsToCreate, v6SourceRangeMap)
	} else {
		mapsToDelete = append(mapsToDelete, v6SourceRangeMap)
	}

	if r.ExtCfg.EnableIPv4 {
		mapsToCreate = append(mapsToCreate, v4Maps...)
	} else {
		mapsToDelete = append(mapsToDelete, v4Maps...)
		mapsToDelete = append(mapsToDelete, v4SourceRangeMap)
	}
	if r.ExtCfg.EnableIPv6 {
		mapsToCreate = append(mapsToCreate, v6Maps...)
	} else {
		mapsToDelete = append(mapsToDelete, v6Maps...)
		mapsToDelete = append(mapsToDelete, v6SourceRangeMap)
	}
	return mapsToCreate, mapsToDelete
}

func NewMaglevInnerMapSpec(tableSize uint) *ebpf.MapSpec {
	return &ebpf.MapSpec{
		Name:       MaglevInnerMapName,
		Type:       ebpf.Array,
		KeySize:    uint32(unsafe.Sizeof(MaglevInnerKey{})),
		MaxEntries: 1,
		ValueSize:  MaglevBackendLen * uint32(tableSize),
	}
}

// Start implements cell.HookInterface.
func (r *BPFLBMaps) Start(ctx cell.HookContext) (err error) {
	r.maglevInnerMapSpec = NewMaglevInnerMapSpec(r.MaglevCfg.TableSize)
	mapsToCreate, mapsToDelete := r.allMaps()
	openedMaps := make([]*bpf.Map, 0, len(mapsToCreate))
	for _, desc := range mapsToCreate {
		m := desc.ctor(desc.maxEntries)
		*desc.target = m

		if r.Pinned {
			if err := m.OpenOrCreate(); err != nil {
				return fmt.Errorf("opening map %s: %w", m.Name(), err)
			}
		} else {
			if err := m.CreateUnpinned(); err != nil {
				return fmt.Errorf("opening map %s: %w", m.Name(), err)
			}
		}
		openedMaps = append(openedMaps, m)
	}
	r.openMaps = openedMaps

	if !r.Pinned {
		// nothing to unpin, return early
		return nil
	}

	for _, desc := range mapsToDelete {
		m := desc.ctor(desc.maxEntries)
		if err := m.UnpinIfExists(); err != nil {
			r.Log.Warn("Unpin failed", logfields.Error, err)
		}
	}
	return nil
}

// forEachOpenMap calls [fn] for each open map. The maps cannot close during this.
func (r *BPFLBMaps) forEachOpenMap(fn func(m *bpf.Map)) {
	r.openMapsMu.Lock()
	defer r.openMapsMu.Unlock()
	for _, m := range r.openMaps {
		fn(m)
	}
}

// Stop implements cell.HookInterface.
func (r *BPFLBMaps) Stop(cell.HookContext) error {
	var errs []error

	r.openMapsMu.Lock()
	r.openMaps = nil
	r.openMapsMu.Unlock()

	mapsToCreate, _ := r.allMaps()
	for _, desc := range mapsToCreate {
		m := *desc.target
		if m != nil {
			if err := m.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func dumpMap[K bpf.MapKey, V bpf.MapValue](m *bpf.Map, cb func(K, V)) error {
	if m == nil {
		return nil
	}
	return m.DumpWithCallback(
		func(key bpf.MapKey, value bpf.MapValue) {
			cb(key.(K), value.(V))
		},
	)
}

// DeleteRevNat implements lbmaps.
func (r *BPFLBMaps) DeleteRevNat(key RevNatKey) error {
	var err error
	switch key.(type) {
	case *RevNat4Key:
		_, err = r.revNat4Map.SilentDelete(key)
	case *RevNat6Key:
		_, err = r.revNat6Map.SilentDelete(key)
	default:
		panic("unknown RevNatKey")
	}
	return err
}

// DumpRevNat implements lbmaps.
func (r *BPFLBMaps) DumpRevNat(cb func(RevNatKey, RevNatValue)) error {
	return errors.Join(
		dumpMap(r.revNat4Map, cb),
		dumpMap(r.revNat6Map, cb),
	)
}

// UpdateRevNat4 implements lbmaps.
func (r *BPFLBMaps) UpdateRevNat(key RevNatKey, value RevNatValue) error {
	switch key.(type) {
	case *RevNat4Key:
		return r.revNat4Map.Update(key, value)
	case *RevNat6Key:
		return r.revNat6Map.Update(key, value)
	default:
		panic("unknown RevNatKey")
	}
}

// DumpBackend implements lbmaps.
func (r *BPFLBMaps) DumpBackend(cb func(BackendKey, BackendValue)) error {
	return errors.Join(
		dumpMap(r.backend4Map, cb),
		dumpMap(r.backend6Map, cb),
	)
}

// DeleteBackend implements lbmaps.
func (r *BPFLBMaps) DeleteBackend(key BackendKey) error {
	var err error
	switch key.(type) {
	case *Backend4KeyV3:
		_, err = r.backend4Map.SilentDelete(key)
	case *Backend6KeyV3:
		_, err = r.backend6Map.SilentDelete(key)
	default:
		panic("unknown BackendKey")
	}
	return err
}

func (r *BPFLBMaps) LookupBackend(key BackendKey) (val BackendValue, err error) {
	var v bpf.MapValue
	switch key.(type) {
	case *Backend4KeyV3:
		v, err = r.backend4Map.Lookup(key)
	case *Backend6KeyV3:
		v, err = r.backend6Map.Lookup(key)
	default:
		panic("unknown BackendKey")
	}
	if err == nil {
		val = v.(BackendValue)
	}
	return
}

// DeleteService implements lbmaps.
func (r *BPFLBMaps) DeleteService(key ServiceKey) error {
	var err error
	switch key.(type) {
	case *Service4Key:
		_, err = r.service4Map.SilentDelete(key)
	case *Service6Key:
		_, err = r.service6Map.SilentDelete(key)
	default:
		panic("unknown ServiceKey")
	}
	return err
}

// DumpService implements lbmaps.
func (r *BPFLBMaps) DumpService(cb func(ServiceKey, ServiceValue)) error {
	return errors.Join(
		dumpMap(r.service4Map, cb),
		dumpMap(r.service6Map, cb),
	)
}

// UpdateBackend implements lbmaps.
func (r *BPFLBMaps) UpdateBackend(key BackendKey, value BackendValue) error {
	switch key.(type) {
	case *Backend4KeyV3:
		return r.backend4Map.Update(key, value)
	case *Backend6KeyV3:
		return r.backend6Map.Update(key, value)
	default:
		panic("unknown BackendKey")
	}
}

// UpdateService implements lbmaps.
func (r *BPFLBMaps) UpdateService(key ServiceKey, value ServiceValue) error {
	switch key.(type) {
	case *Service4Key:
		return r.service4Map.Update(key, value)
	case *Service6Key:
		return r.service6Map.Update(key, value)
	default:
		panic("unknown ServiceKey")
	}
}

// DeleteAffinityMatch implements lbmaps.
func (r *BPFLBMaps) DeleteAffinityMatch(key *AffinityMatchKey) error {
	_, err := r.affinityMatchMap.SilentDelete(key)
	return err
}

// DumpAffinityMatch implements lbmaps.
func (r *BPFLBMaps) DumpAffinityMatch(cb func(*AffinityMatchKey, *AffinityMatchValue)) error {
	return dumpMap(r.affinityMatchMap, cb)
}

// UpdateAffinityMatch implements lbmaps.
func (r *BPFLBMaps) UpdateAffinityMatch(key *AffinityMatchKey, value *AffinityMatchValue) error {
	return r.affinityMatchMap.Update(key, value)
}

// DeleteSourceRange implements lbmaps.
func (r *BPFLBMaps) DeleteSourceRange(key SourceRangeKey) error {
	var err error
	switch key.(type) {
	case *SourceRangeKey4:
		_, err = r.sourceRange4Map.SilentDelete(key)
	case *SourceRangeKey6:
		_, err = r.sourceRange6Map.SilentDelete(key)
	default:
		panic("unknown SourceRangeKey")
	}
	return err
}

// DumpSourceRange implements lbmaps.
func (r *BPFLBMaps) DumpSourceRange(cb func(SourceRangeKey, *SourceRangeValue)) error {
	return errors.Join(
		dumpMap(r.sourceRange4Map, cb),
		dumpMap(r.sourceRange6Map, cb),
	)
}

// UpdateSourceRange implements lbmaps.
func (r *BPFLBMaps) UpdateSourceRange(key SourceRangeKey, value *SourceRangeValue) error {
	switch key.(type) {
	case *SourceRangeKey4:
		return r.sourceRange4Map.Update(key, value)
	case *SourceRangeKey6:
		return r.sourceRange6Map.Update(key, value)
	default:
		panic("unknown SourceRangeKey")
	}
}

// UpdateMaglev implements lbmaps.
func (r *BPFLBMaps) UpdateMaglev(key MaglevOuterKey, backendIDs []loadbalancer.BackendID, ipv6 bool) error {
	inner, err := ebpf.NewMap(r.maglevInnerMapSpec)
	if err != nil {
		return fmt.Errorf("failed to create map %q: %w", r.maglevInnerMapSpec.Name, err)
	}
	defer inner.Close()
	var singletonKey MaglevInnerKey
	if err := inner.Update(singletonKey, backendIDs, 0); err != nil {
		return fmt.Errorf("updating backends: %w", err)
	}
	outerKey := &MaglevOuterKey{
		RevNatID: byteorder.HostToNetwork16(key.RevNatID),
	}
	outerValue := &MaglevOuterVal{FD: uint32(inner.FD())}
	if ipv6 {
		return r.maglev6Map.Update(outerKey, outerValue)
	} else {
		return r.maglev4Map.Update(outerKey, outerValue)
	}
}

// DeleteMaglev implements lbmaps.
func (r *BPFLBMaps) DeleteMaglev(key MaglevOuterKey, ipv6 bool) error {
	outerKey := &MaglevOuterKey{
		RevNatID: byteorder.HostToNetwork16(key.RevNatID),
	}
	ebpfmap := r.maglev4Map
	if ipv6 {
		ebpfmap = r.maglev6Map
	}
	_, err := ebpfmap.SilentDelete(outerKey)
	return err
}

func (r *BPFLBMaps) DumpMaglev(cb func(MaglevOuterKey, MaglevOuterVal, MaglevInnerKey, *MaglevInnerVal, bool)) error {
	var errs []error
	var ipv6 bool
	cbWrap := func(key bpf.MapKey, value bpf.MapValue) {
		maglevKey := MaglevOuterKey{
			RevNatID: byteorder.NetworkToHost16(key.(*MaglevOuterKey).RevNatID),
		}
		maglevValue := value.(*MaglevOuterVal)
		inner, err := MaglevInnerMapFromID(maglevValue.FD)
		if err != nil {
			errs = append(errs, fmt.Errorf("cannot open inner map with fd %d: %w", maglevValue.FD, err))
			return
		}
		defer inner.Close()
		// Maglev inner map has a single key and a huge value.
		var singletonKey MaglevInnerKey
		innerValue, err := inner.Lookup(&singletonKey)
		if err != nil {
			errs = append(errs, fmt.Errorf("cannot look up backends in inner map with id %d: %w", maglevValue.FD, err))
		}
		cb(maglevKey, *maglevValue, singletonKey, innerValue, ipv6)
	}
	if r.maglev4Map != nil {
		ipv6 = false
		errs = append(errs, r.maglev4Map.DumpWithCallback(cbWrap))
	}
	if r.maglev6Map != nil {
		ipv6 = true
		errs = append(errs, r.maglev6Map.DumpWithCallback(cbWrap))
	}
	return errors.Join(errs...)
}

// DeleteSockRevNat implements LBMaps.
func (r *BPFLBMaps) DeleteSockRevNat(cookie uint64, addr net.IP, port uint16) error {
	if addr.To4() != nil && r.sockRevNat4Map != nil {
		key := NewSockRevNat4Key(cookie, addr, port)
		_, err := r.sockRevNat4Map.SilentDelete(key)
		return err
	} else if r.sockRevNat6Map != nil {
		key := NewSockRevNat6Key(cookie, addr, port)
		_, err := r.sockRevNat6Map.SilentDelete(key)
		return err
	}
	return nil
}

// UpdateSockRevNat implements LBMaps.
func (r *BPFLBMaps) UpdateSockRevNat(cookie uint64, addr net.IP, port uint16, revNatIndex uint16) error {
	if addr.To4() != nil && r.sockRevNat4Map != nil {
		key := NewSockRevNat4Key(cookie, addr, port)
		value := SockRevNat4Value{
			Address:     key.Address,
			Port:        key.Port,
			RevNatIndex: revNatIndex,
		}
		return r.sockRevNat4Map.Update(key, &value)
	} else if r.sockRevNat6Map != nil {
		key := NewSockRevNat6Key(cookie, addr, port)
		value := SockRevNat6Value{
			Address:     key.Address,
			Port:        key.Port,
			RevNatIndex: revNatIndex,
		}
		return r.sockRevNat6Map.Update(key, &value)
	}
	return nil
}

func (r *BPFLBMaps) ExistsSockRevNat(cookie uint64, addr net.IP, port uint16) bool {
	if addr.To4() != nil && r.sockRevNat4Map != nil {
		key := NewSockRevNat4Key(cookie, addr, port)
		if v, _ := r.sockRevNat4Map.Lookup(key); v != nil {
			return true
		}
	} else if r.sockRevNat6Map != nil {
		key := NewSockRevNat6Key(cookie, addr, port)
		if v, _ := r.sockRevNat6Map.Lookup(key); v != nil {
			return true
		}
	}
	return false
}

func (r *BPFLBMaps) SockRevNat() (*bpf.Map, *bpf.Map) {
	return r.sockRevNat4Map, r.sockRevNat6Map
}

// MaglevInnerMap represents a maglev inner map.
type MaglevInnerMap struct {
	*ebpf.Map
}

// TableSize returns the amount of backends this map can hold as a value.
func (m MaglevInnerMap) TableSize() uint32 {
	return m.Map.ValueSize() / uint32(MaglevBackendLen)
}

// MaglevInnerMapFromID returns a new object representing the maglev inner map
// identified by an ID.
func MaglevInnerMapFromID(id uint32) (MaglevInnerMap, error) {
	m, err := ebpf.NewMapFromID(ebpf.MapID(id))
	return MaglevInnerMap{m}, err
}

// Lookup returns the value associated with a given key for a maglev inner map.
func (m MaglevInnerMap) Lookup(key *MaglevInnerKey) (*MaglevInnerVal, error) {
	value := &MaglevInnerVal{
		BackendIDs: make([]loadbalancer.BackendID, m.TableSize()),
	}

	if err := m.Map.Lookup(key, &value.BackendIDs); err != nil {
		return nil, err
	}

	return value, nil
}

// DumpBackends returns the first key of the map as stringified ints for dumping purposes.
func (m MaglevInnerMap) DumpBackends() (string, error) {
	// A service's backend array sits at the first key of the inner map.
	var key MaglevInnerKey
	val, err := m.Lookup(&key)
	if err != nil {
		return "", fmt.Errorf("lookup up first inner map key (backends): %w", err)
	}

	return fmt.Sprintf("%v", val.BackendIDs), nil
}

// IsEmpty implements lbmaps.
func (r *BPFLBMaps) IsEmpty() bool {
	mapIsEmpty := func(m *bpf.Map) bool {
		if m == nil {
			return true
		}
		var key []byte
		return errors.Is(m.NextKey(nil, &key), ebpf.ErrKeyNotExist)
	}
	createdMaps, _ := r.allMaps()
	for _, desc := range createdMaps {
		if !mapIsEmpty(*desc.target) {
			return false
		}
	}
	return true
}

var _ LBMaps = &BPFLBMaps{}

type FaultyLBMaps struct {
	impl LBMaps

	// 0.0 (never fail) ... 1.0 (always fail)
	failureProbability float32
}

// DeleteSockRevNat implements LBMaps.
func (f *FaultyLBMaps) DeleteSockRevNat(cookie uint64, addr net.IP, port uint16) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.DeleteSockRevNat(cookie, addr, port)
}

// UpdateSockRevNat implements LBMaps.
func (f *FaultyLBMaps) UpdateSockRevNat(cookie uint64, addr net.IP, port uint16, revNatIndex uint16) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.UpdateSockRevNat(cookie, addr, port, revNatIndex)
}

// DeleteSourceRange implements lbmaps.
func (f *FaultyLBMaps) DeleteSourceRange(key SourceRangeKey) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.DeleteSourceRange(key)
}

// DumpSourceRange implements lbmaps.
func (f *FaultyLBMaps) DumpSourceRange(cb func(SourceRangeKey, *SourceRangeValue)) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.DumpSourceRange(cb)
}

// UpdateSourceRange implements lbmaps.
func (f *FaultyLBMaps) UpdateSourceRange(key SourceRangeKey, value *SourceRangeValue) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.UpdateSourceRange(key, value)
}

// DeleteAffinityMatch implements lbmaps.
func (f *FaultyLBMaps) DeleteAffinityMatch(key *AffinityMatchKey) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.DeleteAffinityMatch(key)
}

// DumpAffinityMatch implements lbmaps.
func (f *FaultyLBMaps) DumpAffinityMatch(cb func(*AffinityMatchKey, *AffinityMatchValue)) error {
	return f.impl.DumpAffinityMatch(cb)
}

// UpdateAffinityMatch implements lbmaps.
func (f *FaultyLBMaps) UpdateAffinityMatch(key *AffinityMatchKey, value *AffinityMatchValue) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.UpdateAffinityMatch(key, value)
}

// DeleteRevNat implements lbmaps.
func (f *FaultyLBMaps) DeleteRevNat(key RevNatKey) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.DeleteRevNat(key)
}

// DumpRevNat implements lbmaps.
func (f *FaultyLBMaps) DumpRevNat(cb func(RevNatKey, RevNatValue)) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.DumpRevNat(cb)
}

// UpdateRevNat implements lbmaps.
func (f *FaultyLBMaps) UpdateRevNat(key RevNatKey, value RevNatValue) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.UpdateRevNat(key, value)
}

// DeleteBackend implements lbmaps.
func (f *FaultyLBMaps) DeleteBackend(key BackendKey) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.DeleteBackend(key)
}

// DeleteService implements lbmaps.
func (f *FaultyLBMaps) DeleteService(key ServiceKey) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.DeleteService(key)
}

// DumpBackend implements lbmaps.
func (f *FaultyLBMaps) DumpBackend(cb func(BackendKey, BackendValue)) error {
	return f.impl.DumpBackend(cb)
}

// DumpService implements lbmaps.
func (f *FaultyLBMaps) DumpService(cb func(ServiceKey, ServiceValue)) error {
	return f.impl.DumpService(cb)
}

// IsEmpty implements lbmaps.
func (f *FaultyLBMaps) IsEmpty() bool {
	return f.impl.IsEmpty()
}

// UpdateBackend implements lbmaps.
func (f *FaultyLBMaps) UpdateBackend(key BackendKey, value BackendValue) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.UpdateBackend(key, value)
}

// UpdateService implements lbmaps.
func (f *FaultyLBMaps) UpdateService(key ServiceKey, value ServiceValue) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.UpdateService(key, value)
}

// UpdateMaglev implements lbmaps.
func (f *FaultyLBMaps) UpdateMaglev(key MaglevOuterKey, backendIDs []loadbalancer.BackendID, ipv6 bool) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.UpdateMaglev(key, backendIDs, ipv6)
}

// DeleteMaglev implements lbmaps.
func (f *FaultyLBMaps) DeleteMaglev(key MaglevOuterKey, ipv6 bool) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.DeleteMaglev(key, ipv6)
}

// DumpMaglev implements lbmaps.
func (f *FaultyLBMaps) DumpMaglev(cb func(MaglevOuterKey, MaglevOuterVal, MaglevInnerKey, *MaglevInnerVal, bool)) error {
	return f.impl.DumpMaglev(cb)
}

func (f *FaultyLBMaps) ExistsSockRevNat(cookie uint64, addr net.IP, port uint16) bool {
	return f.impl.ExistsSockRevNat(cookie, addr, port)
}

func (f *FaultyLBMaps) SockRevNat() (*bpf.Map, *bpf.Map) {
	return f.impl.SockRevNat()
}

// LookupBackend implements LBMaps.
func (f *FaultyLBMaps) LookupBackend(key BackendKey) (BackendValue, error) {
	return f.impl.LookupBackend(key)
}

func (f *FaultyLBMaps) isFaulty() bool {
	// Float32() returns value between [0.0, 1.0).
	// We fail if the value is less than our probability [0.0, 1.0].
	return f.failureProbability > rand.Float32()
}

var errFaulty = errors.New("faulty")

var _ LBMaps = &FaultyLBMaps{}

type kvpair struct {
	a, b any
}
type fakeBPFMap struct {
	lock.Map[string, kvpair]
}

func (fm *fakeBPFMap) delete(key bpf.MapKey) error {
	fm.Map.Delete(bpfKey(key))
	return nil
}

func (fm *fakeBPFMap) update(key bpf.MapKey, value any) error {
	fm.Map.Store(bpfKey(key), kvpair{key, value})
	return nil
}

func (fm *fakeBPFMap) exists(key bpf.MapKey) bool {
	_, exists := fm.Map.Load(bpfKey(key))
	return exists
}

func (fm *fakeBPFMap) lookup(key bpf.MapKey) (any, error) {
	v, exists := fm.Map.Load(bpfKey(key))
	if !exists {
		return nil, ebpf.ErrKeyNotExist
	}
	return v.b, nil
}

func (fm *fakeBPFMap) IsEmpty() bool {
	return fm.Map.IsEmpty()
}

func bpfKey(key any) string {
	v := reflect.ValueOf(key)
	size := int(v.Type().Elem().Size())
	keyBytes := unsafe.Slice((*byte)(v.UnsafePointer()), size)
	return string(keyBytes)
}

func dumpFakeBPFMap[K any, V any](m *fakeBPFMap, cb func(K, V)) {
	m.Range(func(_ string, pair kvpair) bool {
		cb(pair.a.(K), pair.b.(V))
		return true
	})
}

type FakeLBMaps struct {
	aff        fakeBPFMap
	be         fakeBPFMap
	svc        fakeBPFMap
	revNat     fakeBPFMap
	sockRevNat fakeBPFMap
	srcRange   fakeBPFMap
	mglv4      fakeBPFMap
	mglv6      fakeBPFMap
	inners     lock.Map[uint32, *fakeBPFMap]
	nextID     uint32
}

func NewFakeLBMaps() LBMaps {
	return &FakeLBMaps{}
}

// DeleteAffinityMatch implements lbmaps.
func (f *FakeLBMaps) DeleteAffinityMatch(key *AffinityMatchKey) error {
	return f.aff.delete(key)
}

// DeleteBackend implements lbmaps.
func (f *FakeLBMaps) DeleteBackend(key BackendKey) error {
	return f.be.delete(key)
}

// DeleteRevNat implements lbmaps.
func (f *FakeLBMaps) DeleteRevNat(key RevNatKey) error {
	return f.revNat.delete(key)
}

// DeleteService implements lbmaps.
func (f *FakeLBMaps) DeleteService(key ServiceKey) error {
	return f.svc.delete(key)
}

// DeleteSourceRange implements lbmaps.
func (f *FakeLBMaps) DeleteSourceRange(key SourceRangeKey) error {
	return f.srcRange.delete(key)
}

// DumpAffinityMatch implements lbmaps.
func (f *FakeLBMaps) DumpAffinityMatch(cb func(*AffinityMatchKey, *AffinityMatchValue)) error {
	dumpFakeBPFMap(&f.aff, cb)
	return nil
}

// DumpBackend implements lbmaps.
func (f *FakeLBMaps) DumpBackend(cb func(BackendKey, BackendValue)) error {
	dumpFakeBPFMap(&f.be, cb)
	return nil
}

// DumpRevNat implements lbmaps.
func (f *FakeLBMaps) DumpRevNat(cb func(RevNatKey, RevNatValue)) error {
	dumpFakeBPFMap(&f.revNat, cb)
	return nil
}

// DumpService implements lbmaps.
func (f *FakeLBMaps) DumpService(cb func(ServiceKey, ServiceValue)) error {
	dumpFakeBPFMap(&f.svc, cb)
	return nil
}

// DumpSourceRange implements lbmaps.
func (f *FakeLBMaps) DumpSourceRange(cb func(SourceRangeKey, *SourceRangeValue)) error {
	dumpFakeBPFMap(&f.srcRange, cb)
	return nil
}

// UpdateAffinityMatch implements lbmaps.
func (f *FakeLBMaps) UpdateAffinityMatch(key *AffinityMatchKey, value *AffinityMatchValue) error {
	return f.aff.update(key, value)
}

// UpdateBackend implements lbmaps.
func (f *FakeLBMaps) UpdateBackend(key BackendKey, value BackendValue) error {
	return f.be.update(key, value)
}

// UpdateRevNat implements lbmaps.
func (f *FakeLBMaps) UpdateRevNat(key RevNatKey, value RevNatValue) error {
	return f.revNat.update(key, value)
}

// UpdateService implements lbmaps.
func (f *FakeLBMaps) UpdateService(key ServiceKey, value ServiceValue) error {
	return f.svc.update(key, value)
}

// UpdateSourceRange implements lbmaps.
func (f *FakeLBMaps) UpdateSourceRange(key SourceRangeKey, value *SourceRangeValue) error {
	return f.srcRange.update(key, value)
}

// UpdateMaglev implements lbmaps.
func (f *FakeLBMaps) UpdateMaglev(key MaglevOuterKey, backendIDs []loadbalancer.BackendID, ipv6 bool) error {
	var outer *fakeBPFMap
	if ipv6 {
		outer = &f.mglv6
	} else {
		outer = &f.mglv4
	}
	var singletonKey MaglevInnerKey
	inner := &fakeBPFMap{}
	currentID := f.nextID
	f.nextID++
	f.inners.Store(currentID, inner)
	value := MaglevOuterVal{
		FD: currentID,
	}
	if err := inner.update(&singletonKey, backendIDs); err != nil {
		return err
	}
	if err := outer.update(&key, value); err != nil {
		return err
	}
	return nil
}

// DeleteMaglev implements lbmaps.
func (f *FakeLBMaps) DeleteMaglev(key MaglevOuterKey, ipv6 bool) error {
	if ipv6 {
		return f.mglv6.delete(&key)
	} else {
		return f.mglv4.delete(&key)
	}
}

func (f *FakeLBMaps) DumpMaglev(cb func(MaglevOuterKey, MaglevOuterVal, MaglevInnerKey, *MaglevInnerVal, bool)) error {
	var err error
	cbWrap := func(key MaglevOuterKey, value MaglevOuterVal, ipv6 bool) bool {
		singletonKey := MaglevInnerKey{}
		innerMap, ok := f.inners.Load(value.FD)
		if !ok {
			err = fmt.Errorf("inner map %d not found", value.FD)
			return false
		}
		innerValue, ok := innerMap.Map.Load(bpfKey(&singletonKey))
		if !ok {
			err = fmt.Errorf("failed to fetch the value from the inner map for RevNatID=%d and FD=%d", key.RevNatID, value.FD)
			return false
		}
		cb(key, value, *innerValue.a.(*MaglevInnerKey), &MaglevInnerVal{BackendIDs: innerValue.b.([]loadbalancer.BackendID)}, ipv6)
		return true
	}
	f.mglv4.Range(func(_ string, pair kvpair) bool {
		return cbWrap(*pair.a.(*MaglevOuterKey), pair.b.(MaglevOuterVal), false)
	})
	f.mglv6.Range(func(_ string, pair kvpair) bool {
		return cbWrap(*pair.a.(*MaglevOuterKey), pair.b.(MaglevOuterVal), true)
	})
	return err
}

// DeleteSockRevNat implements LBMaps.
func (f *FakeLBMaps) DeleteSockRevNat(cookie uint64, addr net.IP, port uint16) error {
	var key bpf.MapKey
	if addr.To4() != nil {
		key4 := NewSockRevNat4Key(cookie, addr, port)
		key = key4
	} else {
		key6 := NewSockRevNat6Key(cookie, addr, port)
		key = key6
	}
	return f.sockRevNat.delete(key)
}

// UpdateSockRevNat implements LBMaps.
func (f *FakeLBMaps) UpdateSockRevNat(cookie uint64, addr net.IP, port uint16, revNatIndex uint16) error {
	var key bpf.MapKey
	var value bpf.MapValue
	if addr.To4() != nil {
		key4 := NewSockRevNat4Key(cookie, addr, port)
		key = key4
		value = &SockRevNat4Value{
			Address:     key4.Address,
			Port:        key4.Port,
			RevNatIndex: revNatIndex,
		}
	} else {
		key6 := NewSockRevNat6Key(cookie, addr, port)
		key = key6
		value = &SockRevNat6Value{
			Address:     key6.Address,
			Port:        key6.Port,
			RevNatIndex: revNatIndex,
		}
	}
	f.sockRevNat.update(key, value)
	return nil
}

func (f *FakeLBMaps) ExistsSockRevNat(cookie uint64, addr net.IP, port uint16) bool {
	var key bpf.MapKey
	if addr.To4() != nil {
		key4 := NewSockRevNat4Key(cookie, addr, port)
		key = key4
	} else {
		key6 := NewSockRevNat6Key(cookie, addr, port)
		key = key6
	}
	return f.sockRevNat.exists(key)
}

func (f *FakeLBMaps) SockRevNat() (*bpf.Map, *bpf.Map) {
	return nil, nil
}

// LookupBackend implements LBMaps.
func (f *FakeLBMaps) LookupBackend(key BackendKey) (BackendValue, error) {
	v, err := f.be.lookup(key)
	if err != nil {
		return nil, err
	}
	return v.(BackendValue), nil
}

// IsEmpty implements lbmaps.
func (f *FakeLBMaps) IsEmpty() bool {
	return f.aff.IsEmpty() &&
		f.be.IsEmpty() &&
		f.svc.IsEmpty() &&
		f.revNat.IsEmpty() &&
		f.srcRange.IsEmpty()
}

var _ LBMaps = &FakeLBMaps{}

type mapKeyValue struct {
	key   bpf.MapKey
	value bpf.MapValue
}
type mapSnapshot = []mapKeyValue

type mapSnapshots struct {
	mu lock.Mutex

	services mapSnapshot
	backends mapSnapshot
	revNat   mapSnapshot
	affinity mapSnapshot
	srcRange mapSnapshot
}

func (s *mapSnapshots) snapshot(lbmaps LBMaps) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	svcCB := func(svcKey ServiceKey, svcValue ServiceValue) {
		s.services = append(s.services, mapKeyValue{svcKey, svcValue})
	}
	if err := lbmaps.DumpService(svcCB); err != nil {
		return fmt.Errorf("DumpService: %w", err)
	}

	beCB := func(beKey BackendKey, beValue BackendValue) {
		s.backends = append(s.backends, mapKeyValue{beKey, beValue})
	}
	if err := lbmaps.DumpBackend(beCB); err != nil {
		return fmt.Errorf("DumpBackend: %w", err)
	}

	revCB := func(revKey RevNatKey, revValue RevNatValue) {
		s.revNat = append(s.revNat, mapKeyValue{revKey, revValue})
	}
	if err := lbmaps.DumpRevNat(revCB); err != nil {
		return fmt.Errorf("DumpRevNat: %w", err)
	}

	affCB := func(affKey *AffinityMatchKey, affValue *AffinityMatchValue) {
		s.affinity = append(s.revNat, mapKeyValue{affKey, affValue})
	}
	if err := lbmaps.DumpAffinityMatch(affCB); err != nil {
		return fmt.Errorf("DumpAffinityMatch: %w", err)
	}

	srcRangeCB := func(key SourceRangeKey, value *SourceRangeValue) {
		s.srcRange = append(s.srcRange, mapKeyValue{key, value})
	}
	if err := lbmaps.DumpSourceRange(srcRangeCB); err != nil {
		return fmt.Errorf("DumpSourceRange: %w", err)
	}
	return nil
}

// restore the snapshot. If [anyProto] is true the protocol for services and backends is
// ignored and 'ANY' is used instead. This is for testing migration from Cilium version
// that did not support protocol differentiation.
func (s *mapSnapshots) restore(lbmaps LBMaps, anyProto bool) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, kv := range s.services {
		key := kv.key.(ServiceKey)
		if anyProto {
			switch k := key.(type) {
			case *Service4Key:
				k.Proto = uint8(u8proto.ANY)
			case *Service6Key:
				k.Proto = uint8(u8proto.ANY)
			}
		}
		err = errors.Join(err, lbmaps.UpdateService(kv.key.(ServiceKey), kv.value.(ServiceValue)))
	}
	for _, kv := range s.backends {
		value := kv.value.(BackendValue)
		if anyProto {
			switch v := value.(type) {
			case *Backend4ValueV3:
				v.Proto = u8proto.ANY
			case *Backend6ValueV3:
				v.Proto = u8proto.ANY
			}
		}
		err = errors.Join(err, lbmaps.UpdateBackend(kv.key.(BackendKey), value))
	}
	for _, kv := range s.revNat {
		err = errors.Join(err, lbmaps.UpdateRevNat(kv.key.(RevNatKey), kv.value.(RevNatValue)))
	}
	for _, kv := range s.affinity {
		err = errors.Join(err, lbmaps.UpdateAffinityMatch(kv.key.(*AffinityMatchKey), kv.value.(*AffinityMatchValue)))
	}
	for _, kv := range s.srcRange {
		err = errors.Join(err, lbmaps.UpdateSourceRange(kv.key.(SourceRangeKey), kv.value.(*SourceRangeValue)))
	}
	return
}
