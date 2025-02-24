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
	"github.com/cilium/cilium/pkg/maps/lbmap"
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
	if !p.Config.EnableExperimentalLB {
		return bpf.MapOut[LBMaps]{}
	}

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
	UpdateService(key lbmap.ServiceKey, value lbmap.ServiceValue) error
	DeleteService(key lbmap.ServiceKey) error
	DumpService(cb func(lbmap.ServiceKey, lbmap.ServiceValue)) error
}

type backendMaps interface {
	UpdateBackend(lbmap.BackendKey, lbmap.BackendValue) error
	DeleteBackend(lbmap.BackendKey) error
	DumpBackend(cb func(lbmap.BackendKey, lbmap.BackendValue)) error
}

type revNatMaps interface {
	UpdateRevNat(lbmap.RevNatKey, lbmap.RevNatValue) error
	DeleteRevNat(lbmap.RevNatKey) error
	DumpRevNat(cb func(lbmap.RevNatKey, lbmap.RevNatValue)) error
}

type affinityMaps interface {
	UpdateAffinityMatch(*lbmap.AffinityMatchKey, *lbmap.AffinityMatchValue) error
	DeleteAffinityMatch(*lbmap.AffinityMatchKey) error
	DumpAffinityMatch(cb func(*lbmap.AffinityMatchKey, *lbmap.AffinityMatchValue)) error
}

type sourceRangeMaps interface {
	UpdateSourceRange(lbmap.SourceRangeKey, *lbmap.SourceRangeValue) error
	DeleteSourceRange(lbmap.SourceRangeKey) error
	DumpSourceRange(cb func(lbmap.SourceRangeKey, *lbmap.SourceRangeValue)) error
}

type maglevMaps interface {
	UpdateMaglev(key lbmap.MaglevOuterKey, backendIDs []loadbalancer.BackendID, ipv6 bool) error
	DeleteMaglev(key lbmap.MaglevOuterKey, ipv6 bool) error
	DumpMaglev(cb func(lbmap.MaglevOuterKey, lbmap.MaglevOuterVal, lbmap.MaglevInnerKey, *lbmap.MaglevInnerVal, bool)) error
}

type sockRevNatMaps interface {
	UpdateSockRevNat(cookie uint64, addr net.IP, port uint16, revNatIndex uint16) error
	DeleteSockRevNat(cookie uint64, addr net.IP, port uint16) error
	ExistsSockRevNat(cookie uint64, addr net.IP, port uint16) bool
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

func newService4Map(maxEntries int) *bpf.Map {
	return bpf.NewMap(
		lbmap.Service4MapV2Name,
		ebpf.Hash,
		&lbmap.Service4Key{},
		&lbmap.Service4Value{},
		maxEntries,
		0,
	)
}

func newService6Map(maxEntries int) *bpf.Map {
	return bpf.NewMap(
		lbmap.Service6MapV2Name,
		ebpf.Hash,
		&lbmap.Service6Key{},
		&lbmap.Service6Value{},
		maxEntries,
		0,
	)
}

func newBackend4Map(maxEntries int) *bpf.Map {
	return bpf.NewMap(
		lbmap.Backend4MapV3Name,
		ebpf.Hash,
		&lbmap.Backend4KeyV3{},
		&lbmap.Backend4ValueV3{},
		maxEntries,
		0,
	)
}

func newBackend6Map(maxEntries int) *bpf.Map {
	return bpf.NewMap(
		lbmap.Backend6MapV3Name,
		ebpf.Hash,
		&lbmap.Backend6KeyV3{},
		&lbmap.Backend6ValueV3{},
		maxEntries,
		0,
	)
}

func newRevNat4Map(maxEntries int) *bpf.Map {
	return bpf.NewMap(
		lbmap.RevNat4MapName,
		ebpf.Hash,
		&lbmap.RevNat4Key{},
		&lbmap.RevNat4Value{},
		maxEntries,
		0,
	)
}

func newRevNat6Map(maxEntries int) *bpf.Map {
	return bpf.NewMap(
		lbmap.RevNat6MapName,
		ebpf.Hash,
		&lbmap.RevNat6Key{},
		&lbmap.RevNat6Value{},
		maxEntries,
		0,
	)
}

func newAffinityMatchMap(maxEntries int) *bpf.Map {
	return bpf.NewMap(
		lbmap.AffinityMatchMapName,
		ebpf.Hash,
		&lbmap.AffinityMatchKey{},
		&lbmap.AffinityMatchValue{},
		maxEntries,
		0,
	)
}

func newSourceRange4Map(maxEntries int) *bpf.Map {
	return bpf.NewMap(
		lbmap.SourceRange4MapName,
		ebpf.LPMTrie,
		&lbmap.SourceRangeKey4{},
		&lbmap.SourceRangeValue{},
		maxEntries,
		0,
	)
}

func newSourceRange6Map(maxEntries int) *bpf.Map {
	return bpf.NewMap(
		lbmap.SourceRange6MapName,
		ebpf.LPMTrie,
		&lbmap.SourceRangeKey6{},
		&lbmap.SourceRangeValue{},
		maxEntries,
		0,
	)
}

func newSockRevNat4Map(maxEntries int) *bpf.Map {
	return bpf.NewMap(
		lbmap.SockRevNat4MapName,
		ebpf.LRUHash,
		&lbmap.SockRevNat4Key{},
		&lbmap.SockRevNat4Value{},
		maxEntries,
		0,
	)
}

func newSockRevNat6Map(maxEntries int) *bpf.Map {
	return bpf.NewMap(
		lbmap.SockRevNat6MapName,
		ebpf.LRUHash,
		&lbmap.SockRevNat6Key{},
		&lbmap.SockRevNat6Value{},
		maxEntries,
		0,
	)
}

func newMaglevOuterMap(name string, maxEntries int, innerSpec *ebpf.MapSpec) *bpf.Map {
	return bpf.NewMapWithInnerSpec(
		name,
		ebpf.HashOfMaps,
		&lbmap.MaglevOuterKey{},
		&lbmap.MaglevOuterVal{},
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
		return newMaglevOuterMap(lbmap.MaglevOuter4MapName, maxEntries, r.maglevInnerMapSpec)
	}
	newMaglev6 := func(maxEntries int) *bpf.Map {
		return newMaglevOuterMap(lbmap.MaglevOuter6MapName, maxEntries, r.maglevInnerMapSpec)
	}
	v4Maps := []mapDesc{
		{&r.service4Map, newService4Map, r.Cfg.LBServiceMapEntries},
		{&r.backend4Map, newBackend4Map, r.Cfg.LBBackendMapEntries},
		{&r.revNat4Map, newRevNat4Map, r.Cfg.LBRevNatEntries},
		{&r.sourceRange4Map, newSourceRange4Map, r.Cfg.LBSourceRangeMapEntries},
		{&r.maglev4Map, newMaglev4, r.Cfg.LBMaglevMapEntries},
		{&r.sockRevNat4Map, newSockRevNat4Map, r.Cfg.LBSockRevNatEntries},
	}
	v6Maps := []mapDesc{
		{&r.service6Map, newService6Map, r.Cfg.LBServiceMapEntries},
		{&r.backend6Map, newBackend6Map, r.Cfg.LBBackendMapEntries},
		{&r.revNat6Map, newRevNat6Map, r.Cfg.LBRevNatEntries},
		{&r.sourceRange6Map, newSourceRange6Map, r.Cfg.LBSourceRangeMapEntries},
		{&r.maglev6Map, newMaglev6, r.Cfg.LBMaglevMapEntries},
		{&r.sockRevNat6Map, newSockRevNat6Map, r.Cfg.LBSockRevNatEntries},
	}
	mapsToCreate := []mapDesc{
		{&r.affinityMatchMap, newAffinityMatchMap, r.Cfg.LBAffinityMapEntries},
	}
	mapsToDelete := []mapDesc{}
	if r.ExtCfg.EnableIPv4 {
		mapsToCreate = append(mapsToCreate, v4Maps...)
	} else {
		mapsToDelete = append(mapsToDelete, v4Maps...)
	}
	if r.ExtCfg.EnableIPv6 {
		mapsToCreate = append(mapsToCreate, v6Maps...)
	} else {
		mapsToDelete = append(mapsToDelete, v6Maps...)
	}
	return mapsToCreate, mapsToDelete
}

// Start implements cell.HookInterface.
func (r *BPFLBMaps) Start(ctx cell.HookContext) (err error) {
	r.maglevInnerMapSpec = &ebpf.MapSpec{
		Name:       lbmap.MaglevInnerMapName,
		Type:       ebpf.Array,
		KeySize:    uint32(unsafe.Sizeof(lbmap.MaglevInnerKey{})),
		MaxEntries: 1,
		ValueSize:  lbmap.MaglevBackendLen * uint32(r.MaglevCfg.TableSize),
	}

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
func (r *BPFLBMaps) DeleteRevNat(key lbmap.RevNatKey) error {
	var err error
	switch key.(type) {
	case *lbmap.RevNat4Key:
		err = r.revNat4Map.Delete(key)
	case *lbmap.RevNat6Key:
		err = r.revNat6Map.Delete(key)
	default:
		panic("unknown RevNatKey")
	}
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

// DumpRevNat implements lbmaps.
func (r *BPFLBMaps) DumpRevNat(cb func(lbmap.RevNatKey, lbmap.RevNatValue)) error {
	return errors.Join(
		dumpMap(r.revNat4Map, cb),
		dumpMap(r.revNat6Map, cb),
	)
}

// UpdateRevNat4 implements lbmaps.
func (r *BPFLBMaps) UpdateRevNat(key lbmap.RevNatKey, value lbmap.RevNatValue) error {
	switch key.(type) {
	case *lbmap.RevNat4Key:
		return r.revNat4Map.Update(key, value)
	case *lbmap.RevNat6Key:
		return r.revNat6Map.Update(key, value)
	default:
		panic("unknown RevNatKey")
	}
}

// DumpBackend implements lbmaps.
func (r *BPFLBMaps) DumpBackend(cb func(lbmap.BackendKey, lbmap.BackendValue)) error {
	return errors.Join(
		dumpMap(r.backend4Map, cb),
		dumpMap(r.backend6Map, cb),
	)
}

// DeleteBackend implements lbmaps.
func (r *BPFLBMaps) DeleteBackend(key lbmap.BackendKey) error {
	var err error
	switch key.(type) {
	case *lbmap.Backend4KeyV3:
		err = r.backend4Map.Delete(key)
	case *lbmap.Backend6KeyV3:
		err = r.backend6Map.Delete(key)
	default:
		panic("unknown BackendKey")
	}
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

// DeleteService implements lbmaps.
func (r *BPFLBMaps) DeleteService(key lbmap.ServiceKey) error {
	var err error
	switch key.(type) {
	case *lbmap.Service4Key:
		_, err = r.service4Map.SilentDelete(key)
	case *lbmap.Service6Key:
		_, err = r.service6Map.SilentDelete(key)
	default:
		panic("unknown ServiceKey")
	}
	return err
}

// DumpService implements lbmaps.
func (r *BPFLBMaps) DumpService(cb func(lbmap.ServiceKey, lbmap.ServiceValue)) error {
	return errors.Join(
		dumpMap(r.service4Map, cb),
		dumpMap(r.service6Map, cb),
	)
}

// UpdateBackend implements lbmaps.
func (r *BPFLBMaps) UpdateBackend(key lbmap.BackendKey, value lbmap.BackendValue) error {
	switch key.(type) {
	case *lbmap.Backend4KeyV3:
		return r.backend4Map.Update(key, value)
	case *lbmap.Backend6KeyV3:
		return r.backend6Map.Update(key, value)
	default:
		panic("unknown BackendKey")
	}
}

// UpdateService implements lbmaps.
func (r *BPFLBMaps) UpdateService(key lbmap.ServiceKey, value lbmap.ServiceValue) error {
	switch key.(type) {
	case *lbmap.Service4Key:
		return r.service4Map.Update(key, value)
	case *lbmap.Service6Key:
		return r.service6Map.Update(key, value)
	default:
		panic("unknown ServiceKey")
	}
}

// DeleteAffinityMatch implements lbmaps.
func (r *BPFLBMaps) DeleteAffinityMatch(key *lbmap.AffinityMatchKey) error {
	err := r.affinityMatchMap.Delete(key)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

// DumpAffinityMatch implements lbmaps.
func (r *BPFLBMaps) DumpAffinityMatch(cb func(*lbmap.AffinityMatchKey, *lbmap.AffinityMatchValue)) error {
	return dumpMap(r.affinityMatchMap, cb)
}

// UpdateAffinityMatch implements lbmaps.
func (r *BPFLBMaps) UpdateAffinityMatch(key *lbmap.AffinityMatchKey, value *lbmap.AffinityMatchValue) error {
	return r.affinityMatchMap.Update(key, value)
}

// DeleteSourceRange implements lbmaps.
func (r *BPFLBMaps) DeleteSourceRange(key lbmap.SourceRangeKey) error {
	var err error
	switch key.(type) {
	case *lbmap.SourceRangeKey4:
		err = r.sourceRange4Map.Delete(key)
	case *lbmap.SourceRangeKey6:
		err = r.sourceRange6Map.Delete(key)
	default:
		panic("unknown SourceRangeKey")
	}
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

// DumpSourceRange implements lbmaps.
func (r *BPFLBMaps) DumpSourceRange(cb func(lbmap.SourceRangeKey, *lbmap.SourceRangeValue)) error {
	return errors.Join(
		dumpMap(r.sourceRange4Map, cb),
		dumpMap(r.sourceRange6Map, cb),
	)
}

// UpdateSourceRange implements lbmaps.
func (r *BPFLBMaps) UpdateSourceRange(key lbmap.SourceRangeKey, value *lbmap.SourceRangeValue) error {
	switch key.(type) {
	case *lbmap.SourceRangeKey4:
		return r.sourceRange4Map.Update(key, value)
	case *lbmap.SourceRangeKey6:
		return r.sourceRange6Map.Update(key, value)
	default:
		panic("unknown SourceRangeKey")
	}
}

// UpdateMaglev implements lbmaps.
func (r *BPFLBMaps) UpdateMaglev(key lbmap.MaglevOuterKey, backendIDs []loadbalancer.BackendID, ipv6 bool) error {
	inner, err := ebpf.NewMap(r.maglevInnerMapSpec)
	if err != nil {
		return fmt.Errorf("failed to create map %q: %w", r.maglevInnerMapSpec.Name, err)
	}
	defer inner.Close()
	var singletonKey lbmap.MaglevInnerKey
	if err := inner.Update(singletonKey, backendIDs, 0); err != nil {
		return fmt.Errorf("updating backends: %w", err)
	}
	outerKey := &lbmap.MaglevOuterKey{
		RevNatID: byteorder.HostToNetwork16(key.RevNatID),
	}
	outerValue := &lbmap.MaglevOuterVal{FD: uint32(inner.FD())}
	if ipv6 {
		return r.maglev6Map.Update(outerKey, outerValue)
	} else {
		return r.maglev4Map.Update(outerKey, outerValue)
	}
}

// DeleteMaglev implements lbmaps.
func (r *BPFLBMaps) DeleteMaglev(key lbmap.MaglevOuterKey, ipv6 bool) error {
	outerKey := &lbmap.MaglevOuterKey{
		RevNatID: byteorder.HostToNetwork16(key.RevNatID),
	}
	ebpfmap := r.maglev4Map
	if ipv6 {
		ebpfmap = r.maglev6Map
	}
	err := ebpfmap.Delete(outerKey)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

func (r *BPFLBMaps) DumpMaglev(cb func(lbmap.MaglevOuterKey, lbmap.MaglevOuterVal, lbmap.MaglevInnerKey, *lbmap.MaglevInnerVal, bool)) error {
	var errs []error
	var ipv6 bool
	cbWrap := func(key bpf.MapKey, value bpf.MapValue) {
		maglevKey := lbmap.MaglevOuterKey{
			RevNatID: byteorder.NetworkToHost16(key.(*lbmap.MaglevOuterKey).RevNatID),
		}
		maglevValue := value.(*lbmap.MaglevOuterVal)
		inner, err := lbmap.MaglevInnerMapFromID(r.Log, maglevValue.FD)
		if err != nil {
			errs = append(errs, fmt.Errorf("cannot open inner map with fd %d: %w", maglevValue.FD, err))
			return
		}
		defer inner.Close()
		// Maglev inner map has a single key and a huge value.
		var singletonKey lbmap.MaglevInnerKey
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
		key := lbmap.NewSockRevNat4Key(cookie, addr, port)
		_, err := r.sockRevNat4Map.SilentDelete(key)
		return err
	} else if r.sockRevNat6Map != nil {
		key := lbmap.NewSockRevNat6Key(cookie, addr, port)
		_, err := r.sockRevNat6Map.SilentDelete(key)
		return err
	}
	return nil
}

// UpdateSockRevNat implements LBMaps.
func (r *BPFLBMaps) UpdateSockRevNat(cookie uint64, addr net.IP, port uint16, revNatIndex uint16) error {
	if addr.To4() != nil && r.sockRevNat4Map != nil {
		key := lbmap.NewSockRevNat4Key(cookie, addr, port)
		value := lbmap.SockRevNat4Value{
			Address:     key.Address,
			Port:        key.Port,
			RevNatIndex: revNatIndex,
		}
		return r.sockRevNat4Map.Update(key, &value)
	} else if r.sockRevNat6Map != nil {
		key := lbmap.NewSockRevNat6Key(cookie, addr, port)
		value := lbmap.SockRevNat6Value{
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
		key := lbmap.NewSockRevNat4Key(cookie, addr, port)
		if v, _ := r.sockRevNat4Map.Lookup(key); v != nil {
			return true
		}
	} else if r.sockRevNat6Map != nil {
		key := lbmap.NewSockRevNat6Key(cookie, addr, port)
		if v, _ := r.sockRevNat6Map.Lookup(key); v != nil {
			return true
		}
	}
	return false
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
func (f *FaultyLBMaps) DeleteSourceRange(key lbmap.SourceRangeKey) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.DeleteSourceRange(key)
}

// DumpSourceRange implements lbmaps.
func (f *FaultyLBMaps) DumpSourceRange(cb func(lbmap.SourceRangeKey, *lbmap.SourceRangeValue)) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.DumpSourceRange(cb)
}

// UpdateSourceRange implements lbmaps.
func (f *FaultyLBMaps) UpdateSourceRange(key lbmap.SourceRangeKey, value *lbmap.SourceRangeValue) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.UpdateSourceRange(key, value)
}

// DeleteAffinityMatch implements lbmaps.
func (f *FaultyLBMaps) DeleteAffinityMatch(key *lbmap.AffinityMatchKey) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.DeleteAffinityMatch(key)
}

// DumpAffinityMatch implements lbmaps.
func (f *FaultyLBMaps) DumpAffinityMatch(cb func(*lbmap.AffinityMatchKey, *lbmap.AffinityMatchValue)) error {
	return f.impl.DumpAffinityMatch(cb)
}

// UpdateAffinityMatch implements lbmaps.
func (f *FaultyLBMaps) UpdateAffinityMatch(key *lbmap.AffinityMatchKey, value *lbmap.AffinityMatchValue) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.UpdateAffinityMatch(key, value)
}

// DeleteRevNat implements lbmaps.
func (f *FaultyLBMaps) DeleteRevNat(key lbmap.RevNatKey) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.DeleteRevNat(key)
}

// DumpRevNat implements lbmaps.
func (f *FaultyLBMaps) DumpRevNat(cb func(lbmap.RevNatKey, lbmap.RevNatValue)) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.DumpRevNat(cb)
}

// UpdateRevNat implements lbmaps.
func (f *FaultyLBMaps) UpdateRevNat(key lbmap.RevNatKey, value lbmap.RevNatValue) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.UpdateRevNat(key, value)
}

// DeleteBackend implements lbmaps.
func (f *FaultyLBMaps) DeleteBackend(key lbmap.BackendKey) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.DeleteBackend(key)
}

// DeleteService implements lbmaps.
func (f *FaultyLBMaps) DeleteService(key lbmap.ServiceKey) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.DeleteService(key)
}

// DumpBackend implements lbmaps.
func (f *FaultyLBMaps) DumpBackend(cb func(lbmap.BackendKey, lbmap.BackendValue)) error {
	return f.impl.DumpBackend(cb)
}

// DumpService implements lbmaps.
func (f *FaultyLBMaps) DumpService(cb func(lbmap.ServiceKey, lbmap.ServiceValue)) error {
	return f.impl.DumpService(cb)
}

// IsEmpty implements lbmaps.
func (f *FaultyLBMaps) IsEmpty() bool {
	return f.impl.IsEmpty()
}

// UpdateBackend implements lbmaps.
func (f *FaultyLBMaps) UpdateBackend(key lbmap.BackendKey, value lbmap.BackendValue) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.UpdateBackend(key, value)
}

// UpdateService implements lbmaps.
func (f *FaultyLBMaps) UpdateService(key lbmap.ServiceKey, value lbmap.ServiceValue) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.UpdateService(key, value)
}

// UpdateMaglev implements lbmaps.
func (f *FaultyLBMaps) UpdateMaglev(key lbmap.MaglevOuterKey, backendIDs []loadbalancer.BackendID, ipv6 bool) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.UpdateMaglev(key, backendIDs, ipv6)
}

// DeleteMaglev implements lbmaps.
func (f *FaultyLBMaps) DeleteMaglev(key lbmap.MaglevOuterKey, ipv6 bool) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.DeleteMaglev(key, ipv6)
}

// DumpMaglev implements lbmaps.
func (f *FaultyLBMaps) DumpMaglev(cb func(lbmap.MaglevOuterKey, lbmap.MaglevOuterVal, lbmap.MaglevInnerKey, *lbmap.MaglevInnerVal, bool)) error {
	return f.impl.DumpMaglev(cb)
}

func (f *FaultyLBMaps) ExistsSockRevNat(cookie uint64, addr net.IP, port uint16) bool {
	return f.impl.ExistsSockRevNat(cookie, addr, port)
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
func (f *FakeLBMaps) DeleteAffinityMatch(key *lbmap.AffinityMatchKey) error {
	return f.aff.delete(key)
}

// DeleteBackend implements lbmaps.
func (f *FakeLBMaps) DeleteBackend(key lbmap.BackendKey) error {
	return f.be.delete(key)
}

// DeleteRevNat implements lbmaps.
func (f *FakeLBMaps) DeleteRevNat(key lbmap.RevNatKey) error {
	return f.revNat.delete(key)
}

// DeleteService implements lbmaps.
func (f *FakeLBMaps) DeleteService(key lbmap.ServiceKey) error {
	return f.svc.delete(key)
}

// DeleteSourceRange implements lbmaps.
func (f *FakeLBMaps) DeleteSourceRange(key lbmap.SourceRangeKey) error {
	return f.srcRange.delete(key)
}

// DumpAffinityMatch implements lbmaps.
func (f *FakeLBMaps) DumpAffinityMatch(cb func(*lbmap.AffinityMatchKey, *lbmap.AffinityMatchValue)) error {
	dumpFakeBPFMap(&f.aff, cb)
	return nil
}

// DumpBackend implements lbmaps.
func (f *FakeLBMaps) DumpBackend(cb func(lbmap.BackendKey, lbmap.BackendValue)) error {
	dumpFakeBPFMap(&f.be, cb)
	return nil
}

// DumpRevNat implements lbmaps.
func (f *FakeLBMaps) DumpRevNat(cb func(lbmap.RevNatKey, lbmap.RevNatValue)) error {
	dumpFakeBPFMap(&f.revNat, cb)
	return nil
}

// DumpService implements lbmaps.
func (f *FakeLBMaps) DumpService(cb func(lbmap.ServiceKey, lbmap.ServiceValue)) error {
	dumpFakeBPFMap(&f.svc, cb)
	return nil
}

// DumpSourceRange implements lbmaps.
func (f *FakeLBMaps) DumpSourceRange(cb func(lbmap.SourceRangeKey, *lbmap.SourceRangeValue)) error {
	dumpFakeBPFMap(&f.srcRange, cb)
	return nil
}

// UpdateAffinityMatch implements lbmaps.
func (f *FakeLBMaps) UpdateAffinityMatch(key *lbmap.AffinityMatchKey, value *lbmap.AffinityMatchValue) error {
	return f.aff.update(key, value)
}

// UpdateBackend implements lbmaps.
func (f *FakeLBMaps) UpdateBackend(key lbmap.BackendKey, value lbmap.BackendValue) error {
	return f.be.update(key, value)
}

// UpdateRevNat implements lbmaps.
func (f *FakeLBMaps) UpdateRevNat(key lbmap.RevNatKey, value lbmap.RevNatValue) error {
	return f.revNat.update(key, value)
}

// UpdateService implements lbmaps.
func (f *FakeLBMaps) UpdateService(key lbmap.ServiceKey, value lbmap.ServiceValue) error {
	return f.svc.update(key, value)
}

// UpdateSourceRange implements lbmaps.
func (f *FakeLBMaps) UpdateSourceRange(key lbmap.SourceRangeKey, value *lbmap.SourceRangeValue) error {
	return f.srcRange.update(key, value)
}

// UpdateMaglev implements lbmaps.
func (f *FakeLBMaps) UpdateMaglev(key lbmap.MaglevOuterKey, backendIDs []loadbalancer.BackendID, ipv6 bool) error {
	var outer *fakeBPFMap
	if ipv6 {
		outer = &f.mglv6
	} else {
		outer = &f.mglv4
	}
	var singletonKey lbmap.MaglevInnerKey
	inner := &fakeBPFMap{}
	currentID := f.nextID
	f.nextID++
	f.inners.Store(currentID, inner)
	value := lbmap.MaglevOuterVal{
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
func (f *FakeLBMaps) DeleteMaglev(key lbmap.MaglevOuterKey, ipv6 bool) error {
	if ipv6 {
		return f.mglv6.delete(&key)
	} else {
		return f.mglv4.delete(&key)
	}
}

func (f *FakeLBMaps) DumpMaglev(cb func(lbmap.MaglevOuterKey, lbmap.MaglevOuterVal, lbmap.MaglevInnerKey, *lbmap.MaglevInnerVal, bool)) error {
	var err error
	cbWrap := func(key lbmap.MaglevOuterKey, value lbmap.MaglevOuterVal, ipv6 bool) bool {
		singletonKey := lbmap.MaglevInnerKey{}
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
		cb(key, value, *innerValue.a.(*lbmap.MaglevInnerKey), &lbmap.MaglevInnerVal{BackendIDs: innerValue.b.([]loadbalancer.BackendID)}, ipv6)
		return true
	}
	f.mglv4.Range(func(_ string, pair kvpair) bool {
		return cbWrap(*pair.a.(*lbmap.MaglevOuterKey), pair.b.(lbmap.MaglevOuterVal), false)
	})
	f.mglv6.Range(func(_ string, pair kvpair) bool {
		return cbWrap(*pair.a.(*lbmap.MaglevOuterKey), pair.b.(lbmap.MaglevOuterVal), true)
	})
	return err
}

// DeleteSockRevNat implements LBMaps.
func (f *FakeLBMaps) DeleteSockRevNat(cookie uint64, addr net.IP, port uint16) error {
	var key bpf.MapKey
	if addr.To4() != nil {
		key4 := lbmap.NewSockRevNat4Key(cookie, addr, port)
		key = key4
	} else {
		key6 := lbmap.NewSockRevNat6Key(cookie, addr, port)
		key = key6
	}
	return f.sockRevNat.delete(key)
}

// UpdateSockRevNat implements LBMaps.
func (f *FakeLBMaps) UpdateSockRevNat(cookie uint64, addr net.IP, port uint16, revNatIndex uint16) error {
	var key bpf.MapKey
	var value bpf.MapValue
	if addr.To4() != nil {
		key4 := lbmap.NewSockRevNat4Key(cookie, addr, port)
		key = key4
		value = &lbmap.SockRevNat4Value{
			Address:     key4.Address,
			Port:        key4.Port,
			RevNatIndex: revNatIndex,
		}
	} else {
		key6 := lbmap.NewSockRevNat6Key(cookie, addr, port)
		key = key6
		value = &lbmap.SockRevNat6Value{
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
		key4 := lbmap.NewSockRevNat4Key(cookie, addr, port)
		key = key4
	} else {
		key6 := lbmap.NewSockRevNat6Key(cookie, addr, port)
		key = key6
	}
	return f.sockRevNat.exists(key)
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

	svcCB := func(svcKey lbmap.ServiceKey, svcValue lbmap.ServiceValue) {
		s.services = append(s.services, mapKeyValue{svcKey, svcValue})
	}
	if err := lbmaps.DumpService(svcCB); err != nil {
		return fmt.Errorf("DumpService: %w", err)
	}

	beCB := func(beKey lbmap.BackendKey, beValue lbmap.BackendValue) {
		s.backends = append(s.backends, mapKeyValue{beKey, beValue})
	}
	if err := lbmaps.DumpBackend(beCB); err != nil {
		return fmt.Errorf("DumpBackend: %w", err)
	}

	revCB := func(revKey lbmap.RevNatKey, revValue lbmap.RevNatValue) {
		s.revNat = append(s.revNat, mapKeyValue{revKey, revValue})
	}
	if err := lbmaps.DumpRevNat(revCB); err != nil {
		return fmt.Errorf("DumpRevNat: %w", err)
	}

	affCB := func(affKey *lbmap.AffinityMatchKey, affValue *lbmap.AffinityMatchValue) {
		s.affinity = append(s.revNat, mapKeyValue{affKey, affValue})
	}
	if err := lbmaps.DumpAffinityMatch(affCB); err != nil {
		return fmt.Errorf("DumpAffinityMatch: %w", err)
	}

	srcRangeCB := func(key lbmap.SourceRangeKey, value *lbmap.SourceRangeValue) {
		s.srcRange = append(s.srcRange, mapKeyValue{key, value})
	}
	if err := lbmaps.DumpSourceRange(srcRangeCB); err != nil {
		return fmt.Errorf("DumpSourceRange: %w", err)
	}
	return nil
}

func (s *mapSnapshots) restore(lbmaps LBMaps) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, kv := range s.services {
		err = errors.Join(err, lbmaps.UpdateService(kv.key.(lbmap.ServiceKey), kv.value.(lbmap.ServiceValue)))
	}
	for _, kv := range s.backends {
		err = errors.Join(err, lbmaps.UpdateBackend(kv.key.(lbmap.BackendKey), kv.value.(lbmap.BackendValue)))
	}
	for _, kv := range s.revNat {
		err = errors.Join(err, lbmaps.UpdateRevNat(kv.key.(lbmap.RevNatKey), kv.value.(lbmap.RevNatValue)))
	}
	for _, kv := range s.affinity {
		err = errors.Join(err, lbmaps.UpdateAffinityMatch(kv.key.(*lbmap.AffinityMatchKey), kv.value.(*lbmap.AffinityMatchValue)))
	}
	for _, kv := range s.srcRange {
		err = errors.Join(err, lbmaps.UpdateSourceRange(kv.key.(lbmap.SourceRangeKey), kv.value.(*lbmap.SourceRangeValue)))
	}
	return
}
