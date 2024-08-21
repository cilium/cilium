// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package experimental

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"reflect"
	"unsafe"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/option"
)

// LBMapsConfig specifies the configuration for the load-balancing BPF
// maps.
type LBMapsConfig struct {
	MaxSockRevNatMapEntries                                         int
	ServiceMapMaxEntries, BackendMapMaxEntries, RevNatMapMaxEntries int
	AffinityMapMaxEntries                                           int
	SourceRangeMapMaxEntries                                        int
	MaglevMapMaxEntries                                             int
}

// newLBMapsConfig creates the config from the DaemonConfig. When we
// move to the new implementation this should be replaced with a cell.Config.
func newLBMapsConfig(dcfg *option.DaemonConfig) (cfg LBMapsConfig) {
	cfg.MaxSockRevNatMapEntries = dcfg.SockRevNatEntries
	cfg.ServiceMapMaxEntries = dcfg.LBMapEntries
	cfg.BackendMapMaxEntries = dcfg.LBMapEntries
	cfg.RevNatMapMaxEntries = dcfg.LBMapEntries
	cfg.AffinityMapMaxEntries = dcfg.LBMapEntries
	cfg.SourceRangeMapMaxEntries = dcfg.LBMapEntries
	cfg.MaglevMapMaxEntries = dcfg.LBMapEntries
	if dcfg.LBServiceMapEntries > 0 {
		cfg.ServiceMapMaxEntries = dcfg.LBServiceMapEntries
	}
	if dcfg.LBBackendMapEntries > 0 {
		cfg.BackendMapMaxEntries = dcfg.LBBackendMapEntries
	}
	if dcfg.LBRevNatEntries > 0 {
		cfg.RevNatMapMaxEntries = dcfg.LBRevNatEntries
	}
	if dcfg.LBAffinityMapEntries > 0 {
		cfg.AffinityMapMaxEntries = dcfg.LBAffinityMapEntries
	}
	if dcfg.LBSourceRangeMapEntries > 0 {
		cfg.SourceRangeMapMaxEntries = dcfg.LBSourceRangeMapEntries
	}
	if dcfg.LBMaglevMapEntries > 0 {
		cfg.MaglevMapMaxEntries = dcfg.LBMaglevMapEntries
	}
	return
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

// LBMaps defines the map operations performed by the reconciliation.
// Depending on this interface instead of on the underlying maps allows
// testing the implementation with a fake map or injected errors.
type LBMaps interface {
	serviceMaps
	backendMaps
	revNatMaps
	affinityMaps
	sourceRangeMaps

	// TODO rest of the maps:
	// Maglev, SockRevNat, SkipLB
	IsEmpty() bool
}

type BPFLBMaps struct {
	// Pinned if true will pin the maps to a file. Tests may turn this off.
	Pinned bool

	Cfg LBMapsConfig

	service4Map, service6Map         *ebpf.Map
	backend4Map, backend6Map         *ebpf.Map
	revNat4Map, revNat6Map           *ebpf.Map
	affinityMatchMap                 *ebpf.Map
	sourceRange4Map, sourceRange6Map *ebpf.Map
}

func sizeOf[T any]() uint32 {
	var x T
	return uint32(reflect.TypeOf(x).Size())
}

// BPF map specs
var (
	service4MapSpec = &ebpf.MapSpec{
		Name:      lbmap.Service4MapV2Name,
		Type:      ebpf.Hash,
		KeySize:   sizeOf[lbmap.Service4Key](),
		ValueSize: sizeOf[lbmap.Service4Value](),
	}

	service6MapSpec = &ebpf.MapSpec{
		Name:      lbmap.Service6MapV2Name,
		Type:      ebpf.Hash,
		KeySize:   sizeOf[lbmap.Service6Key](),
		ValueSize: sizeOf[lbmap.Service6Value](),
	}

	backend4MapSpec = &ebpf.MapSpec{
		Name:      lbmap.Backend4MapV3Name,
		Type:      ebpf.Hash,
		KeySize:   sizeOf[lbmap.Backend4KeyV3](),
		ValueSize: sizeOf[lbmap.Backend4ValueV3](),
	}

	backend6MapSpec = &ebpf.MapSpec{
		Name:      lbmap.Backend6MapV3Name,
		Type:      ebpf.Hash,
		KeySize:   sizeOf[lbmap.Backend6KeyV3](),
		ValueSize: sizeOf[lbmap.Backend6ValueV3](),
	}

	revNat4MapSpec = &ebpf.MapSpec{
		Name:      lbmap.RevNat4MapName,
		Type:      ebpf.Hash,
		KeySize:   sizeOf[lbmap.RevNat4Key](),
		ValueSize: sizeOf[lbmap.RevNat4Value](),
	}

	revNat6MapSpec = &ebpf.MapSpec{
		Name:      lbmap.RevNat6MapName,
		Type:      ebpf.Hash,
		KeySize:   sizeOf[lbmap.RevNat6Key](),
		ValueSize: sizeOf[lbmap.RevNat6Value](),
	}

	affinityMatchMapSpec = &ebpf.MapSpec{
		Name:      lbmap.AffinityMatchMapName,
		Type:      ebpf.Hash,
		KeySize:   sizeOf[lbmap.AffinityMatchKey](),
		ValueSize: sizeOf[lbmap.AffinityMatchValue](),
	}

	sourceRange4MapSpec = &ebpf.MapSpec{
		Name:      lbmap.SourceRange4MapName,
		Type:      ebpf.LPMTrie,
		KeySize:   sizeOf[lbmap.SourceRangeKey4](),
		ValueSize: sizeOf[lbmap.SourceRangeValue](),
	}

	sourceRange6MapSpec = &ebpf.MapSpec{
		Name:      lbmap.SourceRange6MapName,
		Type:      ebpf.LPMTrie,
		KeySize:   sizeOf[lbmap.SourceRangeKey6](),
		ValueSize: sizeOf[lbmap.SourceRangeValue](),
	}
)

type mapDesc struct {
	target     **ebpf.Map // pointer to the field in realLBMaps
	spec       *ebpf.MapSpec
	maxEntries int
}

func (r *BPFLBMaps) allMaps() []mapDesc {
	return []mapDesc{
		{&r.service4Map, service4MapSpec, r.Cfg.ServiceMapMaxEntries},
		{&r.service6Map, service6MapSpec, r.Cfg.ServiceMapMaxEntries},
		{&r.backend4Map, backend4MapSpec, r.Cfg.BackendMapMaxEntries},
		{&r.backend6Map, backend6MapSpec, r.Cfg.BackendMapMaxEntries},
		{&r.revNat4Map, revNat4MapSpec, r.Cfg.RevNatMapMaxEntries},
		{&r.revNat6Map, revNat6MapSpec, r.Cfg.RevNatMapMaxEntries},
		{&r.affinityMatchMap, affinityMatchMapSpec, r.Cfg.AffinityMapMaxEntries},
		{&r.sourceRange4Map, sourceRange4MapSpec, r.Cfg.SourceRangeMapMaxEntries},
		{&r.sourceRange6Map, sourceRange6MapSpec, r.Cfg.SourceRangeMapMaxEntries},
	}
}

// Start implements cell.HookInterface.
func (r *BPFLBMaps) Start(cell.HookContext) error {
	for _, desc := range r.allMaps() {
		if r.Pinned {
			desc.spec.Pinning = ebpf.PinByName
		} else {
			desc.spec.Pinning = ebpf.PinNone
		}
		desc.spec.MaxEntries = uint32(desc.maxEntries)
		m := ebpf.NewMap(desc.spec)
		*desc.target = m

		if err := m.OpenOrCreate(); err != nil {
			return fmt.Errorf("opening map %s: %w", desc.spec.Name, err)
		}
	}
	return nil
}

// Stop implements cell.HookInterface.
func (r *BPFLBMaps) Stop(cell.HookContext) error {
	var errs []error
	for _, desc := range r.allMaps() {
		m := *desc.target
		if m != nil {
			if err := m.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
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
	cbWrap := func(key, value any) {
		cb(
			key.(lbmap.RevNatKey),
			value.(lbmap.RevNatValue),
		)
	}
	return errors.Join(
		r.revNat4Map.IterateWithCallback(&lbmap.RevNat4Key{}, &lbmap.RevNat4Value{}, cbWrap),
		r.revNat6Map.IterateWithCallback(&lbmap.RevNat6Key{}, &lbmap.RevNat6Value{}, cbWrap),
	)
}

// UpdateRevNat4 implements lbmaps.
func (r *BPFLBMaps) UpdateRevNat(key lbmap.RevNatKey, value lbmap.RevNatValue) error {
	switch key.(type) {
	case *lbmap.RevNat4Key:
		return r.revNat4Map.Update(key, value, 0)
	case *lbmap.RevNat6Key:
		return r.revNat6Map.Update(key, value, 0)
	default:
		panic("unknown RevNatKey")
	}
}

// DumpBackend implements lbmaps.
func (r *BPFLBMaps) DumpBackend(cb func(lbmap.BackendKey, lbmap.BackendValue)) error {
	cbWrap := func(key, value any) {
		cb(
			key.(lbmap.BackendKey),
			value.(lbmap.BackendValue),
		)
	}
	return errors.Join(
		r.backend4Map.IterateWithCallback(&lbmap.Backend4KeyV3{}, &lbmap.Backend4ValueV3{}, cbWrap),
		r.backend6Map.IterateWithCallback(&lbmap.Backend6KeyV3{}, &lbmap.Backend6ValueV3{}, cbWrap),
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
		err = r.service4Map.Delete(key)
	case *lbmap.Service6Key:
		err = r.service6Map.Delete(key)
	default:
		panic("unknown ServiceKey")
	}
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

// DumpService implements lbmaps.
func (r *BPFLBMaps) DumpService(cb func(lbmap.ServiceKey, lbmap.ServiceValue)) error {
	cbWrap := func(key, value any) {
		svcKey := key.(lbmap.ServiceKey)
		svcValue := value.(lbmap.ServiceValue)
		cb(svcKey, svcValue)
	}

	return errors.Join(
		r.service4Map.IterateWithCallback(&lbmap.Service4Key{}, &lbmap.Service4Value{}, cbWrap),
		r.service6Map.IterateWithCallback(&lbmap.Service6Key{}, &lbmap.Service6Value{}, cbWrap),
	)
}

// UpdateBackend implements lbmaps.
func (r *BPFLBMaps) UpdateBackend(key lbmap.BackendKey, value lbmap.BackendValue) error {
	switch key.(type) {
	case *lbmap.Backend4KeyV3:
		return r.backend4Map.Update(key, value, 0)
	case *lbmap.Backend6KeyV3:
		return r.backend6Map.Update(key, value, 0)
	default:
		panic("unknown BackendKey")
	}
}

// UpdateService implements lbmaps.
func (r *BPFLBMaps) UpdateService(key lbmap.ServiceKey, value lbmap.ServiceValue) error {
	switch key.(type) {
	case *lbmap.Service4Key:
		return r.service4Map.Update(key, value, 0)
	case *lbmap.Service6Key:
		return r.service6Map.Update(key, value, 0)
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
	cbWrap := func(key, value any) {
		affKey := key.(*lbmap.AffinityMatchKey)
		affValue := value.(*lbmap.AffinityMatchValue)
		cb(affKey, affValue)
	}
	return r.affinityMatchMap.IterateWithCallback(
		&lbmap.AffinityMatchKey{},
		&lbmap.AffinityMatchValue{},
		cbWrap,
	)
}

// UpdateAffinityMatch implements lbmaps.
func (r *BPFLBMaps) UpdateAffinityMatch(key *lbmap.AffinityMatchKey, value *lbmap.AffinityMatchValue) error {
	return r.affinityMatchMap.Update(key, value, 0)
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
	cbWrap := func(key, value any) {
		svcKey := key.(lbmap.SourceRangeKey)
		svcValue := value.(*lbmap.SourceRangeValue)

		cb(svcKey, svcValue)
	}

	return errors.Join(
		r.sourceRange4Map.IterateWithCallback(&lbmap.SourceRangeKey4{}, &lbmap.SourceRangeValue{}, cbWrap),
		r.sourceRange6Map.IterateWithCallback(&lbmap.SourceRangeKey6{}, &lbmap.SourceRangeValue{}, cbWrap),
	)
}

// UpdateSourceRange implements lbmaps.
func (r *BPFLBMaps) UpdateSourceRange(key lbmap.SourceRangeKey, value *lbmap.SourceRangeValue) error {
	switch key.(type) {
	case *lbmap.SourceRangeKey4:
		return r.sourceRange4Map.Update(key, value, 0)
	case *lbmap.SourceRangeKey6:
		return r.sourceRange6Map.Update(key, value, 0)
	default:
		panic("unknown SourceRangeKey")
	}
}

// IsEmpty implements lbmaps.
func (r *BPFLBMaps) IsEmpty() bool {
	return r.service4Map.IsEmpty() &&
		r.service6Map.IsEmpty() &&
		r.backend4Map.IsEmpty() &&
		r.backend6Map.IsEmpty() &&
		r.revNat4Map.IsEmpty() &&
		r.revNat6Map.IsEmpty() &&
		r.affinityMatchMap.IsEmpty() &&
		r.sourceRange4Map.IsEmpty() &&
		r.sourceRange6Map.IsEmpty()
}

var _ LBMaps = &BPFLBMaps{}

type FaultyLBMaps struct {
	impl LBMaps

	// 0.0 (never fail) ... 1.0 (always fail)
	failureProbability float32
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
	aff      fakeBPFMap
	be       fakeBPFMap
	svc      fakeBPFMap
	revNat   fakeBPFMap
	srcRange fakeBPFMap
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

// IsEmpty implements lbmaps.
func (f *FakeLBMaps) IsEmpty() bool {
	return f.aff.IsEmpty() &&
		f.be.IsEmpty() &&
		f.svc.IsEmpty() &&
		f.revNat.IsEmpty() &&
		f.srcRange.IsEmpty()
}

var _ LBMaps = &FakeLBMaps{}
