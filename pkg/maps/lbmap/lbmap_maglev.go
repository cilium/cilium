// Copyright 2016-2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package lbmap

import (
	"fmt"
	"math"
	"net"
	"reflect"
	"sort"
	"sync"

	"github.com/cilium/cilium/pkg/lock"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/u8proto"
)

const (
	// DefaultMaglevRingSize is the size of maglev hash rings
	DefaultMaglevRingSize = 65537
)

// LBMaglevBpfMap is an implementation of the LBMap interface with maglev hash.
type LBMaglevMap struct {
	ringSize int
	LBBPFMap
	LBMaglevServiceMap
}

// NewMaglevMap creates a new instance of the maglev LBMap handler.
func NewMaglevMap(ringSize int) (*LBMaglevMap, error) {
	return &LBMaglevMap{
		ringSize:           ringSize,
		LBBPFMap:           LBBPFMap{},
		LBMaglevServiceMap: LBMaglevServiceMap{Map: new(sync.Map)},
	}, nil
}

// UpsertService inserts or updates the given service in a BPF map.
//
// The corresponding backend entries (identified with the given backendIDs)
// have to exist before calling the function.
//
// The given prevBackendCount denotes a previous service backend entries count,
// so that the function can remove obsolete ones.
func (m *LBMaglevMap) UpsertService(
	svcID uint16, svcIP net.IP, svcPort uint16,
	backends []*loadbalancer.BackendMeta, prevBackendCount int,
	ipv6 bool, svcType loadbalancer.SVCType, svcLocal bool,
	svcScope uint8, sessionAffinity bool,
	sessionAffinityTimeoutSec uint32) error {

	var (
		err    error
		svcKey ServiceKey
	)

	if svcID == 0 {
		return fmt.Errorf("Invalid svc ID 0")
	}

	svc, ok, e := m.getMaglevService(svcID)
	if e != nil {
		err = fmt.Errorf("Unable to create maglev ring map of svc %v : %v", svcID, e)
		return err
	}
	defer func() {
		if err != nil && !ok {
			// create by us, so we should destroy it when err happens
			m.delMaglevService(svcID)
		}
	}()
	if e := svc.updateBackends(backends); e != nil {
		err = fmt.Errorf("Unable to update backends %v of svc %v : %v", backends, svcID, e)
		return err
	}

	if ipv6 {
		svcKey = NewService6Key(svcIP, svcPort, u8proto.ANY, 0, 0)
	} else {
		svcKey = NewService4Key(svcIP, svcPort, u8proto.ANY, 0, 0)
	}

	zeroValue := svcKey.NewValue().(ServiceValue)
	zeroValue.SetRevNat(int(svcID)) // TODO change to uint16
	revNATKey := zeroValue.RevNatKey()
	revNATValue := svcKey.RevNatValue()
	if e := updateRevNatLocked(revNATKey, revNATValue); e != nil {
		err = fmt.Errorf("Unable to update reverse NAT %+v => %+v: %s", revNATKey, revNATValue, e)
		goto end
	}
	defer func() {
		if err != nil {
			_ = deleteRevNatLocked(revNATKey)
		}
	}()

	if e := updateMasterService(svcKey, len(backends), int(svcID), svcType, svcLocal,
		sessionAffinity, sessionAffinityTimeoutSec); err != nil {

		err = fmt.Errorf("Unable to update service %+v: %s", svcKey, e)
		goto end
	}
end:
	return err
}

// DeleteService removes given service from a BPF map.
func (m *LBMaglevMap) DeleteService(svc loadbalancer.L3n4AddrID, backendCount int) error {
	var (
		svcKey    ServiceKey
		revNATKey RevNatKey
	)

	if svc.ID == 0 {
		return fmt.Errorf("Invalid svc ID 0")
	}

	if svc.IsIPv6() {
		svcKey = NewService6Key(svc.IP, svc.Port, u8proto.ANY, 0, 0)
		revNATKey = NewRevNat6Key(uint16(svc.ID))
	} else {
		svcKey = NewService4Key(svc.IP, svc.Port, u8proto.ANY, 0, 0)
		revNATKey = NewRevNat4Key(uint16(svc.ID))
	}

	if err := svcKey.MapDelete(); err != nil {
		return fmt.Errorf("Unable to delete service entry %+v: %s", svcKey, err)
	}

	if err := deleteRevNatLocked(revNATKey); err != nil {
		return fmt.Errorf("Unable to delete revNAT entry %+v: %s", revNATKey, err)
	}

	m.delMaglevService(uint16(svc.ID))

	return nil
}

// DumpServiceMaps dumps the services from the BPF maps.
func (m *LBMaglevMap) DumpServiceMaps() ([]*loadbalancer.SVC, []error) {
	newSVCMap, newBackendMap, flagsCache, errors := m.dumpServiceMaps()
	if len(errors) != 0 {
		return nil, errors
	}

	for _, svc := range newSVCMap {
		mSvc, _, err := m.getMaglevService(uint16(svc.Frontend.ID))
		if err != nil {
			errors = append(errors, err)
			continue
		}
		backendFreq, errs := mSvc.GetBackendFreq()
		if len(errs) != 0 {
			errors = append(errors, errs...)
			continue
		}
		backends := backendFreq[0].BackendSort
		for slot, backendID := range backends {
			backendValue, ok := newBackendMap[loadbalancer.BackendID(backendID)]
			if !ok {
				errors = append(errors, fmt.Errorf("backend %d not found", backendID))
				continue
			}
			be := svcBackend(loadbalancer.BackendID(backendID), backendValue)
			newSVCMap.addFEnBE(&svc.Frontend, be, slot+1)
		}
	}

	svcList := newSVCMap.toSvcList(flagsCache)

	return svcList, errors
}

func (m *LBMaglevMap) recoverMaglevService(id uint16) (*LBMaglevService, error) {
	var (
		svc          *LBMaglevService
		err, dumpErr error
		value        bpf.MapValue
		backendValue *MaglevRingValue
	)

	ringMap, err := lookupMaglevRingInnerMap(m.ringSize, id)
	if err != nil || ringMap == nil {
		log.WithError(err).Warningf("lookupMaglevRingInnerMap id %v", id)
		goto createOne
	}
	svc = &LBMaglevService{
		LBMaglevMap: m,
		ringMap:     ringMap,
		Ring:        loadbalancer.NewMaglevRing(m.ringSize, 0),
		Backends:    make(map[uint16]*loadbalancer.BackendMeta),
	}
	// recover ring
	value, err = ringMap.Lookup(&MaglevRingKey{Id: 0})
	if err != nil {
		log.WithError(err).Warningf("ringMap.Lookup key 0")
		goto createOne
	}
	backendValue = value.(*MaglevRingValue)
	if !backendValue.IsInvalid() {
		if err = ringMap.DumpWithCallback(func(key bpf.MapKey, value bpf.MapValue) {
			id := key.(*MaglevRingKey).Id
			if id >= uint32(len(svc.Ring)) {
				dumpErr = fmt.Errorf("invalid id %v", id)
				return
			}
			backendValue = value.(*MaglevRingValue)
			if backendValue.IsInvalid() {
				dumpErr = fmt.Errorf("invalid backend id %v", backendValue.BackendID)
				return
			}
			backendID := backendValue.BackendID
			svc.Ring[id] = int(backendID)

			// recover backends
			_, ok := svc.Backends[uint16(backendID)]
			if !ok {
				// FIXME: should add real backend here, not fake one.
				svc.Backends[uint16(backendID)] = &loadbalancer.BackendMeta{
					ID:            loadbalancer.BackendID(backendID),
					BackendMaglev: &loadbalancer.BackendMaglev{},
				}
			}
		}); err != nil || dumpErr != nil {
			log.Warningf("DumpWithCallback: %v, %v", err, dumpErr)
			goto createOne
		}
	}
	return svc, nil

createOne:
	return m.createMaglevService(id)
}

func (m *LBMaglevMap) createMaglevService(id uint16) (*LBMaglevService, error) {
	ringMap, err := createMaglevRingInnerMap(m.ringSize, id)
	if err != nil {
		return nil, fmt.Errorf("create inner maglev ring map : %v", err)
	}
	if err = registerMaglevRingMap(ringMap, id); err != nil {
		closeMaglevRingInnerMap(ringMap, id)
		return nil, fmt.Errorf("register inner maglev ring map : %v", err)
	}
	return &LBMaglevService{
		LBMaglevMap: m,
		ringMap:     ringMap,
		Ring:        loadbalancer.NewMaglevRing(m.ringSize, 0),
		Backends:    make(map[uint16]*loadbalancer.BackendMeta),
	}, nil
}

func (m *LBMaglevMap) getMaglevService(id uint16) (*LBMaglevService, bool, error) {
	var err error

	svc, ok := m.Load(id)
	if !ok {
		if svc, err = m.recoverMaglevService(id); err == nil {
			m.Store(id, svc)
		}
	}
	return svc, ok, err
}

func (m *LBMaglevMap) delMaglevService(id uint16) {
	if svc, ok := m.Load(id); ok {
		svc.lock.Lock()
		defer svc.lock.Unlock()

		_ = unregisterMaglevRingMap(id)
		if svc.ringMap != nil {
			closeMaglevRingInnerMap(svc.ringMap, id)
			svc.ringMap = nil
		}
	}
	m.Delete(id)
}

// Destruct is used to cleanup all maglev ring inner map and global map.
func (m *LBMaglevMap) Destruct() {
	m.Range(func(key uint16, value *LBMaglevService) bool {
		m.delMaglevService(key)
		return true
	})
}

// LBMaglevService is used to map service id and backend id with maglev hash.
type LBMaglevService struct {
	*LBMaglevMap
	lock     lock.RWMutex
	Ring     loadbalancer.MaglevRing
	ringMap  *bpf.Map
	Backends map[uint16]*loadbalancer.BackendMeta
}

func (s *LBMaglevService) getBackends(backends []*loadbalancer.BackendMeta) ([]*loadbalancer.BackendMeta, bool) {
	changed := false
	for _, b := range s.Backends {
		// ready to delete all backends
		b.ID = 0
	}
	for _, b := range backends {
		if o, ok := s.Backends[uint16(b.ID)]; ok {
			// save one backend
			o.ID = b.ID
			if *(o.BackendMaglev) != *(b.BackendMaglev) {
				*(o.BackendMaglev) = *(b.BackendMaglev)
				changed = true
			}
			continue
		}
		s.Backends[uint16(b.ID)] = &loadbalancer.BackendMeta{
			ID: b.ID,
			BackendMaglev: &loadbalancer.BackendMaglev{
				Hash:   b.Hash,
				Weight: b.Weight,
			},
		}
		changed = true
	}
	for id, b := range s.Backends {
		// delete obsolete backends
		if b.ID == 0 {
			delete(s.Backends, id)
			changed = true
		}
	}
	return backends, changed
}

func (s *LBMaglevService) updateBackends(backends []*loadbalancer.BackendMeta) error {
	for _, elem := range s.getMaglevElems(backends) {
		if e := s.updateMaglevElem(elem); e != nil {
			return fmt.Errorf("Unable to set maglev elem (%v,%v) : %v", elem.Key, elem.Value, e)
		}
	}
	return nil
}

func (s *LBMaglevService) getBackendFreq() (*LBBackendFreq, error) {
	backendFreq := newLBBackendFreq()
	s.lock.RLock()
	for _, id := range s.Ring {
		freq, ok := backendFreq.Backend[id]
		if !ok {
			freq = 0
		}
		freq++
		backendFreq.Backend[id] = freq
	}
	s.lock.RUnlock()
	backendFreq.sort()
	if !backendFreq.backendWeightEqual() {
		return backendFreq, fmt.Errorf("invalid backend freq %v", backendFreq.Backend)
	}
	return backendFreq, nil
}

func (s *LBMaglevService) getMaglevElems(backends []*loadbalancer.BackendMeta) (elems []*loadbalancer.MaglevElem) {
	s.lock.Lock()
	defer s.lock.Unlock()

	ringSize := s.ringSize
	if deltaBackends, changed := s.getBackends(backends); changed {
		newRing := generateMaglevHash(deltaBackends, uint32(ringSize))
		for i := 0; i < ringSize; i++ {
			if newRing[i] != s.Ring[i] {
				s.Ring[i] = newRing[i]
				elems = append(elems, &loadbalancer.MaglevElem{
					Key:   uint32(i),
					Value: int32(newRing[i]),
				})
			}
		}
	}
	return elems
}

func (s *LBMaglevService) updateMaglevElem(elem *loadbalancer.MaglevElem) error {
	s.lock.RLock()
	defer s.lock.RUnlock()

	if s.ringMap != nil {
		return s.ringMap.Update(&MaglevRingKey{Id: elem.Key}, &MaglevRingValue{BackendID: elem.Value})
	}
	return fmt.Errorf("maglev bpf ring map is nil")
}

func (s *LBMaglevService) getBackendFreqBpf() (*LBBackendFreq, error) {
	var (
		err         error
		backendFreq = newLBBackendFreq()
	)

	s.lock.RLock()
	if s.ringMap != nil {
		err = s.ringMap.DumpWithCallback(func(key bpf.MapKey, value bpf.MapValue) {
			mValue := value.(*MaglevRingValue)
			i := int(mValue.BackendID)
			freq, ok := backendFreq.Backend[i]
			if !ok {
				freq = 0
			}
			freq++
			backendFreq.Backend[i] = freq
		})
	}
	s.lock.RUnlock()

	backendFreq.sort()
	if !backendFreq.backendWeightEqual() {
		return backendFreq, fmt.Errorf("invalid backend freq %v", backendFreq.Backend)
	}
	return backendFreq, err
}

// GetBackendFreq returns local and kernel BPF backend frequency struct.
// Both two of them should be equal according to maglev hash algorithm.
func (s *LBMaglevService) GetBackendFreq() ([2]*LBBackendFreq, []error) {
	backendFreq := [2]*LBBackendFreq{}
	errors := []error{}

	backendFreqLocal, err := s.getBackendFreq()
	if err != nil {
		errors = append(errors, err)
	}
	backendFreq[0] = backendFreqLocal

	backendFreqBpf, err := s.getBackendFreqBpf()
	if err != nil {
		errors = append(errors, err)
	}
	backendFreq[1] = backendFreqBpf

	if !reflect.DeepEqual(backendFreqLocal.Backend, backendFreqBpf.Backend) {
		errors = append(errors, fmt.Errorf("local maglev ring not equal to bpf ring"))
	}

	return backendFreq, errors
}

// LBMaglevServiceMap is a sync map of LBMaglevService.
type LBMaglevServiceMap struct {
	*sync.Map
}

// Range calls f sequentially for each key and value present in the map.
// If f returns false, range stops the iteration.
func (m *LBMaglevServiceMap) Range(f func(key uint16, value *LBMaglevService) bool) {
	m.Map.Range(func(key, value interface{}) bool {
		return f(key.(uint16), value.(*LBMaglevService))
	})
}

// Load returns the value stored in the map for a key, or nil if no
// value is present.
// The ok result indicates whether value was found in the map.
func (m *LBMaglevServiceMap) Load(key uint16) (*LBMaglevService, bool) {
	if value, ok := m.Map.Load(key); ok {
		return value.(*LBMaglevService), true
	}
	return nil, false
}

type LBBackendFreq struct {
	Min         int
	Max         int
	Backend     map[int]int
	BackendSort []int
}

func newLBBackendFreq() *LBBackendFreq {
	return &LBBackendFreq{
		Min:     math.MaxInt32,
		Backend: make(map[int]int),
	}
}

func (b *LBBackendFreq) sort() {
	var backendSort []int

	for id, w := range b.Backend {
		if w > b.Max {
			b.Max = w
		}
		if w < b.Min {
			b.Min = w
		}
		backendSort = append(backendSort, id)
	}
	sort.Ints(backendSort)
	b.BackendSort = backendSort
}

// testing that when weights are equal and = 1 the diff
// between max and min frequency is 1 as maglev's doc
// promised
func (b *LBBackendFreq) backendWeightEqual() bool {
	return b.Max-b.Min == 1
}
