// Copyright 2016-2021 Authors of Cilium
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
	"net"
	"sort"
	"strconv"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/u8proto"

	"github.com/sirupsen/logrus"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "map-lb")

var (
	// MaxEntries contains the maximum number of entries that are allowed
	// in Cilium LB service, backend and affinity maps.
	MaxEntries = 65536
)

// LBBPFMap is an implementation of the LBMap interface.
type LBBPFMap struct {
	// Buffer used to avoid excessive allocations to temporarily store backend
	// IDs. Concurrent access is protected by the
	// pkg/service.go:(Service).UpsertService() lock.
	maglevBackendIDsBuffer []uint16
	maglevTableSize        uint64
}

func New(maglev bool, maglevTableSize int) *LBBPFMap {
	m := &LBBPFMap{}

	if maglev {
		m.maglevBackendIDsBuffer = make([]uint16, maglevTableSize)
		m.maglevTableSize = uint64(maglevTableSize)
	}

	return m
}

type UpsertServiceParams struct {
	ID                        uint16
	IP                        net.IP
	Port                      uint16
	Protocol                  string
	Backends                  map[string]uint16
	PrevBackendCount          int
	IPv6                      bool
	Type                      loadbalancer.SVCType
	Local                     bool
	Scope                     uint8
	SessionAffinity           bool
	SessionAffinityTimeoutSec uint32
	CheckSourceRange          bool
	UseMaglev                 bool
}

// UpsertService inserts or updates the given service in a BPF map.
//
// The corresponding backend entries (identified with the given backendIDs)
// have to exist before calling the function.
//
// The given prevBackendCount denotes a previous service backend entries count,
// so that the function can remove obsolete ones.
func (lbmap *LBBPFMap) UpsertService(p *UpsertServiceParams) error {
	var svcKey ServiceKey

	if p.ID == 0 {
		return fmt.Errorf("Invalid svc ID 0")
	}

	proto, err := u8proto.ParseProtocol(p.Protocol)
	if err != nil {
		return err
	}

	if p.IPv6 {
		svcKey = NewService6Key(p.IP, p.Port, proto, p.Scope, 0)
	} else {
		svcKey = NewService4Key(p.IP, p.Port, proto, p.Scope, 0)
	}

	slot := 1
	svcVal := svcKey.NewValue().(ServiceValue)

	if p.UseMaglev && len(p.Backends) != 0 {
		if err := lbmap.UpsertMaglevLookupTable(p.ID, p.Backends, p.IPv6); err != nil {
			return err
		}
	}

	backendIDs := make([]uint16, 0, len(p.Backends))
	for _, id := range p.Backends {
		backendIDs = append(backendIDs, id)
	}
	for _, backendID := range backendIDs {
		if backendID == 0 {
			return fmt.Errorf("Invalid backend ID 0")
		}
		svcVal.SetBackendID(loadbalancer.BackendID(backendID))
		svcVal.SetRevNat(int(p.ID))
		svcKey.SetBackendSlot(slot)
		if err := updateServiceEndpoint(svcKey, svcVal); err != nil {
			return fmt.Errorf("Unable to update service entry %+v => %+v: %s",
				svcKey, svcVal, err)
		}
		slot++
	}

	zeroValue := svcKey.NewValue().(ServiceValue)
	zeroValue.SetRevNat(int(p.ID)) // TODO change to uint16
	revNATKey := zeroValue.RevNatKey()
	revNATValue := svcKey.RevNatValue()
	if err := updateRevNatLocked(revNATKey, revNATValue); err != nil {
		return fmt.Errorf("Unable to update reverse NAT %+v => %+v: %s", revNATKey, revNATValue, err)
	}

	if err := updateMasterService(svcKey, len(backendIDs), int(p.ID), p.Type, p.Local,
		p.SessionAffinity, p.SessionAffinityTimeoutSec, p.CheckSourceRange); err != nil {

		deleteRevNatLocked(revNATKey)
		return fmt.Errorf("Unable to update service %+v: %s", svcKey, err)
	}

	for i := slot; i <= p.PrevBackendCount; i++ {
		svcKey.SetBackendSlot(i)
		if err := deleteServiceLocked(svcKey); err != nil {
			log.WithFields(logrus.Fields{
				logfields.ServiceKey:  svcKey,
				logfields.BackendSlot: svcKey.GetBackendSlot(),
			}).WithError(err).Warn("Unable to delete service entry from BPF map")
		}
	}

	return nil
}

// UpsertMaglevLookupTable calculates Maglev lookup table for given backends, and
// inserts into the Maglev BPF map.
func (lbmap *LBBPFMap) UpsertMaglevLookupTable(svcID uint16, backends map[string]uint16, ipv6 bool) error {
	backendNames := make([]string, 0, len(backends))
	for name := range backends {
		backendNames = append(backendNames, name)
	}
	// Maglev algorithm might produce different lookup table for the same
	// set of backends listed in a different order. To avoid that sort
	// backends by name, as the names are the same on all nodes (in opposite
	// to backend IDs which are node-local).
	sort.Strings(backendNames)
	table := maglev.GetLookupTable(backendNames, lbmap.maglevTableSize)
	for i, pos := range table {
		lbmap.maglevBackendIDsBuffer[i] = backends[backendNames[pos]]
	}

	if err := updateMaglevTable(ipv6, svcID, lbmap.maglevBackendIDsBuffer); err != nil {
		return err
	}

	return nil
}

// DeleteService removes given service from a BPF map.
func (*LBBPFMap) DeleteService(svc loadbalancer.L3n4AddrID, backendCount int, useMaglev bool) error {
	var (
		svcKey    ServiceKey
		revNATKey RevNatKey
	)

	if svc.ID == 0 {
		return fmt.Errorf("Invalid svc ID 0")
	}

	proto, err := u8proto.ParseProtocol(string(svc.Protocol))
	if err != nil {
		return err
	}
	ipv6 := svc.IsIPv6()
	if ipv6 {
		svcKey = NewService6Key(svc.IP, svc.Port, proto, svc.Scope, 0)
		revNATKey = NewRevNat6Key(uint16(svc.ID))
	} else {
		svcKey = NewService4Key(svc.IP, svc.Port, proto, svc.Scope, 0)
		revNATKey = NewRevNat4Key(uint16(svc.ID))
	}

	for slot := 0; slot <= backendCount; slot++ {
		svcKey.SetBackendSlot(slot)
		if err := svcKey.MapDelete(); err != nil {
			return fmt.Errorf("Unable to delete service entry %+v: %s", svcKey, err)
		}
	}

	if useMaglev {
		if err := deleteMaglevTable(ipv6, uint16(svc.ID)); err != nil {
			return fmt.Errorf("Unable to delete maglev lookup table %d: %s", svc.ID, err)
		}
	}

	if err := deleteRevNatLocked(revNATKey); err != nil {
		return fmt.Errorf("Unable to delete revNAT entry %+v: %s", revNATKey, err)
	}

	return nil
}

// AddBackend adds a backend into a BPF map.
func (*LBBPFMap) AddBackend(id uint16, ip net.IP, protocol loadbalancer.L4Type, port uint16, ipv6 bool) error {
	var (
		backend Backend
		err     error
	)

	if id == 0 {
		return fmt.Errorf("Invalid backend ID 0")
	}

	p, err := u8proto.ParseProtocol(string(protocol))
	if err != nil {
		return err
	}
	if ipv6 {
		backend, err = NewBackend6(loadbalancer.BackendID(id), ip, port, p)
	} else {
		backend, err = NewBackend4(loadbalancer.BackendID(id), ip, port, p)
	}
	if err != nil {
		return fmt.Errorf("Unable to create backend (%d, %s, %d, %t): %s",
			id, ip, port, ipv6, err)
	}

	if err := updateBackend(backend); err != nil {
		return fmt.Errorf("Unable to add backend %+v: %s", backend, err)
	}

	return nil
}

// DeleteBackendByID removes a backend identified with the given ID from a BPF map.
func (*LBBPFMap) DeleteBackendByID(id uint16, ipv6 bool) error {
	var key BackendKey

	if id == 0 {
		return fmt.Errorf("Invalid backend ID 0")
	}

	if ipv6 {
		key = NewBackend6Key(loadbalancer.BackendID(id))
	} else {
		key = NewBackend4Key(loadbalancer.BackendID(id))
	}

	if err := deleteBackendLocked(key); err != nil {
		return fmt.Errorf("Unable to delete backend %d (%t): %s", id, ipv6, err)
	}

	return nil
}

// DeleteAffinityMatch removes the affinity match for the given svc and backend ID
// tuple from the BPF map
func (*LBBPFMap) DeleteAffinityMatch(revNATID uint16, backendID uint16) error {
	return AffinityMatchMap.Delete(
		NewAffinityMatchKey(revNATID, uint32(backendID)).ToNetwork())
}

// AddAffinityMatch adds the given affinity match to the BPF map.
func (*LBBPFMap) AddAffinityMatch(revNATID uint16, backendID uint16) error {
	return AffinityMatchMap.Update(
		NewAffinityMatchKey(revNATID, uint32(backendID)).ToNetwork(),
		&AffinityMatchValue{})
}

// DumpAffinityMatches returns the affinity match map represented as a nested
// map which first key is svc ID and the second - backend ID.
func (*LBBPFMap) DumpAffinityMatches() (BackendIDByServiceIDSet, error) {
	matches := BackendIDByServiceIDSet{}

	parse := func(key bpf.MapKey, value bpf.MapValue) {
		matchKey := key.DeepCopyMapKey().(*AffinityMatchKey).ToHost()
		svcID := matchKey.RevNATID
		backendID := uint16(matchKey.BackendID) // currently backend_id is u16

		if _, ok := matches[svcID]; !ok {
			matches[svcID] = map[uint16]struct{}{}
		}
		matches[svcID][backendID] = struct{}{}
	}

	err := AffinityMatchMap.DumpWithCallback(parse)
	if err != nil {
		return nil, err
	}

	return matches, nil
}

func (*LBBPFMap) DumpSourceRanges(ipv6 bool) (SourceRangeSetByServiceID, error) {
	ret := SourceRangeSetByServiceID{}
	parser := func(key bpf.MapKey, value bpf.MapValue) {
		k := key.(SourceRangeKey).ToHost()
		revNATID := k.GetRevNATID()
		if _, found := ret[revNATID]; !found {
			ret[revNATID] = []*cidr.CIDR{}
		}
		ret[revNATID] = append(ret[revNATID], k.GetCIDR())
	}

	m := SourceRange4Map
	if ipv6 {
		m = SourceRange6Map
	}
	if err := m.DumpWithCallback(parser); err != nil {
		return nil, err
	}

	return ret, nil
}

func updateRevNatLocked(key RevNatKey, value RevNatValue) error {
	if key.GetKey() == 0 {
		return fmt.Errorf("invalid RevNat ID (0)")
	}
	if _, err := key.Map().OpenOrCreate(); err != nil {
		return err
	}

	return key.Map().Update(key.ToNetwork(), value.ToNetwork())
}

func deleteRevNatLocked(key RevNatKey) error {
	return key.Map().Delete(key.ToNetwork())
}

func (*LBBPFMap) UpdateSourceRanges(revNATID uint16, prevSourceRanges []*cidr.CIDR,
	sourceRanges []*cidr.CIDR, ipv6 bool) error {

	m := SourceRange4Map
	if ipv6 {
		m = SourceRange6Map
	}

	srcRangeMap := map[string]*cidr.CIDR{}
	for _, cidr := range sourceRanges {
		srcRangeMap[cidr.String()] = cidr
	}

	for _, prevCIDR := range prevSourceRanges {
		if _, found := srcRangeMap[prevCIDR.String()]; !found {
			if err := m.Delete(srcRangeKey(prevCIDR, revNATID, ipv6)); err != nil {
				return err
			}
		} else {
			delete(srcRangeMap, prevCIDR.String())
		}
	}

	for _, cidr := range srcRangeMap {
		if err := m.Update(srcRangeKey(cidr, revNATID, ipv6), &SourceRangeValue{}); err != nil {
			return err
		}
	}

	return nil
}

// DumpServiceMaps dumps the services from the BPF maps.
func (*LBBPFMap) DumpServiceMaps() ([]*loadbalancer.SVC, []error) {
	newSVCMap := svcMap{}
	errors := []error{}
	flagsCache := map[string]loadbalancer.ServiceFlags{}
	backendValueMap := map[loadbalancer.BackendID]BackendValue{}

	parseBackendEntries := func(key bpf.MapKey, value bpf.MapValue) {
		backendKey := key.(BackendKey)
		backendValue := value.DeepCopyMapValue().(BackendValue).ToHost()
		backendValueMap[backendKey.GetID()] = backendValue
	}

	parseSVCEntries := func(key bpf.MapKey, value bpf.MapValue) {
		svcKey := key.DeepCopyMapKey().(ServiceKey).ToHost()
		svcValue := value.DeepCopyMapValue().(ServiceValue).ToHost()

		fe := svcFrontend(svcKey, svcValue)

		// Create master entry in case there are no backends.
		if svcKey.GetBackendSlot() == 0 {
			// Build a cache of flags stored in the value of the master key to
			// map it later.
			// FIXME proto is being ignored everywhere in the datapath.
			addrStr := svcKey.GetAddress().String()
			portStr := strconv.Itoa(int(svcKey.GetPort()))
			flagsCache[net.JoinHostPort(addrStr, portStr)] = loadbalancer.ServiceFlags(svcValue.GetFlags())

			newSVCMap.addFE(fe)
			return
		}

		backendID := svcValue.GetBackendID()
		backendValue, found := backendValueMap[backendID]
		if !found {
			errors = append(errors, fmt.Errorf("backend %d not found", backendID))
			return
		}

		be := svcBackend(backendID, backendValue)
		newSVCMap.addFEnBE(fe, be, svcKey.GetBackendSlot())
	}

	if option.Config.EnableIPv4 {
		// TODO(brb) optimization: instead of dumping the backend map, we can
		// pass its content to the function.
		err := Backend4Map.DumpWithCallback(parseBackendEntries)
		if err != nil {
			errors = append(errors, err)
		}
		err = Service4MapV2.DumpWithCallback(parseSVCEntries)
		if err != nil {
			errors = append(errors, err)
		}
	}

	if option.Config.EnableIPv6 {
		// TODO(brb) same ^^ optimization applies here as well.
		err := Backend6Map.DumpWithCallback(parseBackendEntries)
		if err != nil {
			errors = append(errors, err)
		}
		err = Service6MapV2.DumpWithCallback(parseSVCEntries)
		if err != nil {
			errors = append(errors, err)
		}
	}

	newSVCList := make([]*loadbalancer.SVC, 0, len(newSVCMap))
	for hash := range newSVCMap {
		svc := newSVCMap[hash]
		addrStr := svc.Frontend.IP.String()
		portStr := strconv.Itoa(int(svc.Frontend.Port))
		host := net.JoinHostPort(addrStr, portStr)
		svc.Type = flagsCache[host].SVCType()
		svc.TrafficPolicy = flagsCache[host].SVCTrafficPolicy()
		newSVCList = append(newSVCList, &svc)
	}

	return newSVCList, errors
}

// DumpBackendMaps dumps the backend entries from the BPF maps.
func (*LBBPFMap) DumpBackendMaps() ([]*loadbalancer.Backend, error) {
	backendValueMap := map[loadbalancer.BackendID]BackendValue{}
	lbBackends := []*loadbalancer.Backend{}

	parseBackendEntries := func(key bpf.MapKey, value bpf.MapValue) {
		// No need to deep copy the key because we are using the ID which
		// is a value.
		backendKey := key.(BackendKey)
		backendValue := value.DeepCopyMapValue().(BackendValue).ToHost()
		backendValueMap[backendKey.GetID()] = backendValue
	}

	if option.Config.EnableIPv4 {
		err := Backend4Map.DumpWithCallback(parseBackendEntries)
		if err != nil {
			return nil, fmt.Errorf("Unable to dump lb4 backends map: %s", err)
		}
	}

	if option.Config.EnableIPv6 {
		err := Backend6Map.DumpWithCallback(parseBackendEntries)
		if err != nil {
			return nil, fmt.Errorf("Unable to dump lb6 backends map: %s", err)
		}
	}

	for backendID, backendVal := range backendValueMap {
		ip := backendVal.GetAddress()
		port := backendVal.GetPort()
		proto := loadbalancer.NewL4TypeFromNumber(backendVal.GetProtocol())
		lbBackend := loadbalancer.NewBackend(backendID, proto, ip, port)
		lbBackends = append(lbBackends, lbBackend)
	}

	return lbBackends, nil
}

// IsMaglevLookupTableRecreated returns true if the maglev lookup BPF map
// was recreated due to the changed M param.
func (*LBBPFMap) IsMaglevLookupTableRecreated(ipv6 bool) bool {
	if ipv6 {
		return maglevRecreatedIPv6
	}
	return maglevRecreatedIPv4
}

func updateMasterService(fe ServiceKey, nbackends int, revNATID int, svcType loadbalancer.SVCType,
	svcLocal bool, sessionAffinity bool, sessionAffinityTimeoutSec uint32,
	checkSourceRange bool) error {

	fe.SetBackendSlot(0)
	zeroValue := fe.NewValue().(ServiceValue)
	zeroValue.SetCount(nbackends)
	zeroValue.SetRevNat(revNATID)
	flag := loadbalancer.NewSvcFlag(&loadbalancer.SvcFlagParam{
		SvcType:          svcType,
		SvcLocal:         svcLocal,
		SessionAffinity:  sessionAffinity,
		IsRoutable:       !fe.IsSurrogate(),
		CheckSourceRange: checkSourceRange,
	})
	zeroValue.SetFlags(flag.UInt16())
	if sessionAffinity {
		zeroValue.SetSessionAffinityTimeoutSec(sessionAffinityTimeoutSec)
	}

	return updateServiceEndpoint(fe, zeroValue)
}

func deleteServiceLocked(key ServiceKey) error {
	return key.Map().Delete(key.ToNetwork())
}

func updateBackend(backend Backend) error {
	if _, err := backend.Map().OpenOrCreate(); err != nil {
		return err
	}
	return backend.Map().Update(backend.GetKey(), backend.GetValue().ToNetwork())
}

func deleteBackendLocked(key BackendKey) error {
	return key.Map().Delete(key)
}

func updateServiceEndpoint(key ServiceKey, value ServiceValue) error {
	log.WithFields(logrus.Fields{
		logfields.ServiceKey:   key,
		logfields.ServiceValue: value,
		logfields.BackendSlot:  key.GetBackendSlot(),
	}).Debug("Upserting service entry")

	if key.GetBackendSlot() != 0 && value.RevNatKey().GetKey() == 0 {
		return fmt.Errorf("invalid RevNat ID (0) in the Service Value")
	}
	if _, err := key.Map().OpenOrCreate(); err != nil {
		return err
	}

	return key.Map().Update(key.ToNetwork(), value.ToNetwork())
}

type svcMap map[string]loadbalancer.SVC

// addFE adds the give 'fe' to the svcMap without any backends. If it does not
// yet exist, an entry is created. Otherwise, the existing entry is left
// unchanged.
func (svcs svcMap) addFE(fe *loadbalancer.L3n4AddrID) *loadbalancer.SVC {
	hash := fe.Hash()
	lbsvc, ok := svcs[hash]
	if !ok {
		lbsvc = loadbalancer.SVC{Frontend: *fe}
		svcs[hash] = lbsvc
	}
	return &lbsvc
}

// addFEnBE adds the given 'fe' and 'be' to the svcMap. If 'fe' exists and beIndex is 0,
// the new 'be' will be appended to the list of existing backends. If beIndex is bigger
// than the size of existing backends slice, it will be created a new array with size of
// beIndex and the new 'be' will be inserted on index beIndex-1 of that new array. All
// remaining be elements will be kept on the same index and, in case the new array is
// larger than the number of backends, some elements will be empty.
func (svcs svcMap) addFEnBE(fe *loadbalancer.L3n4AddrID, be *loadbalancer.Backend, beIndex int) *loadbalancer.SVC {
	hash := fe.Hash()
	lbsvc, ok := svcs[hash]
	if !ok {
		var bes []loadbalancer.Backend
		if beIndex == 0 {
			bes = make([]loadbalancer.Backend, 1)
			bes[0] = *be
		} else {
			bes = make([]loadbalancer.Backend, beIndex)
			bes[beIndex-1] = *be
		}
		lbsvc = loadbalancer.SVC{
			Frontend: *fe,
			Backends: bes,
		}
	} else {
		var bes []loadbalancer.Backend
		if len(lbsvc.Backends) < beIndex {
			bes = make([]loadbalancer.Backend, beIndex)
			copy(bes, lbsvc.Backends)
			lbsvc.Backends = bes
		}
		if beIndex == 0 {
			lbsvc.Backends = append(lbsvc.Backends, *be)
		} else {
			lbsvc.Backends[beIndex-1] = *be
		}
	}

	svcs[hash] = lbsvc
	return &lbsvc
}

// Init updates the map info defaults for sock rev nat {4,6} and LB maps and
// then initializes all LB-related maps.
func Init(params InitParams) {
	if params.MaxSockRevNatMapEntries != 0 {
		MaxSockRevNat4MapEntries = params.MaxSockRevNatMapEntries
		MaxSockRevNat6MapEntries = params.MaxSockRevNatMapEntries
	}

	if params.MaxEntries != 0 {
		MaxEntries = params.MaxEntries
	}

	initSVC(params)
	initAffinity(params)
	initSourceRange(params)
}

// InitParams represents the parameters to be passed to Init().
type InitParams struct {
	IPv4, IPv6 bool

	MaxSockRevNatMapEntries, MaxEntries int
}
