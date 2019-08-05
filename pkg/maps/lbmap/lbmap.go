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

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/u8proto"

	"github.com/sirupsen/logrus"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "map-lb")

	// mutex protects access to the BPF map to guarantee atomicity if a
	// transaction must be split across multiple map access operations.
	mutex lock.RWMutex
)

const (
	// Maximum number of entries in each hashtable
	MaxEntries   = 65536
	maxFrontEnds = 256
	// MaxSeq is used by daemon for generating bpf define LB_RR_MAX_SEQ.
	MaxSeq = 31
)

var (
	// cache contains *all* services of both IPv4 and IPv6 based maps
	// combined
	cache = newLBMapCache()
)

func updateRevNatLocked(key RevNatKey, value RevNatValue) error {
	log.WithFields(logrus.Fields{
		logfields.BPFMapKey:   key,
		logfields.BPFMapValue: value,
	}).Debug("adding revNat to lbmap")

	if key.GetKey() == 0 {
		return fmt.Errorf("invalid RevNat ID (0)")
	}
	if _, err := key.Map().OpenOrCreate(); err != nil {
		return err
	}

	return key.Map().Update(key.ToNetwork(), value.ToNetwork())
}

func UpdateRevNat(key RevNatKey, value RevNatValue) error {
	mutex.Lock()
	defer mutex.Unlock()

	return updateRevNatLocked(key, value)
}

func deleteRevNatLocked(key RevNatKey) error {
	log.WithField(logfields.BPFMapKey, key).Debug("deleting RevNatKey")

	return key.Map().Delete(key.ToNetwork())
}

func DeleteRevNat(key RevNatKey) error {
	mutex.Lock()
	defer mutex.Unlock()

	return deleteRevNatLocked(key)
}

// gcd computes the gcd of two numbers.
func gcd(x, y uint16) uint16 {
	for y != 0 {
		x, y = y, x%y
	}
	return x
}

// generateWrrSeq generates a wrr sequence based on provided weights.
func generateWrrSeq(weights []uint16) (*RRSeqValue, error) {
	svcRRSeq := RRSeqValue{}

	n := len(weights)
	if n < 2 {
		return nil, fmt.Errorf("needs at least 2 weights")
	}

	g := uint16(0)
	for i := 0; i < n; i++ {
		if weights[i] != 0 {
			g = gcd(g, weights[i])
		}
	}

	// This means all the weights are 0.
	if g == 0 {
		return nil, fmt.Errorf("all specified weights are 0")
	}

	sum := uint16(0)
	for i := range weights {
		// Normalize the weights.
		weights[i] = weights[i] / g
		sum += weights[i]
	}

	// Check if Generated seq fits in our array.
	if int(sum) > len(svcRRSeq.Idx) {
		return nil, fmt.Errorf("sum of normalized weights exceeds %d", len(svcRRSeq.Idx))
	}

	// Generate the Sequence.
	i := uint16(0)
	k := uint16(0)
	for {
		j := uint16(0)
		for j < weights[k] {
			svcRRSeq.Idx[i] = k
			i++
			j++
		}
		if i >= sum {
			break
		}
		k++
	}
	svcRRSeq.Count = sum
	return &svcRRSeq, nil
}

// UpdateService adds or updates the given service in the bpf maps.
func UpdateService(fe ServiceKey, backends []ServiceValue,
	addRevNAT bool, revNATID int,
	acquireBackendID func(loadbalancer.L3n4Addr) (loadbalancer.BackendID, error),
	releaseBackendID func(loadbalancer.BackendID)) error {

	scopedLog := log.WithFields(logrus.Fields{
		"frontend": fe,
		"backends": backends,
	})

	mutex.Lock()
	defer mutex.Unlock()

	var (
		weights         []uint16
		nNonZeroWeights uint16
	)

	// Find out which backends are new (i.e. the ones which do not exist yet and
	// will be created in this function) and acquire IDs for them
	newBackendIDs, err := acquireNewBackendIDs(backends, acquireBackendID)
	if err != nil {
		return err
	}

	// Store mapping of backend addr ID => backend ID in the cache
	cache.addBackendIDs(newBackendIDs)

	// Prepare the service cache for the updates
	svc, addedBackends, removedBackendIDs, err := cache.prepareUpdate(fe, backends)
	if err != nil {
		return err
	}

	// FIXME(brb) Uncomment the following code after we have enabled weights
	// in the BPF datapath code.
	//for _, be := range besValues {
	//	weights = append(weights, be.GetWeight())
	//	if be.GetWeight() != 0 {
	//		nNonZeroWeights++
	//	}
	//}

	besValuesV2 := svc.getBackendsV2()

	scopedLog.Debug("Updating BPF representation of service")

	// Add the new backends to the BPF maps
	if err := updateBackendsLocked(addedBackends); err != nil {
		return err
	}

	// Update the v2 service BPF maps
	if err := updateServiceV2Locked(fe, besValuesV2, svc, addRevNAT, revNATID, weights, nNonZeroWeights); err != nil {
		return err
	}

	// Delete no longer needed backends
	if err := removeBackendsLocked(removedBackendIDs, releaseBackendID); err != nil {
		return err
	}

	return nil
}

func acquireNewBackendIDs(backends []ServiceValue,
	acquireBackendID func(loadbalancer.L3n4Addr) (loadbalancer.BackendID, error)) (
	map[BackendAddrID]BackendKey, error) {

	newBackendsByAddrID := serviceValueMap{}
	for _, b := range backends {
		newBackendsByAddrID[b.BackendAddrID()] = b
	}
	newBackendsByAddrID = cache.filterNewBackends(newBackendsByAddrID)
	newBackendIDs := map[BackendAddrID]BackendKey{}

	for addrID, value := range newBackendsByAddrID {
		addr := *serviceValue2L3n4Addr(newBackendsByAddrID[addrID])
		backendID, err := acquireBackendID(addr)
		if err != nil {
			return nil, fmt.Errorf("Unable to acquire backend ID for %s: %s", addrID, err)
		}
		if value.IsIPv6() {
			newBackendIDs[addrID] = NewBackend6Key(backendID)
		} else {
			newBackendIDs[addrID] = NewBackend4Key(backendID)
		}
		log.WithFields(logrus.Fields{
			logfields.BackendName: addrID,
			logfields.BackendID:   backendID,
		}).Debug("Acquired backend ID")
	}
	return newBackendIDs, nil
}

func updateBackendsLocked(addedBackends map[loadbalancer.BackendID]ServiceValue) error {
	var err error

	// Create new backends
	for backendID, svcVal := range addedBackends {
		var b Backend

		if svcVal.IsIPv6() {
			svc6Val := svcVal.(*Service6Value)
			b, err = NewBackend6(backendID, svc6Val.Address.IP(), svc6Val.Port, u8proto.ANY)
		} else {
			svc4Val := svcVal.(*Service4Value)
			b, err = NewBackend4(backendID, svc4Val.Address.IP(), svc4Val.Port, u8proto.ANY)
		}
		if err != nil {
			return err
		}
		if err := updateBackend(b); err != nil {
			return err
		}
	}
	return nil

}

func updateServiceV2Locked(fe ServiceKey, backends serviceValueMap,
	svc *bpfService,
	addRevNAT bool, revNATID int,
	weights []uint16, nNonZeroWeights uint16) error {

	var (
		existingCount int
		svcKeyV2      ServiceKeyV2
	)

	if fe.IsIPv6() {
		svc6Key := fe.(*Service6Key)
		svcKeyV2 = NewService6KeyV2(svc6Key.Address.IP(), svc6Key.Port, u8proto.ANY, 0)
	} else {
		svc4Key := fe.(*Service4Key)
		svcKeyV2 = NewService4KeyV2(svc4Key.Address.IP(), svc4Key.Port, u8proto.ANY, 0)
	}

	svcValV2, err := lookupServiceV2(svcKeyV2)
	if err == nil {
		existingCount = svcValV2.GetCount()
	}

	svcValV2 = svcKeyV2.NewValue().(ServiceValueV2)
	slot := 1
	for addrID, svcVal := range backends {
		backendKey := cache.getBackendKey(addrID)
		svcValV2.SetBackendID(backendKey.GetID())
		svcValV2.SetRevNat(revNATID)
		svcValV2.SetWeight(svcVal.GetWeight())
		svcKeyV2.SetSlave(slot)
		if err := updateServiceEndpointV2(svcKeyV2, svcValV2); err != nil {
			return fmt.Errorf("Unable to update service %+v with the value %+v: %s",
				svcKeyV2, svcValV2, err)
		}
		log.WithFields(logrus.Fields{
			logfields.ServiceKey:   svcKeyV2,
			logfields.ServiceValue: svcValV2,
			logfields.SlaveSlot:    slot,
		}).Debug("Upserted service entry")
		slot++
	}

	if addRevNAT {
		zeroValue := fe.NewValue().(ServiceValue)
		zeroValue.SetRevNat(revNATID)
		revNATKey := zeroValue.RevNatKey()
		revNATValue := fe.RevNatValue()

		if err := updateRevNatLocked(revNATKey, revNATValue); err != nil {
			return fmt.Errorf("unable to update reverse NAT %+v with value %+v, %s", revNATKey, revNATValue, err)
		}
		defer func() {
			if err != nil {
				deleteRevNatLocked(revNATKey)
			}
		}()
	}

	err = updateMasterServiceV2(svcKeyV2, len(svc.backendsV2), nNonZeroWeights, revNATID)
	if err != nil {
		return fmt.Errorf("unable to update service %+v: %s", svcKeyV2, err)
	}

	err = updateWrrSeqV2(svcKeyV2, weights)
	if err != nil {
		return fmt.Errorf("unable to update service weights for %s with value %+v: %s", svcKeyV2.String(), weights, err)
	}

	for i := slot; i <= existingCount; i++ {
		svcKeyV2.SetSlave(i)
		if err := deleteServiceLockedV2(svcKeyV2); err != nil {
			return fmt.Errorf("unable to delete service %+v: %s", svcKeyV2, err)
		}
		log.WithFields(logrus.Fields{
			logfields.SlaveSlot:  i,
			logfields.ServiceKey: svcKeyV2,
		}).Debug("Deleted service entry")
	}

	return nil
}

func removeBackendsLocked(removedBackendIDs []BackendKey,
	releaseBackendID func(loadbalancer.BackendID)) error {

	for _, backendKey := range removedBackendIDs {
		if err := deleteBackendLocked(backendKey); err != nil {
			return fmt.Errorf("Unable to delete backend with ID %d: %s", backendKey, err)
		}
		releaseBackendID(backendKey.GetID())
		log.WithField(logfields.BackendID, backendKey).Debug("Deleted backend")
	}

	return nil
}

// DeleteRevNATBPF deletes the revNAT entry from its corresponding BPF map
// (IPv4 or IPv6) with ID id. Returns an error if the deletion operation failed.
func DeleteRevNATBPF(id loadbalancer.ServiceID, isIPv6 bool) error {
	var revNATK RevNatKey
	if isIPv6 {
		revNATK = NewRevNat6Key(uint16(id))
	} else {
		revNATK = NewRevNat4Key(uint16(id))
	}
	err := DeleteRevNat(revNATK)
	return err
}

// DumpServiceMapsToUserspaceV2 dumps the services in the same way as
// DumpServiceMapsToUserspace.
func DumpServiceMapsToUserspaceV2() (loadbalancer.SVCMap, []*loadbalancer.LBSVC, []error) {
	mutex.RLock()
	defer mutex.RUnlock()

	newSVCMap := loadbalancer.SVCMap{}
	newSVCList := []*loadbalancer.LBSVC{}
	errors := []error{}
	idCache := map[string]loadbalancer.ServiceID{}
	backendValueMap := map[loadbalancer.BackendID]BackendValue{}

	parseBackendEntries := func(key bpf.MapKey, value bpf.MapValue) {
		backendKey := key.(BackendKey)
		backendValue := value.DeepCopyMapValue().(BackendValue)
		backendValueMap[backendKey.GetID()] = backendValue
	}

	parseSVCEntries := func(key bpf.MapKey, value bpf.MapValue) {
		svcKey := key.DeepCopyMapKey().(ServiceKeyV2)
		svcValue := value.DeepCopyMapValue().(ServiceValueV2)

		// Skip master service
		if svcKey.GetSlave() == 0 {
			return
		}

		backendID := svcValue.GetBackendID()

		scopedLog := log.WithFields(logrus.Fields{
			logfields.BPFMapKey:   svcKey,
			logfields.BPFMapValue: svcValue,
		})

		backendValue, found := backendValueMap[backendID]
		if !found {
			errors = append(errors, fmt.Errorf("backend %d not found", backendID))
			return
		}

		scopedLog.Debug("parsing service mapping v2")
		fe, be := serviceKeynValuenBackendValue2FEnBE(svcKey, svcValue, backendID, backendValue)

		// Build a cache to map frontend IP to service ID. The master
		// service key does not have the service ID set so the cache
		// needs to be built based on backend key entries.
		if k := svcValue.RevNatKey().GetKey(); k != uint16(0) {
			idCache[fe.String()] = loadbalancer.ServiceID(k)
		}

		svc := newSVCMap.AddFEnBE(fe, be, svcKey.GetSlave())
		newSVCList = append(newSVCList, svc)
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

	// serviceKeynValue2FEnBE() cannot fill in the service ID reliably as
	// not all BPF map entries contain the service ID. Do a pass over all
	// parsed entries and fill in the service ID
	for i := range newSVCList {
		newSVCList[i].FE.ID = loadbalancer.ID(idCache[newSVCList[i].FE.String()])
	}

	// Do the same for the svcMap
	for key, svc := range newSVCMap {
		svc.FE.ID = loadbalancer.ID(idCache[svc.FE.String()])
		newSVCMap[key] = svc
	}

	return newSVCMap, newSVCList, errors
}

// DumpBackendMapsToUserspace dumps the backend entries from the BPF maps.
func DumpBackendMapsToUserspace() (map[BackendAddrID]*loadbalancer.LBBackEnd, error) {
	mutex.RLock()
	defer mutex.RUnlock()

	backendValueMap := map[loadbalancer.BackendID]BackendValue{}
	lbBackends := map[BackendAddrID]*loadbalancer.LBBackEnd{}

	parseBackendEntries := func(key bpf.MapKey, value bpf.MapValue) {
		// No need to deep copy the key because we are using the ID which
		// is a value.
		backendKey := key.(BackendKey)
		backendValue := value.DeepCopyMapValue().(BackendValue)
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
		weight := uint16(0) // FIXME(brb): set weight when we support it
		proto := loadbalancer.NONE
		lbBackend := loadbalancer.NewLBBackEnd(backendID, proto, ip, port, weight)
		lbBackends[backendVal.BackendAddrID()] = lbBackend
	}

	return lbBackends, nil
}

// DumpRevNATMapsToUserspace dumps the contents of both the IPv6 and IPv4
// revNAT BPF maps, and stores the contents of said dumps in a RevNATMap.
// Returns the errors that occurred while dumping the maps.
func DumpRevNATMapsToUserspace() (loadbalancer.RevNATMap, []error) {
	mutex.RLock()
	defer mutex.RUnlock()

	newRevNATMap := loadbalancer.RevNATMap{}
	errors := []error{}

	parseRevNATEntries := func(key bpf.MapKey, value bpf.MapValue) {
		revNatK := key.DeepCopyMapKey().(RevNatKey)
		revNatV := value.DeepCopyMapValue().(RevNatValue)
		scopedLog := log.WithFields(logrus.Fields{
			logfields.BPFMapKey:   revNatK,
			logfields.BPFMapValue: revNatV,
		})

		scopedLog.Debug("parsing BPF revNAT mapping")
		fe := revNatValue2L3n4AddrID(revNatK, revNatV)
		newRevNATMap[loadbalancer.ServiceID(fe.ID)] = fe.L3n4Addr
	}

	if option.Config.EnableIPv4 {
		if err := RevNat4Map.DumpWithCallback(parseRevNATEntries); err != nil {
			err = fmt.Errorf("error dumping RevNat4Map: %s", err)
			errors = append(errors, err)
		}
	}

	if option.Config.EnableIPv6 {
		if err := RevNat6Map.DumpWithCallback(parseRevNATEntries); err != nil {
			err = fmt.Errorf("error dumping RevNat6Map: %s", err)
			errors = append(errors, err)
		}
	}

	return newRevNATMap, errors
}

// RestoreService restores a single service in the cache. This is required to
// guarantee consistent backend ordering, slave slot and backend by backend
// address ID lookups.
func RestoreService(svc loadbalancer.LBSVC) error {
	mutex.Lock()
	defer mutex.Unlock()

	return cache.restoreService(svc)
}

func lookupServiceV2(key ServiceKeyV2) (ServiceValueV2, error) {
	val, err := key.Map().Lookup(key.ToNetwork())
	if err != nil {
		return nil, err
	}
	svc := val.(ServiceValueV2)

	return svc.ToNetwork(), nil
}

func updateMasterServiceV2(fe ServiceKeyV2, nbackends int, nonZeroWeights uint16, revNATID int) error {
	fe.SetSlave(0)
	zeroValue := fe.NewValue().(ServiceValueV2)
	zeroValue.SetCount(nbackends)
	zeroValue.SetWeight(nonZeroWeights)
	zeroValue.SetRevNat(revNATID)

	return updateServiceEndpointV2(fe, zeroValue)
}

// updateWrrSeq updates bpf map with the generated wrr sequence.
func updateWrrSeqV2(fe ServiceKeyV2, weights []uint16) error {
	sum := uint16(0)
	for _, v := range weights {
		sum += v
	}
	if sum == 0 {
		return nil
	}
	svcRRSeq, err := generateWrrSeq(weights)
	if err != nil {
		return fmt.Errorf("unable to generate weighted round robin seq for %s with value %+v: %s", fe.String(), weights, err)
	}
	return updateServiceWeightsV2(fe, svcRRSeq)
}

// updateServiceWeightsV2 updates cilium_lb6_rr_seq_v2 or cilium_lb4_rr_seq_v2 bpf maps.
func updateServiceWeightsV2(key ServiceKeyV2, value *RRSeqValue) error {
	if _, err := key.RRMap().OpenOrCreate(); err != nil {
		return err
	}

	return key.RRMap().Update(key.ToNetwork(), value)
}

func deleteServiceLockedV2(key ServiceKeyV2) error {
	err := key.Map().Delete(key.ToNetwork())
	if err != nil {
		return err
	}
	return lookupAndDeleteServiceWeightsV2(key)
}

// lookupAndDeleteServiceWeightsV2 deletes entry from cilium_lb6_rr_seq or cilium_lb4_rr_seq
func lookupAndDeleteServiceWeightsV2(key ServiceKeyV2) error {
	_, err := key.RRMap().Lookup(key.ToNetwork())
	if err != nil {
		// Ignore if entry is not found.
		return nil
	}

	return key.RRMap().Delete(key.ToNetwork())
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

func updateServiceEndpointV2(key ServiceKeyV2, value ServiceValueV2) error {
	log.WithFields(logrus.Fields{
		logfields.ServiceKey:   key,
		logfields.ServiceValue: value,
		logfields.SlaveSlot:    key.GetSlave(),
	}).Debug("Upserting service entry")

	if key.GetSlave() != 0 && value.RevNatKey().GetKey() == 0 {
		return fmt.Errorf("invalid RevNat ID (0) in the Service Value")
	}
	if _, err := key.Map().OpenOrCreate(); err != nil {
		return err
	}

	return key.Map().Update(key.ToNetwork(), value.ToNetwork())
}

// AddBackendIDsToCache populates the given backend IDs to the lbmap local cache.
func AddBackendIDsToCache(backendIDs map[BackendAddrID]BackendKey) {
	mutex.Lock()
	defer mutex.Unlock()

	cache.addBackendIDs(backendIDs)
}

// DeleteServiceV2 deletes a service from the lbmap and deletes backends of it if
// they are not used by any other service.
//
//The given key has to be of the master service.
func DeleteServiceV2(svc loadbalancer.L3n4AddrID, releaseBackendID func(loadbalancer.BackendID)) error {
	mutex.Lock()
	defer mutex.Unlock()

	var (
		svcKey ServiceKeyV2
	)

	isIPv6 := svc.IsIPv6()

	log.WithField(logfields.ServiceName, svc).Debug("Deleting service")

	if isIPv6 {
		svcKey = NewService6KeyV2(svc.IP, svc.Port, u8proto.ANY, 0)
	} else {
		svcKey = NewService4KeyV2(svc.IP, svc.Port, u8proto.ANY, 0)
	}

	backendsToRemove, backendsCount, err := cache.removeServiceV2(svcKey)
	if err != nil {
		return err
	}

	for slot := 0; slot <= backendsCount; slot++ {
		svcKey.SetSlave(slot)
		if err := svcKey.MapDelete(); err != nil {
			return err
		}
	}

	for _, backendKey := range backendsToRemove {
		if err := deleteBackendLocked(backendKey); err != nil {
			return fmt.Errorf("Unable to delete backend with ID %d: %s", backendKey, err)
		}
		releaseBackendID(backendKey.GetID())
		log.WithField(logfields.BackendID, backendKey).Debug("Deleted backend")
	}

	return nil
}

// DeleteServiceCache deletes the service cache.
func DeleteServiceCache(svc loadbalancer.L3n4AddrID) {
	mutex.Lock()
	defer mutex.Unlock()

	var svcKey ServiceKey

	if !svc.IsIPv6() {
		svcKey = NewService4Key(svc.IP, svc.Port, 0)
	} else {
		svcKey = NewService6Key(svc.IP, svc.Port, 0)
	}

	cache.delete(svcKey)
}

func DeleteOrphanBackends(releaseBackendID func(loadbalancer.BackendID)) []error {
	mutex.Lock()
	defer mutex.Unlock()

	errors := make([]error, 0)
	toRemove := cache.removeBackendsWithRefCountZero()

	for _, key := range toRemove {
		log.WithField(logfields.BackendID, key).Debug("Removing orphan backend")
		if err := deleteBackendLocked(key); err != nil {
			errors = append(errors,
				fmt.Errorf("Unable to remove backend from the BPF map %d: %s", key, err))
		}
		releaseBackendID(key.GetID())
	}

	return errors
}

// RemoveDeprecatedMaps removes the maps for legacy services, left over from
// previous installations.
//
// Safe to remove in Cilium 1.7.
func RemoveDeprecatedMaps() error {
	if err := Service6Map.UnpinIfExists(); err != nil {
		return err
	}
	if err := RRSeq6Map.UnpinIfExists(); err != nil {
		return err
	}
	if err := Service4Map.UnpinIfExists(); err != nil {
		return err
	}
	if err := RRSeq4Map.UnpinIfExists(); err != nil {
		return err
	}
	return nil
}
