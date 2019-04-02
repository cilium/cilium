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

func updateService(key ServiceKey, value ServiceValue) error {
	log.WithFields(logrus.Fields{
		"frontend": key,
		"backend":  value,
	}).Debug("adding frontend for backend to BPF maps")
	if key.GetBackend() != 0 && value.RevNatKey().GetKey() == 0 {
		return fmt.Errorf("invalid RevNat ID (0) in the Service Value")
	}
	if _, err := key.Map().OpenOrCreate(); err != nil {
		return err
	}

	return key.Map().Update(key.ToNetwork(), value.ToNetwork())
}

// DeleteService deletes a service from the lbmap. key should be the master (i.e., with backend set to zero).
func DeleteService(key ServiceKey) error {
	mutex.Lock()
	defer mutex.Unlock()

	return deleteServiceLocked(key)
}

func deleteServiceLocked(key ServiceKey) error {
	err := key.Map().Delete(key.ToNetwork())
	if err != nil {
		return err
	}
	err = lookupAndDeleteServiceWeights(key)
	if err == nil {
		cache.delete(key)
	}
	return err
}

func lookupService(key ServiceKey) (ServiceValue, error) {
	var svc ServiceValue

	val, err := key.Map().Lookup(key.ToNetwork())
	if err != nil {
		return nil, err
	}

	if key.IsIPv6() {
		svc = val.(*Service6Value)
	} else {
		svc = val.(*Service4Value)
	}

	return svc.ToNetwork(), nil
}

// updateServiceWeights updates cilium_lb6_rr_seq or cilium_lb4_rr_seq bpf maps.
func updateServiceWeights(key ServiceKey, value *RRSeqValue) error {
	if _, err := key.RRMap().OpenOrCreate(); err != nil {
		return err
	}

	return key.RRMap().Update(key.ToNetwork(), value)
}

// lookupAndDeleteServiceWeights deletes entry from cilium_lb6_rr_seq or cilium_lb4_rr_seq
func lookupAndDeleteServiceWeights(key ServiceKey) error {
	_, err := key.RRMap().Lookup(key.ToNetwork())
	if err != nil {
		// Ignore if entry is not found.
		return nil
	}

	return key.RRMap().Delete(key.ToNetwork())
}

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

// updateWrrSeq updates bpf map with the generated wrr sequence.
func updateWrrSeq(fe ServiceKey, weights []uint16) error {
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
	return updateServiceWeights(fe, svcRRSeq)
}

func updateMasterService(fe ServiceKey, nbackends int, nonZeroWeights uint16) error {
	fe.SetBackend(0)
	zeroValue := fe.NewValue().(ServiceValue)
	zeroValue.SetCount(nbackends)
	zeroValue.SetWeight(nonZeroWeights)

	return updateService(fe, zeroValue)
}

// UpdateService adds or updates the given service in the bpf maps
func UpdateService(fe ServiceKey, backends []ServiceValue, addRevNAT bool, revNATID int) error {
	var (
		weights         []uint16
		nNonZeroWeights uint16
		existingCount   int
	)

	svc := cache.prepareUpdate(fe, backends)
	besValues := svc.getBackends()

	log.WithFields(logrus.Fields{
		"frontend": fe,
		"backends": besValues,
	}).Debugf("Updating BPF representation of service")

	for _, be := range besValues {
		weights = append(weights, be.GetWeight())
		if be.GetWeight() != 0 {
			nNonZeroWeights++
		}
	}

	mutex.Lock()
	defer mutex.Unlock()

	// Check if the service already exists, it is not failure scenario if
	// the services doesn't exist. That's simply a new service. Even if the
	// service cannot be looked up for an existing service, it is still
	// better to proceed and update the service, at the cost of a slightly
	// less atomic update.
	svcValue, err := lookupService(fe)
	if err == nil {
		existingCount = svcValue.GetCount()
	}

	for nsvc, be := range besValues {
		fe.SetBackend(nsvc + 1) // service count starts with 1
		if err := updateService(fe, be); err != nil {
			return fmt.Errorf("unable to update service %+v with the value %+v: %s", fe, be, err)
		}
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

	err = updateMasterService(fe, len(besValues), nNonZeroWeights)
	if err != nil {
		return fmt.Errorf("unable to update service %+v: %s", fe, err)
	}

	err = updateWrrSeq(fe, weights)
	if err != nil {
		return fmt.Errorf("unable to update service weights for %s with value %+v: %s", fe.String(), weights, err)
	}

	// Remove old backends that are no longer needed
	for i := len(besValues) + 1; i <= existingCount; i++ {
		fe.SetBackend(i)
		if err := deleteServiceLocked(fe); err != nil {
			return fmt.Errorf("unable to delete service %+v: %s", fe, err)
		}
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

// DumpServiceMapsToUserspace dumps the contents of both the IPv6 and IPv4
// service / loadbalancer BPF maps, and converts them to a SVCMap and slice of
// LBSVC. IPv4 maps may not be dumped depending on if skipIPv4 is enabled. If
// includeMasterBackend is true, the returned values will also include services
// which correspond to "master" backend values in the BPF maps. Returns the
// errors that occurred while dumping the maps.
func DumpServiceMapsToUserspace(includeMasterBackend bool) (loadbalancer.SVCMap, []*loadbalancer.LBSVC, []error) {

	newSVCMap := loadbalancer.SVCMap{}
	newSVCList := []*loadbalancer.LBSVC{}
	errors := []error{}
	idCache := map[string]loadbalancer.ServiceID{}

	parseSVCEntries := func(key bpf.MapKey, value bpf.MapValue) {
		svcKey := key.(ServiceKey)
		//It's the frontend service so we don't add this one
		if svcKey.GetBackend() == 0 && !includeMasterBackend {
			return
		}
		svcValue := value.(ServiceValue)

		scopedLog := log.WithFields(logrus.Fields{
			logfields.BPFMapKey:   svcKey,
			logfields.BPFMapValue: svcValue,
		})

		scopedLog.Debug("parsing service mapping")
		fe, be := serviceKeynValue2FEnBE(svcKey, svcValue)

		// Build a cache to map frontend IP to service ID. The master
		// service key does not have the service ID set so the cache
		// needs to be built based on backend key entries.
		if k := svcValue.RevNatKey().GetKey(); k != uint16(0) {
			idCache[fe.String()] = loadbalancer.ServiceID(k)
		}

		svc := newSVCMap.AddFEnBE(fe, be, svcKey.GetBackend())
		newSVCList = append(newSVCList, svc)
	}

	mutex.RLock()
	defer mutex.RUnlock()

	if option.Config.EnableIPv4 {
		err := Service4Map.DumpWithCallback(parseSVCEntries)
		if err != nil {
			errors = append(errors, err)
		}
	}

	if option.Config.EnableIPv6 {
		err := Service6Map.DumpWithCallback(parseSVCEntries)
		if err != nil {
			errors = append(errors, err)
		}
	}

	// serviceKeynValue2FEnBE() cannot fill in the service ID reliably as
	// not all BPF map entries contain the service ID. Do a pass over all
	// parsed entries and fill in the service ID
	for i := range newSVCList {
		newSVCList[i].FE.ID = idCache[newSVCList[i].FE.String()]
	}

	// Do the same for the svcMap
	for key, svc := range newSVCMap {
		svc.FE.ID = idCache[svc.FE.String()]
		newSVCMap[key] = svc
	}

	return newSVCMap, newSVCList, errors
}

// DumpRevNATMapsToUserspace dumps the contents of both the IPv6 and IPv4
// revNAT BPF maps, and stores the contents of said dumps in a RevNATMap.
// Returns the errors that occurred while dumping the maps.
func DumpRevNATMapsToUserspace() (loadbalancer.RevNATMap, []error) {

	newRevNATMap := loadbalancer.RevNATMap{}
	errors := []error{}

	parseRevNATEntries := func(key bpf.MapKey, value bpf.MapValue) {
		revNatK := key.(RevNatKey)
		revNatV := value.(RevNatValue)
		scopedLog := log.WithFields(logrus.Fields{
			logfields.BPFMapKey:   revNatK,
			logfields.BPFMapValue: revNatV,
		})

		scopedLog.Debug("parsing BPF revNAT mapping")
		fe := revNatValue2L3n4AddrID(revNatK, revNatV)
		newRevNATMap[fe.ID] = fe.L3n4Addr
	}

	mutex.RLock()
	defer mutex.RUnlock()

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
// guarantee consistent backend ordering
func RestoreService(svc loadbalancer.LBSVC) error {
	return cache.restoreService(svc)
}
