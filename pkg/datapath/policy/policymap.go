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

package policy

import (
	"fmt"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/policy"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "datapath-policymap")
)

type PolicyMapImplementer struct {
	policymap *policymap.PolicyMap
	id        uint16
	isInit    bool
}

func (p *PolicyMapImplementer) IsInit() bool {
	return p.isInit
}

func (p *PolicyMapImplementer) GetFd() int {
	return p.policymap.GetFd()
}

func (p *PolicyMapImplementer) DeleteKey(key policy.Key) error {
	// Convert from policy.Key to policymap.Key
	policyKeyToPolicyMapKey := policymap.PolicyKey{
		Identity:         key.Identity,
		DestPort:         key.DestPort,
		Nexthdr:          key.Nexthdr,
		TrafficDirection: key.TrafficDirection,
	}
	return p.policymap.DeleteKey(policyKeyToPolicyMapKey)
}

func (p *PolicyMapImplementer) AllowKey(key policy.Key, entry policy.MapStateEntry) error {
	// Convert from policy.Key to policymap.Key
	policyKeyToPolicyMapKey := policymap.PolicyKey{
		Identity:         key.Identity,
		DestPort:         key.DestPort,
		Nexthdr:          key.Nexthdr,
		TrafficDirection: key.TrafficDirection,
	}

	return p.policymap.AllowKey(policyKeyToPolicyMapKey, entry.ProxyPort)
}

func (p *PolicyMapImplementer) Close() error {
	if p.policymap != nil {
		return p.policymap.Close()
	}
	return nil
}

func (p *PolicyMapImplementer) DeleteAll() error {
	return p.policymap.DeleteAll()
}

func (p *PolicyMapImplementer) Path() string {
	return bpf.LocalMapPath(policymap.MapName, p.id)
}

func (p *PolicyMapImplementer) AddID(id uint16) {
	p.id = id
}

func (p *PolicyMapImplementer) OpenOrCreate(id uint16) (bool, error) {
	p.isInit = true
	p.id = id
	pmap, isNewMap, err := policymap.OpenOrCreate(bpf.LocalMapPath(policymap.MapName, id))
	p.policymap = pmap
	return isNewMap, err
}
func (p *PolicyMapImplementer) String() string {
	return p.policymap.String()
}

func (p *PolicyMapImplementer) SyncDelta(realized policy.MapState, desired policy.MapState) error {
	// Nothing to do if the desired policy is already fully realized.
	/*if e.realizedPolicy == e.desiredPolicy {
		return nil
	}*/

	errors := []error{}

	// Delete policy keys present in the realized state, but not present in the desired state
	for keyToDelete := range realized {
		// If key that is in realized state is not in desired state, just remove it.
		if _, ok := desired[keyToDelete]; !ok {

			// Convert from policy.Key to policymap.Key
			policyKeyToPolicyMapKey := policymap.PolicyKey{
				Identity:         keyToDelete.Identity,
				DestPort:         keyToDelete.DestPort,
				Nexthdr:          keyToDelete.Nexthdr,
				TrafficDirection: keyToDelete.TrafficDirection,
			}

			err := p.DeleteKey(keyToDelete)
			if err != nil {
				log.WithError(err).WithField("map", p.policymap.String()).Errorf("Failed to delete PolicyMap key %s", policyKeyToPolicyMapKey.String())
				errors = append(errors, err)
			} else {
				// Operation was successful, remove from realized state.
				delete(realized, keyToDelete)
			}
		}
	}

	err := p.addPolicyMapDelta(realized, desired)

	if len(errors) > 0 {
		return fmt.Errorf("deleting stale PolicyMap state failed: %s", errors)
	}

	return err
}

// syncPolicyMap attempts to synchronize the PolicyMap for this endpoint to
// contain the set of PolicyKeys represented by the endpoint's desiredMapState.
// It checks the current contents of the endpoint's PolicyMap and deletes any
// PolicyKeys that are not present in the endpoint's desiredMapState. It then
// adds any keys that are not present in the map. When a key from desiredMapState
// is inserted successfully to the endpoint's BPF PolicyMap, it is added to the
// endpoint's realizedMapState field. Returns an error if the endpoint's BPF
// PolicyMap is unable to be dumped, or any update operation to the map fails.
// Must be called with e.Mutex locked.
func (p *PolicyMapImplementer) SyncFull(realized policy.MapState, desired policy.MapState) error {

	if realized == nil {
		realized = make(policy.MapState)
	}

	if desired == nil {
		desired = make(policy.MapState)
	}

	if p.policymap == nil {
		return fmt.Errorf("not syncing PolicyMap state for endpoint because PolicyMap is nil")
	}

	currentMapContents, err := p.policymap.DumpToSlice()

	// If map is unable to be dumped, attempt to close map and open it again.
	// See GH-4229.
	if err != nil {
		log.WithError(err).WithField("map", p.policymap.String()).Error("unable to dump PolicyMap when trying to sync desired and realized PolicyMap state")

		// Close to avoid leaking of file descriptors, but still continue in case
		// Close() does not succeed, because otherwise the map will never be
		// opened again unless the agent is restarted.
		err := p.policymap.Close()
		if err != nil {
			log.WithError(err).WithField("map", p.policymap.String()).Error("unable to close PolicyMap which was not able to be dumped")
		}

		p.policymap, _, err = policymap.OpenOrCreate(bpf.LocalMapPath(policymap.MapName, p.id))
		if err != nil {
			return fmt.Errorf("unable to open PolicyMap for endpoint: %s", err)
		}

		// Try to dump again, fail if error occurs.
		currentMapContents, err = p.policymap.DumpToSlice()
		if err != nil {
			return err
		}
	}

	errors := []error{}

	for _, entry := range currentMapContents {
		// Convert key to host-byte order for lookup in the desiredMapState.
		keyHostOrder := entry.Key.ToHost()

		// Convert from policymap.Key to policy.Key
		policyMapKeyToPolicyKey := policy.Key{
			Identity:         keyHostOrder.Identity,
			DestPort:         keyHostOrder.DestPort,
			Nexthdr:          keyHostOrder.Nexthdr,
			TrafficDirection: keyHostOrder.TrafficDirection,
		}

		// If key that is in policy map is not in desired state, just remove it.
		if _, ok := desired[policyMapKeyToPolicyKey]; !ok {
			// Can pass key with host byte-order fields, as it will get
			// converted to network byte-order.
			err := p.policymap.DeleteKey(keyHostOrder)
			if err != nil {
				log.WithError(err).WithField("map", p.policymap.String()).Errorf("Failed to delete PolicyMap key %s", entry.Key.String())
				errors = append(errors, err)
			} else {
				// Operation was successful, remove from realized state.
				delete(realized, policyMapKeyToPolicyKey)
			}
		}
	}

	err = p.addPolicyMapDelta(realized, desired)

	if len(errors) > 0 {
		return fmt.Errorf("synchronizing desired PolicyMap state failed: %s", errors)
	}

	return err
}

// addPolicyMapDelta adds new or updates existing bpf policy map state based
// on the difference between the realized and desired policy state without
// dumping the bpf policy map.
func (p *PolicyMapImplementer) addPolicyMapDelta(realized, desired policy.MapState) error {
	// Nothing to do if the desired policy is already fully realized.
	/*if realizedPolicy == desiredPolicy {
		return nil
	}*/

	errors := []error{}

	for keyToAdd, entry := range desired {
		if oldEntry, ok := realized[keyToAdd]; !ok || oldEntry != entry {

			// Convert from policy.Key to policymap.Key
			policyKeyToPolicyMapKey := policymap.PolicyKey{
				Identity:         keyToAdd.Identity,
				DestPort:         keyToAdd.DestPort,
				Nexthdr:          keyToAdd.Nexthdr,
				TrafficDirection: keyToAdd.TrafficDirection,
			}

			err := p.AllowKey(keyToAdd, entry)
			if err != nil {
				log.WithError(err).WithField("map", p.policymap.String()).Errorf("Failed to add PolicyMap key %s %d", policyKeyToPolicyMapKey.String(), entry.ProxyPort)
				errors = append(errors, err)
			} else {
				// Operation was successful, add to realized state.
				// The realized policy (including the policy map state) will
				// be replaced with the desired state, but only if everything
				// is successful. If something fails, this ensures that the
				// realized state reflects the state of the bpf map.
				realized[keyToAdd] = entry
			}
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("updating desired PolicyMap state failed: %s", errors)
	}

	return nil
}

func (p *PolicyMapImplementer) RemoveGlobalMapping(id uint32) error {
	return policymap.RemoveGlobalMapping(id)
}
