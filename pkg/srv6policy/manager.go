//  Copyright 2021 Authors of Cilium
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package srv6policy

import (
	"errors"
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/ip"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/srv6map"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/types"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "srv6policy")
)

// The srv6policy manager stores the internal data tracking the policy
// and endpoint mappings. It also hooks up all the callbacks to update
// SRv6 BPF map accordingly.
type Manager struct {
	mutex lock.Mutex

	// Stores endpoint to policy mapping
	policyEndpoints map[endpointID][]policyID
	// Stores policy configs indexed by policyID
	policyConfigs map[policyID]*Config
	// Stores endpointId to endpoint metadata mapping
	epDataStore map[endpointID]*endpointMetadata
}

func NewSRv6PolicyManager() *Manager {
	return &Manager{
		policyEndpoints: make(map[endpointID][]policyID),
		policyConfigs:   make(map[policyID]*Config),
		epDataStore:     make(map[endpointID]*endpointMetadata),
	}
}

// Event handlers

// AddSRv6Policy parses the given policy config, and updates the internal state with the config fields.
// Returns boolean indicating if policy is added and err with first encountered error if any.
func (manager *Manager) AddSRv6Policy(config Config) (bool, error) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()

	_, ok := manager.policyConfigs[config.id]
	if ok {
		log.WithField(logfields.CiliumEgressSRv6PolicyName, config.id.Name).
			Warn("CiliumEgressSRv6Policy already exists and is not re-added.")
		return false, errors.New("already exists")
	}

	manager.policyConfigs[config.id] = &config
	for _, endpoint := range manager.epDataStore {
		if config.policyConfigSelectsEndpoint(endpoint) {
			if err := manager.upsertPolicyEndpoint(&config, endpoint); err != nil {
				return false, err
			}
		}
	}

	return true, nil
}

// Deletes the internal state associated with the given policy, including SRv6 BPF map entries
func (manager *Manager) DeleteSRv6Policy(configID policyID) error {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()

	storedConfig := manager.policyConfigs[configID]
	if storedConfig == nil {
		return fmt.Errorf("policy not found")
	}
	log.WithFields(logrus.Fields{"policyID": configID}).
		Debug("Delete local egress policy.")

	for endpointId, policies := range manager.policyEndpoints {
		var newPolicyList []policyID
		// make a new list excluding policy that is to be deleted
		for _, policyId := range policies {
			if policyId == storedConfig.id {
				// found policy to endpoint mapping, need to delete egress map entry
				// identified by endpoint and config
				epData, ok := manager.epDataStore[endpointId]
				if !ok {
					return fmt.Errorf("failed to get endpoint data for %v", endpointId)
				}
				if err := manager.deleteSRv6MapEntry(storedConfig, epData); err != nil {
					return err
				}
			} else {
				newPolicyList = append(newPolicyList, policyId)
			}
		}
		if len(newPolicyList) > 0 {
			manager.policyEndpoints[endpointId] = newPolicyList
		} else {
			// epDataStore untouched here since endpoint data is unchanged
			delete(manager.policyEndpoints, endpointId)
		}
	}
	delete(manager.policyConfigs, configID)
	return nil
}

// OnUpdateEndpoint is the event handler for endpoint additions and updates.
func (manager *Manager) OnUpdateEndpoint(endpoint *k8sTypes.CiliumEndpoint) {
	var epData *endpointMetadata
	var err error

	manager.mutex.Lock()
	defer manager.mutex.Unlock()

	if len(endpoint.Networking.Addressing) == 0 {
		log.WithError(err).WithFields(logrus.Fields{
			logfields.K8sEndpointName: endpoint.Name,
			logfields.K8sNamespace:    endpoint.Namespace,
		}).Error("Failed to get valid endpoint IPs, skipping update of SRv6 policy.")
		return
	}

	if epData, err = getEndpointMetadata(endpoint); err != nil {
		log.WithError(err).WithFields(logrus.Fields{
			logfields.K8sEndpointName: endpoint.Name,
			logfields.K8sNamespace:    endpoint.Namespace,
		}).Error("Failed to get valid endpoint metadata, skipping update of SRv6 policy.")
		return
	}

	// Remove old: check if the endpoint was previously selected by any of the policies.
	if policies, ok := manager.policyEndpoints[epData.id]; ok {
		for _, policy := range policies {
			config := manager.policyConfigs[policy]
			err := manager.deleteSRv6MapEntry(config, epData)
			if err != nil {
				log.WithError(err).WithFields(logrus.Fields{
					logfields.K8sEndpointName: endpoint.Name,
					logfields.K8sNamespace:    endpoint.Namespace,
				}).Error("Error updating endpoint mapping.")
				return
			}
		}
		delete(manager.policyEndpoints, epData.id)
		delete(manager.epDataStore, epData.id)
	}

	// Upsert new: check if current policies select new endpoint. Also updates endpoint cache
	manager.epDataStore[epData.id] = epData
	for _, config := range manager.policyConfigs {
		if config.policyConfigSelectsEndpoint(epData) {
			err := manager.upsertPolicyEndpoint(config, epData)
			if err != nil {
				log.WithError(err).WithFields(logrus.Fields{
					logfields.K8sEndpointName: endpoint.Name,
					logfields.K8sNamespace:    endpoint.Namespace,
				}).Error("Error upserting pod mapping for pod.")
				return
			}
		}
	}
}

// OnDeleteEndpoint is the event handler for endpoint deletions.
func (manager *Manager) OnDeleteEndpoint(endpoint *k8sTypes.CiliumEndpoint) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()

	id := types.NamespacedName{
		Name:      endpoint.GetName(),
		Namespace: endpoint.GetNamespace(),
	}

	var epData *endpointMetadata
	var err error
	if epData, err = getEndpointMetadata(endpoint); err != nil {
		log.WithError(err).WithFields(logrus.Fields{
			logfields.K8sEndpointName: endpoint.Name,
			logfields.K8sNamespace:    endpoint.Namespace,
		}).Error("Failed to get valid endpoint metadata, abort deleting endpoint mapping.")
		return
	}

	if policies, ok := manager.policyEndpoints[id]; ok {
		for _, policy := range policies {
			config := manager.policyConfigs[policy]
			manager.deleteSRv6MapEntry(config, epData)
		}
		delete(manager.policyEndpoints, id)
	}
	delete(manager.epDataStore, id)
}

func getEndpointMetadata(endpoint *k8sTypes.CiliumEndpoint) (*endpointMetadata, error) {
	var ipv4s, ipv6s []net.IP
	id := types.NamespacedName{
		Name:      endpoint.GetName(),
		Namespace: endpoint.GetNamespace(),
	}

	if endpoint.Networking == nil {
		return nil, fmt.Errorf("endpoint has no networking metadata")
	}

	for _, pair := range endpoint.Networking.Addressing {
		if pair.IPV4 != "" {
			ipv4s = append(ipv4s, net.ParseIP(pair.IPV4).To4())
		}
		if pair.IPV6 != "" {
			ipv6s = append(ipv6s, net.ParseIP(pair.IPV6).To16())
		}
	}

	if endpoint.Identity == nil {
		return nil, fmt.Errorf("endpoint has no identity metadata")
	}

	data := &endpointMetadata{
		ipv4s:  ipv4s,
		ipv6s:  ipv6s,
		labels: labels.NewLabelsFromModel(endpoint.Identity.Labels).K8sStringMap(),
		id:     id,
	}

	return data, nil
}

// upsertPolicyEndpoint updates or insert to endpoint policy mapping for given policy config and endpoints,
// it also upserts egress map to keep in sync
func (manager *Manager) upsertPolicyEndpoint(config *Config, epData *endpointMetadata) error {
	if err := manager.updateSRv6Map(epData.ipv4s, epData.ipv6s, config); err != nil {
		return err
	}

	if endpointPolicies, ok := manager.policyEndpoints[epData.id]; ok {
		for _, polID := range endpointPolicies {
			if polID == config.id {
				log.Debug("Endpoint to policy mapping already exists.")
				return nil
			}
		}
		// Add policy to existing list
		manager.policyEndpoints[epData.id] = append(manager.policyEndpoints[epData.id], config.id)
	} else {
		// Add policy to new list
		pe := []policyID{config.id}
		manager.policyEndpoints[epData.id] = pe
	}
	return nil
}

func (manager *Manager) updateSRv6Map(ipv4s, ipv6s []net.IP, config *Config) error {
	value := &srv6map.Value{}
	copy(value.SID[:], config.sid)
	for _, dstCIDR := range config.dstCIDRs {
		if ip.IsIPv4(dstCIDR.IP) {
			for _, sip := range ipv4s {
				key := srv6map.NewKey4(sip, dstCIDR.IP, dstCIDR.Mask)
				err := srv6map.SRv6Map4.Update(&key, value)
				if err != nil {
					return err
				}
			}
		} else {
			for _, sip := range ipv6s {
				key := srv6map.NewKey6(sip, dstCIDR.IP, dstCIDR.Mask)
				err := srv6map.SRv6Map6.Update(&key, value)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (manager *Manager) deleteSRv6MapEntry(config *Config, epData *endpointMetadata) error {
	for _, dstCIDR := range config.dstCIDRs {
		if ip.IsIPv4(dstCIDR.IP) {
			for _, sip := range epData.ipv4s {
				key := srv6map.NewKey4(sip, dstCIDR.IP, dstCIDR.Mask)
				err := srv6map.SRv6Map4.Delete(&key)
				if err != nil {
					return err
				}
			}
		} else {
			for _, sip := range epData.ipv6s {
				key := srv6map.NewKey6(sip, dstCIDR.IP, dstCIDR.Mask)
				err := srv6map.SRv6Map6.Delete(&key)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}
