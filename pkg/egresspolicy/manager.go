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

package egresspolicy

import (
	"errors"
	"fmt"
	"net"

	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/egressmap"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/types"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "egresspolicy")
)

// The egresspolicy manager stores the internal data tracking the policy
// and endpoint mappings. It also hooks up all the callbacks to update
// egress bpf map accordingly.
type Manager struct {
	mutex lock.Mutex

	// Stores endpoint to policy mapping
	policyEndpoints map[endpointID][]policyID
	// Stores policy configs indexed by policyID
	policyConfigs map[policyID]*Config
	// Stores endpointId to endpoint metadata mapping
	epDataStore map[endpointID]*endpointMetadata
}

func NewEgressPolicyManager() *Manager {
	return &Manager{
		policyEndpoints: make(map[endpointID][]policyID),
		policyConfigs:   make(map[policyID]*Config),
		epDataStore:     make(map[endpointID]*endpointMetadata),
	}
}

// Event handlers

// AddEgressPolicy parses the given policy config, and updates internal state with the config fields.
// returns bool indicates if policy is added, err inidates first encountered error
func (manager *Manager) AddEgressPolicy(config Config) (bool, error) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()

	_, ok := manager.policyConfigs[config.id]
	if ok {
		log.WithField(
			logfields.CiliumEgressNATPolicyName, config.id.Name).Warn("CiliumEgressNATPolicy already exists and is not re-added.")
		return false, errors.New("already exists")
	}

	err := manager.isValidConfig(config)
	if err != nil {
		return false, err
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

// Deletes the internal state associated with the given policy, including egress eBPF map entries
func (manager *Manager) DeleteEgressPolicy(configID policyID) error {
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
				if err := manager.deleteEgressMap(storedConfig, epData); err != nil {
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
		}).Error("Failed to get valid endpoint IPs, skipping update to egress policy.")
		return
	}

	if epData, err = getEndpointMetadata(endpoint); err != nil {
		log.WithError(err).WithFields(logrus.Fields{
			logfields.K8sEndpointName: endpoint.Name,
			logfields.K8sNamespace:    endpoint.Namespace,
		}).Error("Failed to get valid endpoint metadata, skipping update to egress policy.")
		return
	}

	// Remove old: check if the endpoint was previously selected by any of the policies.
	if policies, ok := manager.policyEndpoints[epData.id]; ok {
		for _, policy := range policies {
			config := manager.policyConfigs[policy]
			err := manager.deleteEgressMap(config, epData)
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
			manager.deleteEgressMap(config, epData)
		}
		delete(manager.policyEndpoints, id)
	}
	delete(manager.epDataStore, id)
}

func getEndpointMetadata(endpoint *k8sTypes.CiliumEndpoint) (*endpointMetadata, error) {
	var ipv4s []string
	id := types.NamespacedName{
		Name:      endpoint.GetName(),
		Namespace: endpoint.GetNamespace(),
	}

	if endpoint.Networking == nil {
		return nil, fmt.Errorf("endpoint has no networking metadata")
	}

	for _, pair := range endpoint.Networking.Addressing {
		if pair.IPV4 != "" {
			ipv4s = append(ipv4s, pair.IPV4)
		}
	}

	if endpoint.Identity == nil {
		return nil, fmt.Errorf("endpoint has no identity metadata")
	}

	data := &endpointMetadata{
		ips:    ipv4s,
		labels: labels.NewLabelsFromModel(endpoint.Identity.Labels).K8sStringMap(),
		id:     id,
	}

	return data, nil
}

// isValidConfig validates the given policy config.
func (manager *Manager) isValidConfig(config Config) error {
	for _, policyConfig := range manager.policyConfigs {
		if policyConfig.egressIP.String() == config.egressIP.String() {
			return fmt.Errorf(
				"CiliumEgressNatPolicy for egress IP %v already exists",
				config.egressIP.String())

		}
	}
	return nil
}

// upsertPolicyEndpoint updates or insert to endpoint policy mapping for given policy config and endpoints,
// it also upserts egress map to keep in sync
func (manager *Manager) upsertPolicyEndpoint(config *Config, epData *endpointMetadata) error {
	if err := manager.updateEgressMap(epData.ips, config); err != nil {
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

func (manager *Manager) updateEgressMap(ips []string, config *Config) error {
	for _, ip := range ips {
		sip := net.ParseIP(ip).To4()
		for _, dstCIDR := range config.dstCIDRs {
			key := egressmap.NewKey(sip, dstCIDR.IP, dstCIDR.Mask)
			value := &egressmap.EgressInfo4{}
			// As currently designed, the egressIP serves two purposes, one for forwarding traffic
			// to the gateway node, the other for SNATing the egress traffic on the gateway.
			copy(value.TunnelEndpoint[:], config.egressIP)
			copy(value.EgressIP[:], config.egressIP)

			err := egressmap.EgressMap.Update(&key, value)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (manager *Manager) deleteEgressMap(config *Config, epData *endpointMetadata) error {
	for _, ip := range epData.ips {
		sip := net.ParseIP(ip).To4()
		for _, dstCIDR := range config.dstCIDRs {
			key := egressmap.NewKey(sip, dstCIDR.IP, dstCIDR.Mask)
			err := egressmap.EgressMap.Delete(&key)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
