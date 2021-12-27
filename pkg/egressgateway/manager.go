// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package egressgateway

import (
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/egressmap"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/types"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "egressgateway")
)

type k8sCacheSyncedChecker interface {
	WaitUntilK8sCacheIsSynced()
	K8sCacheIsSynced() bool
}

// The egressgateway manager stores the internal data tracking policies and
// endpoints. It also hooks up all the callbacks to update egress bpf policy map
// accordingly.
type Manager struct {
	mutex lock.Mutex

	// k8sCacheSyncedChecker is used to check if the agent has synced its
	// cache with the k8s API server
	k8sCacheSyncedChecker k8sCacheSyncedChecker

	// policyConfigs stores policy configs indexed by policyID
	policyConfigs map[policyID]*PolicyConfig

	// epDataStore stores endpointId to endpoint metadata mapping
	epDataStore map[endpointID]*endpointMetadata
}

// NewEgressGatewayManager returns a new Egress Gateway Manager.
func NewEgressGatewayManager(k8sCacheSyncedChecker k8sCacheSyncedChecker) *Manager {
	manager := &Manager{
		k8sCacheSyncedChecker: k8sCacheSyncedChecker,
		policyConfigs:         make(map[policyID]*PolicyConfig),
		epDataStore:           make(map[endpointID]*endpointMetadata),
	}

	manager.runReconciliationAfterK8sSync()

	return manager
}

// runReconciliationAfterK8sSync spawns a goroutine that waits for the agent to
// sync with k8s and then runs the first reconciliation.
func (manager *Manager) runReconciliationAfterK8sSync() {
	go func() {
		manager.k8sCacheSyncedChecker.WaitUntilK8sCacheIsSynced()

		manager.mutex.Lock()
		defer manager.mutex.Unlock()

		manager.reconcile()
	}()
}

// Event handlers

// OnAddEgressPolicy and updates the manager internal state with the policy
// config fields.
func (manager *Manager) OnAddEgressPolicy(config PolicyConfig) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()

	logger := log.WithField(logfields.CiliumEgressNATPolicyName, config.id.Name)

	if _, ok := manager.policyConfigs[config.id]; !ok {
		logger.Info("Added CiliumEgressNATPolicy")
	} else {
		logger.Info("Updated CiliumEgressNATPolicy")
	}

	manager.policyConfigs[config.id] = &config

	manager.reconcile()
}

// OnDeleteEgressPolicy deletes the internal state associated with the given
// policy.
func (manager *Manager) OnDeleteEgressPolicy(configID policyID) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()

	logger := log.WithField(logfields.CiliumEgressNATPolicyName, configID.Name)

	if manager.policyConfigs[configID] == nil {
		logger.Warn("Can't delete CiliumEgressNATPolicy: policy not found")
		return
	}

	logger.Info("Deleted CiliumEgressNATPolicy")

	delete(manager.policyConfigs, configID)

	manager.reconcile()
}

// OnUpdateEndpoint is the event handler for endpoint additions and updates.
func (manager *Manager) OnUpdateEndpoint(endpoint *k8sTypes.CiliumEndpoint) {
	var epData *endpointMetadata
	var err error

	manager.mutex.Lock()
	defer manager.mutex.Unlock()

	logger := log.WithFields(logrus.Fields{
		logfields.K8sEndpointName: endpoint.Name,
		logfields.K8sNamespace:    endpoint.Namespace,
	})

	if len(endpoint.Networking.Addressing) == 0 {
		logger.WithError(err).
			Error("Failed to get valid endpoint IPs, skipping update to egress policy.")
		return
	}

	if epData, err = getEndpointMetadata(endpoint); err != nil {
		logger.WithError(err).
			Error("Failed to get valid endpoint metadata, skipping update to egress policy.")
		return
	}

	manager.epDataStore[epData.id] = epData

	manager.reconcile()
}

// OnDeleteEndpoint is the event handler for endpoint deletions.
func (manager *Manager) OnDeleteEndpoint(endpoint *k8sTypes.CiliumEndpoint) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()

	id := types.NamespacedName{
		Name:      endpoint.GetName(),
		Namespace: endpoint.GetNamespace(),
	}

	delete(manager.epDataStore, id)

	manager.reconcile()
}

// addMissingEgressRules is responsible for adding any missing egress gateway policy stored in the
// manager (i.e. k8s CiliumEgressNATPolicies) to the egress policy BPF map.
func (manager *Manager) addMissingEgressRules() {
	egressPolicies := map[egressmap.EgressPolicyKey4]egressmap.EgressPolicyVal4{}
	egressmap.EgressPolicyMap.IterateWithCallback(
		func(key *egressmap.EgressPolicyKey4, val *egressmap.EgressPolicyVal4) {
			egressPolicies[*key] = *val
		})

	for _, policyConfig := range manager.policyConfigs {
		for _, endpoint := range manager.epDataStore {
			if !policyConfig.selectsEndpoint(endpoint) {
				continue
			}

			for _, endpointIP := range endpoint.ips {
				for _, dstCIDR := range policyConfig.dstCIDRs {
					policyKey := egressmap.NewEgressPolicyKey4(endpointIP, dstCIDR.IP, dstCIDR.Mask)
					policyVal, policyPresent := egressPolicies[policyKey]

					if policyPresent && policyVal.Match(policyConfig.egressIP, policyConfig.egressIP) {
						continue
					}

					logger := log.WithFields(logrus.Fields{
						logfields.SourceIP:        endpointIP,
						logfields.DestinationCIDR: *dstCIDR,
						logfields.EgressIP:        policyConfig.egressIP,
						logfields.GatewayIP:       policyConfig.egressIP,
					})

					if err := egressmap.EgressPolicyMap.Update(endpointIP, *dstCIDR, policyConfig.egressIP, policyConfig.egressIP); err != nil {
						logger.WithError(err).Error("Error applying egress gateway policy")
					} else {
						logger.Info("Egress gateway policy applied")
					}
				}
			}
		}
	}
}

// removeUnusedEgressRules is responsible for removing any entry in the egress policy BPF map which
// is not baked by an actual k8s CiliumEgressNATPolicy.
//
// The algorithm for this function can be expressed as:
//
//    nextPolicyKey:
//    for each entry in the egress_policy map {
//        for each policy in k8s CiliumEgressNATPolices {
//            if policy matches entry {
//                // we found one k8s policy that matches the current BPF entry, move to the next one
//                continue nextPolicyKey
//            }
//        }
//
//        // the current BPF entry is not backed by any k8s policy, delete it
//        egressmap.RemoveEgressPolicy(entry)
//    }
func (manager *Manager) removeUnusedEgressRules() {
	egressPolicies := map[egressmap.EgressPolicyKey4]egressmap.EgressPolicyVal4{}
	egressmap.EgressPolicyMap.IterateWithCallback(
		func(key *egressmap.EgressPolicyKey4, val *egressmap.EgressPolicyVal4) {
			egressPolicies[*key] = *val
		})

nextPolicyKey:
	for policyKey, policyVal := range egressPolicies {
		for _, policyConfig := range manager.policyConfigs {
			for _, endpoint := range manager.epDataStore {
				if !policyConfig.selectsEndpoint(endpoint) {
					continue
				}

				for _, endpointIP := range endpoint.ips {
					for _, dstCIDR := range policyConfig.dstCIDRs {
						if policyKey.Match(endpointIP, dstCIDR) &&
							policyVal.Match(policyConfig.egressIP, policyConfig.egressIP) {
							continue nextPolicyKey
						}
					}
				}
			}
		}

		logger := log.WithFields(logrus.Fields{
			logfields.SourceIP:        policyKey.GetSourceIP(),
			logfields.DestinationCIDR: policyKey.GetDestCIDR(),
		})

		if err := egressmap.EgressPolicyMap.Delete(policyKey.GetSourceIP(), *policyKey.GetDestCIDR()); err != nil {
			logger.WithError(err).Error("Error removing egress gateway policy")
		} else {
			logger.Info("Egress gateway policy removed")
		}
	}
}

// reconcile is responsible for reconciling the state of the manager (i.e. the
// desired state) with the actual state of the node (egress policy map entries).
//
// Whenever it encounters an error, it will just log it and move to the next
// item, in order to reconcile as many states as possible.
func (manager *Manager) reconcile() {
	if !manager.k8sCacheSyncedChecker.K8sCacheIsSynced() {
		return
	}

	// The order of the next 2 function calls matters, as by first adding missing policies and
	// only then removing obsolete ones we make sure there will be no connectivity disruption
	manager.addMissingEgressRules()
	manager.removeUnusedEgressRules()
}
