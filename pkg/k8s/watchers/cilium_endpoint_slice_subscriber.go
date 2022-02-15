// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"time"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/metrics"
)

type cesSubscriber struct {
	kWatcher *K8sWatcher
}

func newCESSubscriber(k *K8sWatcher) *cesSubscriber {
	return &cesSubscriber{
		kWatcher: k,
	}
}

// OnAdd invoked for newly created CESs, iterates over coreCEPs
// packed in the CES, converts coreCEP into types.CEP and calls endpointUpdated only for remoteNode CEPs.
func (cs *cesSubscriber) OnAdd(ces *cilium_v2a1.CiliumEndpointSlice) {
	for i, ep := range ces.Endpoints {
		log.WithFields(logrus.Fields{
			"CESName": ces.GetName(),
			"CEPName": ep.Name,
		}).Debug("CES added, calling CoreEndpointUpdate")
		c := k8s.ConvertCoreCiliumEndpointToTypesCiliumEndpoint(&ces.Endpoints[i], ces.Namespace)
		// Map cep name to CES name
		cepMap.insertCEP(ces.Namespace+"/"+ep.Name, ces.GetName())
		if p := cs.kWatcher.endpointManager.LookupPodName(k8sUtils.GetObjNamespaceName(c)); p != nil {
			timeSinceCepCreated := time.Since(p.GetCreatedAt())
			metrics.EndpointPropagationDelay.WithLabelValues().Observe(timeSinceCepCreated.Seconds())
		}
		cs.kWatcher.endpointUpdated(nil, c)
	}
}

// OnUpdate invoked for modified CESs, it compares old CES and new CES objects
// determines below things
// 1) any coreCEPs are removed from CES
// 2) any new coreCEPs are packed in CES
// 3) any existing coreCEPs are modified in CES
// call endpointUpdated/endpointDeleted only for remote node CEPs.
func (cs *cesSubscriber) OnUpdate(oldCES, newCES *cilium_v2a1.CiliumEndpointSlice) {
	oldCEPs := make(map[string]*cilium_v2a1.CoreCiliumEndpoint, len(oldCES.Endpoints))
	for i, ep := range oldCES.Endpoints {
		oldCEPs[oldCES.Namespace+"/"+ep.Name] = &oldCES.Endpoints[i]
	}

	newCEPs := make(map[string]*cilium_v2a1.CoreCiliumEndpoint, len(newCES.Endpoints))
	for i, ep := range newCES.Endpoints {
		newCEPs[newCES.Namespace+"/"+ep.Name] = &newCES.Endpoints[i]
	}

	// Handle, removed CEPs from the CES.
	// old CES would have one or more stale cep entries, remove stale CEPs from oldCES.
	for CEPName, oldCEP := range oldCEPs {
		if _, exists := newCEPs[CEPName]; !exists {
			log.WithFields(logrus.Fields{
				"CESName": oldCES.GetName(),
				"CEPName": CEPName,
			}).Debug("CEP deleted, calling endpointDeleted")
			c := k8s.ConvertCoreCiliumEndpointToTypesCiliumEndpoint(oldCEP, oldCES.Namespace)
			// LocalNode already has the latest CEP.
			// Hence, skip processing endpointupdate for localNode CEPs.
			if p := cs.kWatcher.endpointManager.LookupPodName(k8sUtils.GetObjNamespaceName(c)); p != nil {
				continue
			}
			// Delete CEP if and only if that CEP is owned by a CES, that was used during CES updated.
			// Delete CEP only if there is match in CEPToCES map and also delete CEPName in CEPToCES map.
			if cesName := cepMap.getCESName(CEPName); cesName == oldCES.GetName() {
				cs.kWatcher.endpointDeleted(c)
				cepMap.deleteCEP(CEPName)
			}
		}
	}

	// Handle any new CEPs inserted in the CES.
	for CEPName, newCEP := range newCEPs {
		if _, exists := oldCEPs[CEPName]; !exists {
			log.WithFields(logrus.Fields{
				"CESName": oldCES.GetName(),
				"CEPName": CEPName,
			}).Debug("CEP inserted, calling endpointUpdated")
			c := k8s.ConvertCoreCiliumEndpointToTypesCiliumEndpoint(newCEP, newCES.Namespace)
			if p := cs.kWatcher.endpointManager.LookupPodName(k8sUtils.GetObjNamespaceName(c)); p != nil {
				timeSinceCepCreated := time.Since(p.GetCreatedAt())
				metrics.EndpointPropagationDelay.WithLabelValues().Observe(timeSinceCepCreated.Seconds())
			}
			cs.kWatcher.endpointUpdated(nil, c)
			cepMap.insertCEP(CEPName, oldCES.GetName())
		}
	}

	// process if any CEP value changed from old to new
	for CEPName, newCEP := range newCEPs {
		if oldCEP, exists := oldCEPs[CEPName]; exists {
			if oldCEP.DeepEqual(newCEP) {
				continue
			}
			log.WithFields(logrus.Fields{
				"CESName": oldCES.GetName(),
				"CEPName": CEPName,
			}).Debug("CES updated, calling endpointUpdated")
			newC := k8s.ConvertCoreCiliumEndpointToTypesCiliumEndpoint(newCEP, newCES.Namespace)
			oldC := k8s.ConvertCoreCiliumEndpointToTypesCiliumEndpoint(oldCEP, oldCES.Namespace)
			cs.kWatcher.endpointUpdated(oldC, newC)
			cepMap.insertCEP(CEPName, oldCES.GetName())
		}
	}
}

// OnDelete invoked for deleted CESs, iterates over coreCEPs
// and calls endpointDeleted only for remoteNode CEPs.
func (cs *cesSubscriber) OnDelete(ces *cilium_v2a1.CiliumEndpointSlice) {
	for i, ep := range ces.Endpoints {
		log.WithFields(logrus.Fields{
			"CESName": ces.GetName(),
			"CEPName": ep.Name,
		}).Debug("CES deleted, calling endpointDeleted")
		c := k8s.ConvertCoreCiliumEndpointToTypesCiliumEndpoint(&ces.Endpoints[i], ces.Namespace)
		// LocalNode already deleted the CEP.
		// Hence, skip processing endpointDeleted for localNode CEPs.
		if p := cs.kWatcher.endpointManager.LookupPodName(k8sUtils.GetObjNamespaceName(c)); p != nil {
			continue
		}
		// Delete CEP if and only if that CEP is owned by a CES, that was used during CES updated.
		// Delete CEP only if there is match in CEPToCES map and also delete CEPName in CEPToCES map.
		if cesName := cepMap.getCESName(ces.Namespace + "/" + ep.Name); cesName == ces.GetName() {
			cs.kWatcher.endpointDeleted(c)
			cepMap.deleteCEP(ep.Name)
		}
	}
}

// cepToCESmap is used to map CiliumEndpoint name to CiliumEndpointBatch name.
type cepToCESmap struct {
	cesMutex lock.RWMutex
	cepMap   map[string]string
}

func newCEPToCESMap() *cepToCESmap {
	return &cepToCESmap{
		cepMap: make(map[string]string),
	}
}

func (c *cepToCESmap) insertCEP(cepName, cesName string) {
	c.cesMutex.Lock()
	defer c.cesMutex.Unlock()
	c.cepMap[cepName] = cesName
}

func (c *cepToCESmap) deleteCEP(cepName string) {
	c.cesMutex.Lock()
	defer c.cesMutex.Unlock()
	delete(c.cepMap, cepName)
}

func (c *cepToCESmap) getCESName(cepName string) string {
	c.cesMutex.RLock()
	defer c.cesMutex.RUnlock()
	return c.cepMap[cepName]
}
