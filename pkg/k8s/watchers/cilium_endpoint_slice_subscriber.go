// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/types"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/time"
)

type endpointWatcher interface {
	endpointUpdated(oldC, newC *types.CiliumEndpoint)
	endpointDeleted(c *types.CiliumEndpoint)
}

type localEndpointCache interface {
	LookupCEPName(namespacedName string) *endpoint.Endpoint
}

type cesSubscriber struct {
	epWatcher endpointWatcher
	epCache   localEndpointCache
	cepMap    *cepToCESmap
}

func newCESSubscriber(k *K8sCiliumEndpointsWatcher) *cesSubscriber {
	return &cesSubscriber{
		epWatcher: k,
		epCache:   k.endpointManager,
		cepMap:    newCEPToCESMap(),
	}
}

// OnAdd invoked for newly created CESs, iterates over coreCEPs
// packed in the CES, converts coreCEP into types.CEP and calls endpointUpdated only for remoteNode CEPs.
func (cs *cesSubscriber) OnAdd(ces *cilium_v2a1.CiliumEndpointSlice) {
	for _, ep := range ces.Endpoints {
		cep := k8s.ConvertCoreCiliumEndpointToTypesCiliumEndpoint(&ep, ces.Namespace)
		CEPName := cep.Namespace + "/" + cep.Name
		log.WithFields(logrus.Fields{
			"CESName": ces.GetName(),
			"CEPName": CEPName,
		}).Debug("CES added, calling CoreEndpointUpdate")
		if p := cs.epCache.LookupCEPName(k8sUtils.GetObjNamespaceName(cep)); p != nil {
			timeSinceCepCreated := time.Since(p.GetCreatedAt())
			metrics.EndpointPropagationDelay.WithLabelValues().Observe(timeSinceCepCreated.Seconds())
		}
		// Map cep name to CES name
		cs.addCEPwithCES(CEPName, ces.GetName(), cep)
	}
}

// OnUpdate invoked for modified CESs, it compares old CES and new CES objects
// determines below things
// 1) any coreCEPs are removed from CES
// 2) any new coreCEPs are packed in CES
// 3) any existing coreCEPs are modified in CES
// call endpointUpdated/endpointDeleted only for remote node CEPs.
func (cs *cesSubscriber) OnUpdate(oldCES, newCES *cilium_v2a1.CiliumEndpointSlice) {
	oldCEPs := make(map[string]*types.CiliumEndpoint, len(oldCES.Endpoints))
	for _, ep := range oldCES.Endpoints {
		cep := k8s.ConvertCoreCiliumEndpointToTypesCiliumEndpoint(&ep, oldCES.Namespace)
		oldCEPs[cep.Namespace+"/"+cep.Name] = cep
	}

	newCEPs := make(map[string]*types.CiliumEndpoint, len(newCES.Endpoints))
	for _, ep := range newCES.Endpoints {
		cep := k8s.ConvertCoreCiliumEndpointToTypesCiliumEndpoint(&ep, newCES.Namespace)
		newCEPs[cep.Namespace+"/"+cep.Name] = cep
	}

	// Handle, removed CEPs from the CES.
	// old CES would have one or more stale cep entries, remove stale CEPs from oldCES.
	for CEPName, oldCEP := range oldCEPs {
		if _, exists := newCEPs[CEPName]; !exists {
			cs.onDelete(newCES, oldCEP)
		}
	}

	// Handle any new CEPs inserted in the CES.
	for CEPName, newCEP := range newCEPs {
		if _, exists := oldCEPs[CEPName]; !exists {
			log.WithFields(logrus.Fields{
				"CESName": newCES.GetName(),
				"CEPName": CEPName,
			}).Debug("CEP inserted, calling endpointUpdated")
			if p := cs.epCache.LookupCEPName(k8sUtils.GetObjNamespaceName(newCEP)); p != nil {
				timeSinceCepCreated := time.Since(p.GetCreatedAt())
				metrics.EndpointPropagationDelay.WithLabelValues().Observe(timeSinceCepCreated.Seconds())
			}
			cs.addCEPwithCES(CEPName, newCES.GetName(), newCEP)
		}
	}

	// process if any CEP value changed from old to new
	for CEPName, newCEP := range newCEPs {
		if oldCEP, exists := oldCEPs[CEPName]; exists {
			if oldCEP.DeepEqual(newCEP) {
				continue
			}
			log.WithFields(logrus.Fields{
				"CESName": newCES.GetName(),
				"CEPName": CEPName,
			}).Debug("CES updated, calling endpointUpdated")
			cs.addCEPwithCES(CEPName, newCES.GetName(), newCEP)
		}
	}
}

// OnDelete iterates over core CEPs in the slice and deletes those from remote Nodes.
// This is invoked in response to a CES delete event.
func (cs *cesSubscriber) OnDelete(ces *cilium_v2a1.CiliumEndpointSlice) {
	for _, ep := range ces.Endpoints {
		cep := k8s.ConvertCoreCiliumEndpointToTypesCiliumEndpoint(&ep, ces.Namespace)
		cs.onDelete(ces, cep)
	}
}

// OnDelete calls endpointDeleted for CEPs from remote Nodes.
func (cs *cesSubscriber) onDelete(ces *cilium_v2a1.CiliumEndpointSlice, cep *types.CiliumEndpoint) {
	CEPName := cep.Namespace + "/" + cep.Name
	log.WithFields(logrus.Fields{
		"CESName": ces.GetName(),
		"CEPName": CEPName,
	}).Debug("CES deleted, calling endpointDeleted")
	// LocalNode already deleted the CEP.
	// Hence, skip processing endpointDeleted for localNode CEPs.
	if p := cs.epCache.LookupCEPName(k8sUtils.GetObjNamespaceName(cep)); p != nil {
		return
	}
	// Delete CEP if and only if that CEP is owned by a CES, that was used during CES updated.
	// Delete CEP only if there is match in CEPToCES map and also delete CEPName in CEPToCES map.
	cs.deleteCEPfromCES(CEPName, ces.GetName(), cep)
}

// deleteCEP deletes the CEP and CES from the map.
// If this was last CES for the CEP it triggers endpointDeleted.
// If this was used CES for the CEP it picks other CES and triggers endpointUpdated.
func (cs *cesSubscriber) deleteCEPfromCES(CEPName, CESName string, c *types.CiliumEndpoint) {
	cs.cepMap.cesMutex.Lock()
	defer cs.cepMap.cesMutex.Unlock()
	needUpdate := cs.cepMap.currentCES[CEPName] == CESName
	cs.cepMap.deleteCEPLocked(CEPName, CESName)
	if !needUpdate {
		return
	}
	cep, exists := cs.cepMap.getCEPLocked(CEPName)
	if !exists {
		log.WithFields(logrus.Fields{
			"CESName": CESName,
			"CEPName": CEPName,
		}).Info("CEP deleted, calling endpointDeleted")
		cs.epWatcher.endpointDeleted(c)
	} else {
		log.WithFields(logrus.Fields{
			"CESName": CESName,
			"CEPName": CEPName,
		}).Info("CEP deleted, other CEP exists, calling endpointUpdated")
		cs.epWatcher.endpointUpdated(c, cep)
	}
}

// addCEPwithCES insert CEP with CES to the map and triggers endpointUpdated.
func (cs *cesSubscriber) addCEPwithCES(CEPName, CESName string, newCep *types.CiliumEndpoint) {
	cs.cepMap.cesMutex.Lock()
	defer cs.cepMap.cesMutex.Unlock()
	// Not checking if exists because it's fine and WAI if oldCep is nil.
	// When there is no previous endpoint the endpointUpdated should be called with nil.
	oldCep, _ := cs.cepMap.getCEPLocked(CEPName)
	cs.cepMap.insertCEPLocked(CEPName, CESName, newCep)
	cs.epWatcher.endpointUpdated(oldCep, newCep)
}

type cesToCEPRef map[string]*types.CiliumEndpoint

// cepToCESmap is used to map CiliumEndpoint name to CiliumEndpointSlice names.
// In steady state, there should be exactly one CiliumEndpointSlice associated
// with a CiliumEndpoint. But when a CEP is being transferred between two CESes,
// there will be a brief period of time in which the CEP exists in both the CESes.
type cepToCESmap struct {
	// cesMutex is used to lock all the operations changing cepMap and ipcache.
	cesMutex lock.Mutex
	// Maps CEP by name to a map of CES and pointer to CiliumEndpoint.
	// In rare case when CEP exists in multiple CESs it would contain all the
	// occurrences. This is needed to retrieve currently used Cilium Endpoint
	// (cepMap[cepName][currentCES[cepName]]) when update comes and to pick other
	// representation when the current one is deleted and other exist.
	// The Cilium Endpoint pointers will point to different objects from different
	// CES. They may or may not be equal to each other.
	cepMap map[string]cesToCEPRef
	// map of CEP name and currently used CES name.
	// Current CEP is cepMap[CEP][currentCES[CEP]]
	currentCES map[string]string
}

func newCEPToCESMap() *cepToCESmap {
	return &cepToCESmap{
		cepMap:     make(map[string]cesToCEPRef),
		currentCES: make(map[string]string),
	}
}

func (c *cepToCESmap) insertCEPLocked(cepName, cesName string, cep *types.CiliumEndpoint) {
	if _, exists := c.cepMap[cepName]; !exists {
		c.cepMap[cepName] = make(map[string]*types.CiliumEndpoint)
	}
	c.cepMap[cepName][cesName] = cep
	c.currentCES[cepName] = cesName
}

func (c *cepToCESmap) deleteCEPLocked(cepName, cesName string) {
	cesToCEPMap, exists := c.cepMap[cepName]
	if !exists {
		return
	}
	if _, exists = cesToCEPMap[cesName]; !exists {
		return
	}
	if len(cesToCEPMap) == 1 {
		delete(c.cepMap, cepName)
		delete(c.currentCES, cepName)
	} else {
		delete(cesToCEPMap, cesName)
		if c.currentCES[cepName] == cesName {
			for k := range cesToCEPMap {
				c.currentCES[cepName] = k
				break
			}
		}
	}
}

// getCEPLocked returns a currently used CEP associated with one of the CESes for the given CEP name.
func (c *cepToCESmap) getCEPLocked(cepName string) (*types.CiliumEndpoint, bool) {
	cep, exists := c.cepMap[cepName][c.currentCES[cepName]]
	return cep, exists
}
