// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"log/slog"

	"github.com/cilium/cilium/pkg/identity/key"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	// sequentialLetters contains lower case alphabets without vowels and few numbers.
	// skipped vowels and numbers [0, 1] to avoid generating controversial names.
	sequentialLetters = []rune("bcdfghjklmnpqrstvwxyz2456789")
)

// cesManager is used to batch CEP into a CES, based on FirstComeFirstServe. If a new CEP
// is inserted, then the CEP is queued in any one of the available CES. CEPs are
// inserted into CESs without any preference or any priority.
type cesManager struct {
	logger *slog.Logger

	// mapping is used to map CESName to CESTracker[i.e. list of CEPs],
	// as well as CEPName to CESName.
	mapping *CESToCEPMapping
	// cache is the local cache of CES state, including
	// associated pods, nodes, and identities.
	cache *CESCache

	// maxCEPsInCES is the maximum number of CiliumCoreEndpoint(s) packed in
	// a CiliumEndpointSlice Resource.
	maxCEPsInCES int
}

// newCESManager creates and initializes a new FirstComeFirstServe based CES
// manager, in this mode CEPs are batched based on FirstComeFirtServe algorithm.
func newCESManager(maxCEPsInCES int, cesWithoutCeps bool, logger *slog.Logger) *cesManager {
	cesManager := cesManager{
		logger:       logger,
		maxCEPsInCES: maxCEPsInCES,
	}

	if cesWithoutCeps {
		cesManager.cache = newCESCache()
	} else {
		cesManager.mapping = newCESToCEPMapping()
	}

	return &cesManager
}

// This function create a new ces and capacity to hold maximum ceps in a CES.
// This is called in 2 different scenarios:
//  1. During runtime, when ces manager decides to create a new ces, it calls
//     with an empty name, it generates a random unique name and assign it to the CES.
//  2. During operator warm boot [after crash or software upgrade], slicing manager
//     creates a CES, by passing unique name.
func (c *cesManager) createCES(name, ns string) CESName {
	if name == "" {
		if c.mapping != nil {
			name = uniqueCESliceName(c.mapping)
		} else {
			name = uniqueCESliceName(c.cache)
		}
	}
	cesName := CESName(name)
	if c.mapping != nil {
		c.mapping.insertCES(cesName, ns)
	} else {
		c.cache.insertCES(cesName, ns)
	}
	c.logger.Debug("Generated CES", logfields.CESName, cesName)
	return cesName
}

// UpdateCEPMapping is used to insert CEP in local cache, this may result in creating a new
// CES object or updating an existing CES object.
func (c *cesManager) UpdateCEPMapping(cep *cilium_v2a1.CoreCiliumEndpoint, ns string) []CESKey {
	cepName := GetCEPNameFromCCEP(cep, ns)
	c.logger.Debug("Insert CEP in local cache",
		logfields.CEPName, cepName.string(),
	)
	// check the given cep is already exists in any of the CES.
	// if yes, Update a ces with the given cep object.
	cesName, exists := c.mapping.getCESName(cepName)
	if exists {
		c.logger.Debug("CEP already mapped to CES",
			logfields.CEPName, cepName.string(),
			logfields.CESName, cesName.string(),
		)
		return []CESKey{NewCESKey(cesName.string(), ns)}
	}

	// Get the largest available CES.
	// This ensures the minimum number of CES updates, as the CESs will be
	// consistently filled up in order.
	cesName = c.getLargestAvailableCESForNamespace(ns)
	if cesName == "" {
		cesName = c.createCES("", ns)
	}
	c.mapping.insertCEP(cepName, cesName)
	c.logger.Debug("CEP mapped to CES",
		logfields.CEPName, cepName.string(),
		logfields.CESName, cesName.string(),
	)
	return []CESKey{NewCESKey(cesName.string(), ns)}
}

func (c *cesManager) RemoveCEPMapping(cep *cilium_v2a1.CoreCiliumEndpoint, ns string) CESKey {
	cepName := GetCEPNameFromCCEP(cep, ns)
	c.logger.Debug("Removing CEP from local cache", logfields.CEPName, cepName.string())
	cesName, exists := c.mapping.getCESName(cepName)
	if exists {
		c.logger.Debug("Removing CEP from CES",
			logfields.CEPName, cepName.string(),
			logfields.CESName, cesName.string(),
		)
		c.mapping.deleteCEP(cepName)
		if c.mapping.countCEPsInCES(cesName) == 0 {
			c.mapping.deleteCES(cesName)
		}
		return NewCESKey(cesName.string(), ns)
	}
	return CESKey(resource.Key{})
}

// Insert a pod into the local cache, before the associated CID has been created. Cache known information.
func (c *cesManager) AddPodMapping(pod *slim_corev1.Pod, nodeName string, cidKey *key.GlobalIdentity) {
	cepName, cesName := c.upsertPodIntoCES(pod)
	gidLabels := cidKey.GetKey()
	c.cache.addCEP(cepName, cesName, NodeName(nodeName), gidLabels)
}

// UpsertPodWithIdentity is used to insert coreCEP in local cache, this may result in creating a new
// CES object or updating an existing CES object.
func (c *cesManager) UpsertPodWithIdentity(pod *slim_corev1.Pod, nodeName string, cid *cilium_v2.CiliumIdentity) []CESKey {
	cepName, cesName := c.upsertPodIntoCES(pod)
	cidName, gidLabels := cidToGidLabels(cid)
	c.cache.upsertCEP(cepName, cesName, NodeName(nodeName), gidLabels, cidName)
	c.logger.Debug("CEP mapped to CES",
		logfields.CEPName, cepName.string(),
		logfields.CESName, cesName.string(),
	)
	return []CESKey{NewCESKey(cesName.string(), pod.Namespace)}
}

// For a pod, return the associated CEP name and CES name (if none already exist,
// create a new CES)
func (c *cesManager) upsertPodIntoCES(pod *slim_corev1.Pod) (CEPName, CESName) {
	cepName := GetCEPNameFromPod(pod)
	c.logger.Debug("Insert CEP in local cache",
		logfields.CEPName, cepName.string(),
	)

	// check if the given pod's corecep already exists in any CES.
	// if yes, update the ces with the given corecep object.
	cesName, exists := c.cache.getCESName(cepName)
	if exists {
		c.logger.Debug("CEP already mapped to CES",
			logfields.CEPName, cepName.string(),
			logfields.CESName, cesName.string(),
		)
		return cepName, cesName
	}

	// Get the largest available CES.
	// This ensures the minimum number of CES updates, as the CESs will be
	// consistently filled up in order.
	cesName = c.getLargestAvailableCESForNamespace(pod.Namespace)
	if cesName == "" {
		cesName = c.createCES("", pod.Namespace)
	}
	return cepName, cesName
}

func (c *cesManager) RemovePodMapping(pod *slim_corev1.Pod) []CESKey {
	cepName := GetCEPNameFromPod(pod)
	c.logger.Debug("Removing CEP from local cache", logfields.CEPName, cepName.string())

	cesName, exists := c.cache.getCESName(cepName)
	if exists {
		c.logger.Debug("Removing CEP from CES",
			logfields.CEPName, cepName.string(),
			logfields.CESName, cesName.string(),
		)
		c.cache.deleteCEP(cepName)
		if c.cache.countCEPsInCES(cesName) == 0 {
			c.cache.deleteCES(cesName)
		}
		return []CESKey{NewCESKey(cesName.string(), pod.Namespace)}
	}
	return nil
}

func (c *cesManager) UpdateNodeMapping(node *cilium_v2.CiliumNode) []CESKey {
	newKey := EncryptionKey(node.Spec.Encryption.Key)
	name := NodeName(node.Name)
	return c.cache.insertNode(name, newKey)
}

func (c *cesManager) RemoveNodeMapping(node *cilium_v2.CiliumNode) []CESKey {
	return c.cache.deleteNode(NodeName(node.Name))
}

func (c *cesManager) UpdateIdentityMapping(id *cilium_v2.CiliumIdentity) []CESKey {
	cidName, gidLabels := cidToGidLabels(id)
	return c.cache.insertCID(cidName, gidLabels)
}

func (c *cesManager) RemoveIdentityMapping(id *cilium_v2.CiliumIdentity) []CESKey {
	cidName, gidLabels := cidToGidLabels(id)
	return c.cache.deleteCID(cidName, gidLabels)
}

func (c *cesManager) GetCESInNs(ns *slim_corev1.Namespace) []CESKey {
	return c.cache.getCESInNs(ns.GetName())
}

func (c *cesManager) RemoveNamespaceMapping(ns *slim_corev1.Namespace) {
	c.cache.deleteNs(ns.GetName())
}

func cidToGidLabels(id *cilium_v2.CiliumIdentity) (CID, string) {
	cidName := id.GetName()
	cidKey := key.GetCIDKeyFromLabels(id.SecurityLabels, "")
	return CID(cidName), cidKey.GetKey()
}

// getLargestAvailableCESForNamespace returns the largest CES from cache for the
// specified namespace that has at least 1 CEP and 1 available spot (less than
// maximum CEPs). If it is not found, a nil is returned.
func (c *cesManager) getLargestAvailableCESForNamespace(ns string) CESName {
	largestCEPCount := 0
	selectedCES := CESName("")

	if c.mapping != nil {
		for _, ces := range c.mapping.getAllCESs() {
			cepCount := c.mapping.countCEPsInCES(ces)
			if cepCount < c.maxCEPsInCES && cepCount > largestCEPCount && c.mapping.getCESNamespace(ces) == ns {
				selectedCES = ces
				largestCEPCount = cepCount
				if largestCEPCount == c.maxCEPsInCES-1 {
					break
				}
			}
		}
	} else {
		for _, ces := range c.cache.getAllCESs() {
			cepCount := c.cache.countCEPsInCES(ces)
			if cepCount < c.maxCEPsInCES && cepCount > largestCEPCount && c.cache.getCESNamespace(ces) == ns {
				selectedCES = ces
				largestCEPCount = cepCount
				if largestCEPCount == c.maxCEPsInCES-1 {
					break
				}
			}
		}
	}
	return selectedCES
}

// TODO, do I need these:
func (c *cesManager) initializeMappingForCES(ces *cilium_v2a1.CiliumEndpointSlice) CESName {
	return c.createCES(ces.Name, ces.Namespace)
}

func (c *cesManager) initializeMappingPodToNode(pod *slim_corev1.Pod, ns string, nodeName string, ces CESName, cid CID, gidLabels string) {
	c.cache.upsertCEP(GetCEPNameFromPod(pod), ces, NodeName(nodeName), gidLabels, cid)
}

func (c *cesManager) initializeMappingCEPtoCES(cep *cilium_v2a1.CoreCiliumEndpoint, ns string, ces CESName) {
	cepName := GetCEPNameFromCCEP(cep, ns)
	c.mapping.insertCEP(cepName, ces)
}

func (c *cesManager) getCEPCountInCES(ces CESName) int {
	if c.mapping != nil {
		return c.mapping.countCEPsInCES(ces)
	}
	return c.cache.countCEPsInCES(ces)
}

func (c *cesManager) getCESNamespace(ces CESName) string {
	if c.mapping != nil {
		return c.mapping.getCESNamespace(ces)
	}
	return c.cache.getCESNamespace(ces)
}

func (c *cesManager) getCEPinCES(ces CESName) []CEPName {
	if c.mapping != nil {
		return c.mapping.getCEPsInCES(ces)
	}
	return c.cache.getCEPsInCES(ces)
}

func (c *cesManager) isCEPinCES(cep CEPName, ces CESName) bool {
	if c.mapping != nil {
		mappedCES, exists := c.mapping.getCESName(cep)
		return exists && mappedCES == ces
	}
	mappedCES, exists := c.cache.getCESName(cep)
	return exists && mappedCES == ces
}

func (c *cesManager) getCIDForCEP(cep CEPName) (CID, bool) {
	return c.cache.getCIDForCEP(cep)
}
