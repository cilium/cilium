// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"log/slog"

	"github.com/cilium/cilium/pkg/identity/key"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
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
	mapping *CESCache

	// maxCEPsInCES is the maximum number of CiliumCoreEndpoint(s) packed in
	// a CiliumEndpointSlice Resource.
	maxCEPsInCES int
}

// newCESManager creates and initializes a new FirstComeFirstServe based CES
// manager, in this mode CEPs are batched based on FirstComeFirtServe algorithm.
func newCESManager(maxCEPsInCES int, logger *slog.Logger) *cesManager {
	return &cesManager{
		logger:       logger,
		mapping:      newCESCache(),
		maxCEPsInCES: maxCEPsInCES,
	}
}

// This function create a new ces and capacity to hold maximum ceps in a CES.
// This is called in 2 different scenarios:
//  1. During runtime, when ces manager decides to create a new ces, it calls
//     with an empty name, it generates a random unique name and assign it to the CES.
//  2. During operator warm boot [after crash or software upgrade], slicing manager
//     creates a CES, by passing unique name.
func (c *cesManager) createCES(name, ns string) CESName {
	if name == "" {
		name = uniqueCESliceName(c.mapping)
	}
	cesName := CESName(name)
	c.mapping.insertCES(cesName, ns)
	c.logger.Debug("Generated CES", logfields.CESName, cesName)
	return cesName
}

// Insert a pod into the local cache, before the associated CID has been created. Cache known information.
func (c *cesManager) AddPodMapping(pod *slim_corev1.Pod, nodeName string, cidKey *key.GlobalIdentity) {
	cepName, cesName := c.upsertPodIntoCES(pod)
	gidLabels := cidKey.GetKey()
	c.mapping.addCEP(cepName, cesName, NodeName(nodeName), gidLabels)
}

// UpdatePodWithIdentity is used to insert coreCEP in local cache, this may result in creating a new
// CES object or updating an existing CES object.
func (c *cesManager) UpdatePodWithIdentity(pod *slim_corev1.Pod, nodeName string, cid *cilium_v2.CiliumIdentity) []CESKey {
	cepName, cesName := c.upsertPodIntoCES(pod)
	cidName, gidLabels := cidToGidLabels(cid)
	c.mapping.insertCEP(cepName, cesName, NodeName(nodeName), gidLabels, cidName)
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

	// check the given pod's corecep already exists in any of the CES.
	// if yes, Update a ces with the given corecep object.
	cesName, exists := c.mapping.getCESName(cepName)
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
		return []CESKey{NewCESKey(cesName.string(), pod.Namespace)}
	}
	return nil
}

func (c *cesManager) UpdateNodeMapping(node *cilium_v2.CiliumNode) []CESKey {
	newKey := EncryptionKey(node.Spec.Encryption.Key)
	name := NodeName(node.Name)
	return c.mapping.insertNode(name, newKey)
}

func (c *cesManager) RemoveNodeMapping(node *cilium_v2.CiliumNode) []CESKey {
	return c.mapping.deleteNode(NodeName(node.Name))
}

func (c *cesManager) UpdateIdentityMapping(id *cilium_v2.CiliumIdentity) []CESKey {
	cidName, gidLabels := cidToGidLabels(id)
	return c.mapping.insertCID(cidName, gidLabels)
}

func (c *cesManager) RemoveIdentityMapping(id *cilium_v2.CiliumIdentity) []CESKey {
	cidName, gidLabels := cidToGidLabels(id)
	return c.mapping.deleteCID(cidName, gidLabels)
}

func (c *cesManager) GetCESInNs(ns *slim_corev1.Namespace) []CESKey {
	return c.mapping.getCESInNs(ns.GetName())
}

func (c *cesManager) RemoveNamespaceMapping(ns *slim_corev1.Namespace) {
	c.mapping.deleteNs(ns.GetName())
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
	return selectedCES
}

func (c *cesManager) initializeMappingForCES(ces *cilium_v2a1.CiliumEndpointSlice) CESName {
	return c.createCES(ces.Name, ces.Namespace)
}

func (c *cesManager) initializeMappingPodToNode(pod *slim_corev1.Pod, ns string, nodeName string, ces CESName, cid CID, gidLabels string) {
	c.mapping.insertCEP(GetCEPNameFromPod(pod), ces, NodeName(nodeName), gidLabels, cid)
}

func (c *cesManager) getCEPCountInCES(ces CESName) int {
	return c.mapping.countCEPsInCES(ces)
}

func (c *cesManager) getCESNamespace(ces CESName) string {
	return c.mapping.getCESNamespace(ces)
}

func (c *cesManager) getCEPinCES(ces CESName) []CEPName {
	return c.mapping.getCEPsInCES(ces)
}

func (c *cesManager) isCEPinCES(cep CEPName, ces CESName) bool {
	mappedCES, exists := c.mapping.getCESName(cep)
	return exists && mappedCES == ces
}

func (c *cesManager) getCIDForCEP(cep CEPName) (CID, bool) {
	return c.mapping.getCIDForCEP(cep)
}
