// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"log/slog"

	"github.com/spf13/cast"

	"github.com/cilium/cilium/pkg/identity/key"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	wgtypes "github.com/cilium/cilium/pkg/wireguard/types"
)

var (
	// sequentialLetters contains lower case alphabets without vowels and few numbers.
	// skipped vowels and numbers [0, 1] to avoid generating controversial names.
	sequentialLetters = []rune("bcdfghjklmnpqrstvwxyz2456789")
)

type CesManager interface {
	getCEPCountInCES(ces CESName) int
	getCESNamespace(ces CESName) string
	getCEPinCES(ces CESName) []CEPName
	isCEPinCES(cep CEPName, ces CESName) bool
}

// cesManager is used to batch CEP into a CES, based on FirstComeFirstServe. If a new CEP
// is inserted, then the CEP is queued in any one of the available CES. CEPs are
// inserted into CESs without any preference or any priority.
type defaultManager struct {
	logger *slog.Logger

	// mapping is used to map CESName to CESTracker[i.e. list of CEPs],
	// as well as CEPName to CESName.
	mapping *CESToCEPMapping

	// maxCEPsInCES is the maximum number of CiliumCoreEndpoint(s) packed in
	// a CiliumEndpointSlice Resource.
	maxCEPsInCES int
}

type slimManager struct {
	defaultManager

	// mapping is used to map CES to the state associated with them
	// in CES Controller's running in slim mode
	mapping *CESCache
}

// newDefaultManager creates and initializes a new FirstComeFirstServe based CES
// manager, in this mode CEPs are batched based on FirstComeFirtServe algorithm.
func newDefaultManager(maxCEPsInCES int, logger *slog.Logger) *defaultManager {
	return &defaultManager{
		logger:       logger,
		mapping:      newCESToCEPMapping(),
		maxCEPsInCES: maxCEPsInCES,
	}
}

// newSlimManager creates and initializes a new FirstComeFirstServe based CES
// manager, in this mode CEPs are batched based on FirstComeFirstServe algorithm.
func newSlimManager(maxCEPsInCES int, logger *slog.Logger) *slimManager {
	return &slimManager{
		defaultManager: defaultManager{
			logger:       logger,
			maxCEPsInCES: maxCEPsInCES,
		},
		mapping: newCESCache(),
	}
}

// This function create a new ces and capacity to hold maximum ceps in a CES.
// This is called in 2 different scenarios:
//  1. During runtime, when ces manager decides to create a new ces, it calls
//     with an empty name, it generates a random unique name and assign it to the CES.
//  2. During operator warm boot [after crash or software upgrade], slicing manager
//     creates a CES, by passing unique name.
func (c *defaultManager) createCES(name, ns string) CESName {
	return createCESHelper(name, ns, c.mapping, c.logger)
}

func (c *slimManager) createCES(name, ns string) CESName {
	return createCESHelper(name, ns, c.mapping, c.logger)
}

func createCESHelper(name, ns string, cacher CESCacher, logger *slog.Logger) CESName {
	if name == "" {
		name = uniqueCESliceName(cacher)
	}
	cesName := CESName(name)
	cacher.insertCES(cesName, ns)
	logger.Debug("Generated CES", logfields.CESName, cesName)
	return cesName
}

// UpdateCEPMapping is used to insert CEP in local cache, this may result in creating a new
// CES object or updating an existing CES object.
func (c *defaultManager) UpdateCEPMapping(cep *cilium_v2a1.CoreCiliumEndpoint, ns string) []CESKey {
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

func (c *defaultManager) RemoveCEPMapping(cep *cilium_v2a1.CoreCiliumEndpoint, ns string) CESKey {
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

// getLargestAvailableCESForNamespace returns the largest CES from cache for the
// specified namespace that has at least 1 CEP and 1 available spot (less than
// maximum CEPs). If it is not found, a nil is returned.
func getLargestAvailableCESForNamespace(mapping CESCacher, ns string, maxCEPsInCES int) CESName {
	largestCEPCount := 0
	selectedCES := CESName("")
	for _, ces := range mapping.getAllCESs() {
		cepCount := mapping.countCEPsInCES(ces)
		if cepCount < maxCEPsInCES && cepCount > largestCEPCount && mapping.getCESNamespace(ces) == ns {
			selectedCES = ces
			largestCEPCount = cepCount
			if largestCEPCount == maxCEPsInCES-1 {
				break
			}
		}
	}
	return selectedCES
}

func (c *defaultManager) getLargestAvailableCESForNamespace(ns string) CESName {
	return getLargestAvailableCESForNamespace(c.mapping, ns, c.maxCEPsInCES)
}

func (c *slimManager) getLargestAvailableCESForNamespace(ns string) CESName {
	return getLargestAvailableCESForNamespace(c.mapping, ns, c.maxCEPsInCES)
}

func (c *defaultManager) initializeMappingForCES(ces *cilium_v2a1.CiliumEndpointSlice) CESName {
	return c.createCES(ces.Name, ces.Namespace)
}

func (c *slimManager) initializeMappingForCES(ces *cilium_v2a1.CiliumEndpointSlice) CESName {
	return c.createCES(ces.Name, ces.Namespace)
}

func (c *defaultManager) initializeMappingCEPtoCES(cep *cilium_v2a1.CoreCiliumEndpoint, ns string, ces CESName) {
	cepName := GetCEPNameFromCCEP(cep, ns)
	c.mapping.insertCEP(cepName, ces)
}

func (c *slimManager) initializeMappingPodToNode(cepName CEPName, nodeName NodeName, ces CESName, cid CID, gidLabels Label, encryptionKey EncryptionKey) {
	c.mapping.upsertCEP(cepName, ces, nodeName, gidLabels, cid)
	c.mapping.insertNode(nodeName, encryptionKey)
}

func (c *defaultManager) getCEPCountInCES(ces CESName) int {
	return c.mapping.countCEPsInCES(ces)
}

func (c *defaultManager) getCESNamespace(ces CESName) string {
	return c.mapping.getCESNamespace(ces)
}

func (c *defaultManager) getCEPinCES(ces CESName) []CEPName {
	return c.mapping.getCEPsInCES(ces)
}

func (c *defaultManager) isCEPinCES(cep CEPName, ces CESName) bool {
	mappedCES, exists := c.mapping.getCESName(cep)
	return exists && mappedCES == ces
}

func (c *slimManager) UpdateNodeMapping(node *cilium_v2.CiliumNode, ipsecEnabled, wgEnabled bool) []CESKey {
	newKey := EncryptionKey(getNodeEndpointEncryptionKey(node, ipsecEnabled, wgEnabled))
	name := NodeName(node.Name)
	return c.mapping.insertNode(name, newKey)
}

func (c *slimManager) RemoveNodeMapping(node *cilium_v2.CiliumNode) []CESKey {
	return c.mapping.deleteNode(NodeName(node.Name))
}

func getNodeEndpointEncryptionKey(node *cilium_v2.CiliumNode, ipsecEnabled, wgEnabled bool) int {
	switch {
	case wgEnabled:
		return cast.ToInt(wgtypes.StaticEncryptKey)
	case ipsecEnabled:
		return node.Spec.Encryption.Key
	default:
		return 0
	}
}

func (c *slimManager) UpdateIdentityMapping(id *cilium_v2.CiliumIdentity) []CESKey {
	cidName, gidLabels := cidToGidLabels(id)
	return c.mapping.insertCID(cidName, gidLabels)
}

func (c *slimManager) RemoveIdentityMapping(id *cilium_v2.CiliumIdentity) []CESKey {
	cidName, gidLabels := cidToGidLabels(id)
	return c.mapping.deleteCID(cidName, gidLabels)
}

// Insert a pod into the local cache, before the associated CID has been created. Cache known information.
func (c *slimManager) AddPodMapping(pod *slim_corev1.Pod, nodeName string, cidKey *key.GlobalIdentity) {
	cepName, cesName := c.upsertPodIntoCES(pod)
	gidLabels := cidKey.GetKey()
	c.mapping.addCEP(cepName, cesName, NodeName(nodeName), Label(gidLabels))
}

// UpsertPodWithIdentity is used to insert coreCEP in local cache, this may result in creating a new
// CES object or updating an existing CES object.
func (c *slimManager) UpsertPodWithIdentity(pod *slim_corev1.Pod, nodeName string, cid *cilium_v2.CiliumIdentity) []CESKey {
	cepName, cesName := c.upsertPodIntoCES(pod)
	cidName, gidLabels := cidToGidLabels(cid)
	c.mapping.upsertCEP(cepName, cesName, NodeName(nodeName), gidLabels, cidName)
	c.logger.Debug("CEP mapped to CES",
		logfields.CEPName, cepName.string(),
		logfields.CESName, cesName.string(),
	)
	return []CESKey{NewCESKey(cesName.string(), pod.Namespace)}
}

// For a pod, return the associated CEP name and CES name (if none already exist,
// create a new CES)
func (c *slimManager) upsertPodIntoCES(pod *slim_corev1.Pod) (CEPName, CESName) {
	cepName := GetCEPNameFromPod(pod)
	c.logger.Debug("Insert CEP in local cache",
		logfields.CEPName, cepName.string(),
	)

	// check if the given pod's corecep already exists in any CES.
	// if yes, update the ces with the given corecep object.
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

func (c *slimManager) RemovePodMapping(pod *slim_corev1.Pod) []CESKey {
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

func (c *slimManager) GetCESInNs(ns *slim_corev1.Namespace) []CESKey {
	return c.mapping.getCESInNs(ns.GetName())
}

func (c *slimManager) RemoveNamespaceMapping(ns *slim_corev1.Namespace) {
	c.mapping.deleteNs(ns.GetName())
}

func (c *slimManager) getCIDForCEP(cep CEPName) (CID, bool) {
	return c.mapping.getCIDForCEP(cep)
}

func cidToGidLabels(id *cilium_v2.CiliumIdentity) (CID, Label) {
	cidName := id.GetName()
	cidKey := key.GetCIDKeyFromLabels(id.SecurityLabels, "")
	return CID(cidName), Label(cidKey.GetKey())
}
