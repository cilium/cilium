// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"log/slog"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	wgtypes "github.com/cilium/cilium/pkg/wireguard/types"
)

var (
	// sequentialLetters contains lower case alphabets without vowels and few numbers.
	// skipped vowels and numbers [0, 1] to avoid generating controversial names.
	sequentialLetters = []rune("bcdfghjklmnpqrstvwxyz2456789")
)

type Manager interface {
	getCEPCountInCES(ces CESName) int
	getCESNamespace(ces CESName) string
	getCEPinCES(ces CESName) []CEPName
	isCEPinCES(cep CEPName, ces CESName) bool
}

// A cesManager is used to batch CEP into a CES, based on FirstComeFirstServe. If a new CEP
// is inserted, then the CEP is queued in any one of the available CES. CEPs are
// inserted into CESs without any preference or any priority. The defaultManager
// is used when the CES controller is running in default mode.
type defaultManager struct {
	logger *slog.Logger
	// mapping is used to map CESName to CESTracker[i.e. list of CEPs],
	// as well as CEPName to CESName.
	mapping *CESToCEPMapping

	// maxCEPsInCES is the maximum number of CiliumCoreEndpoint(s) packed in
	// a CiliumEndpointSlice Resource.
	maxCEPsInCES int
}

// The slimManager is the cesManager used when the CES controller is running in slim mode.
type slimManager struct {
	// Mutex to protect access to the CESCache during multi-step operations.
	mutex lock.RWMutex

	logger *slog.Logger

	// mapping is used to map CES to the state associated with them
	// when the CES controller is running in slim mode
	mapping *CESCache

	// maxCEPsInCES is the maximum number of CiliumCoreEndpoint(s) packed in
	// a CiliumEndpointSlice Resource.
	maxCEPsInCES int
}

// newDefaultManager creates and initializes a new FirstComeFirstServe based CES
// manager for when the CES controller is running in default mode.
func newDefaultManager(maxCEPsInCES int, logger *slog.Logger) *defaultManager {
	return &defaultManager{
		logger:       logger,
		mapping:      newCESToCEPMapping(),
		maxCEPsInCES: maxCEPsInCES,
	}
}

// newSlimManager creates and initializes a new FirstComeFirstServe based CES
// manager for when the CES controller is running in slim mode.
func newSlimManager(maxCEPsInCES int, logger *slog.Logger) *slimManager {
	return &slimManager{
		logger:       logger,
		maxCEPsInCES: maxCEPsInCES,
		mapping:      newCESCache(),
	}
}

// This function create a new ces and capacity to hold maximum ceps in a CES.
// This is called in 2 different scenarios:
//  1. During runtime, when ces manager decides to create a new ces, it calls
//     with an empty name, it generates a random unique name and assign it to the CES.
//  2. During operator warm boot [after crash or software upgrade], slicing manager
//     creates a CES, by passing unique name.
func (c *defaultManager) createCES(name, ns string) CESName {
	if name == "" {
		name = uniqueCESliceName(c.mapping)
	}
	cesName := CESName(name)
	c.mapping.insertCES(cesName, ns)
	c.logger.Debug("Generated CES", logfields.CESName, cesName)
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
func (c *defaultManager) getLargestAvailableCESForNamespace(ns string) CESName {
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

func (c *defaultManager) initializeMappingForCES(ces *cilium_v2a1.CiliumEndpointSlice) CESName {
	return c.createCES(ces.Name, ces.Namespace)
}

func (c *defaultManager) initializeMappingCEPtoCES(cep *cilium_v2a1.CoreCiliumEndpoint, ns string, ces CESName) {
	cepName := GetCEPNameFromCCEP(cep, ns)
	c.mapping.insertCEP(cepName, ces)
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

// UpdateNodeMapping upserts a node and its encryption key into the cache and returns updated CESs.
func (c *slimManager) UpdateNodeMapping(node *cilium_v2.CiliumNode, ipsecEnabled, wgEnabled bool) []CESKey {
	newKey := getNodeEndpointEncryptionKey(node, ipsecEnabled, wgEnabled)
	name := NodeName(node.Name)

	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.mapping.insertNode(name, newKey)
}

// RemoveNodeMapping removes a node from the cache and returns affected CESs.
func (c *slimManager) RemoveNodeMapping(node *cilium_v2.CiliumNode) []CESKey {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	return c.mapping.deleteNode(NodeName(node.Name))
}

func (c *slimManager) getEndpointEncryptionKey(node NodeName) (EncryptionKey, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return c.mapping.getEndpointEncryptionKey(node)
}

func getNodeEndpointEncryptionKey(node *cilium_v2.CiliumNode, ipsecEnabled, wgEnabled bool) EncryptionKey {
	switch {
	case wgEnabled:
		return EncryptionKey(wgtypes.StaticEncryptKey)
	case ipsecEnabled:
		return EncryptionKey(node.Spec.Encryption.Key)
	default:
		return 0
	}
}
