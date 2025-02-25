// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"log/slog"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	// sequentialLetters contains lower case alphabets without vowels and few numbers.
	// skipped vowels and numbers [0, 1] to avoid generating controversial names.
	sequentialLetters = []rune("bcdfghjklmnpqrstvwxyz2456789")
)

// operations is an interface to all operations that a CES manager can perform.
type operations interface {
	// External APIs to Insert/Remove CEP in local dataStore
	UpdateCEPMapping(cep *cilium_v2.CoreCiliumEndpoint, ns string) []CESKey
	RemoveCEPMapping(cep *cilium_v2.CoreCiliumEndpoint, ns string) CESKey

	initializeMappingForCES(ces *cilium_v2.CiliumEndpointSlice) CESName
	initializeMappingCEPtoCES(cep *cilium_v2.CoreCiliumEndpoint, ns string, ces CESName)

	getCEPCountInCES(ces CESName) int
	getCEPinCES(ces CESName) []CEPName
	getCESData(ces CESName) CESData
	isCEPinCES(cep CEPName, ces CESName) bool
}

// cesManager is used to batch CEP into a CES, based on FirstComeFirstServe. If a new CEP
// is inserted, then the CEP is queued in any one of the available CES. CEPs are
// inserted into CESs without any preference or any priority.
type cesManager struct {
	logger *slog.Logger
	// mapping is used to map CESName to CESTracker[i.e. list of CEPs],
	// as well as CEPName to CESName.
	mapping *CESToCEPMapping

	// maxCEPsInCES is the maximum number of CiliumCoreEndpoint(s) packed in
	// a CiliumEndpointSlice Resource.
	maxCEPsInCES int
}

// newCESManager creates and initializes a new FirstComeFirstServe based CES
// manager, in this mode CEPs are batched based on FirstComeFirtServe algorithm.
func newCESManager(maxCEPsInCES int, logger *slog.Logger) operations {
	return &cesManager{
		logger:       logger,
		mapping:      newCESToCEPMapping(),
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

// UpdateCEPMapping is used to insert CEP in local cache, this may result in creating a new
// CES object or updating an existing CES object.
func (c *cesManager) UpdateCEPMapping(cep *cilium_v2.CoreCiliumEndpoint, ns string) []CESKey {
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

func (c *cesManager) RemoveCEPMapping(cep *cilium_v2.CoreCiliumEndpoint, ns string) CESKey {
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
func (c *cesManager) getLargestAvailableCESForNamespace(ns string) CESName {
	largestCEPCount := 0
	selectedCES := CESName("")
	for _, ces := range c.mapping.getAllCESs() {
		cepCount := c.mapping.countCEPsInCES(ces)
		if cepCount < c.maxCEPsInCES && cepCount > largestCEPCount && c.mapping.getCESData(ces).ns == ns {
			selectedCES = ces
			largestCEPCount = cepCount
			if largestCEPCount == c.maxCEPsInCES-1 {
				break
			}
		}
	}
	return selectedCES
}

func (c *cesManager) initializeMappingForCES(ces *cilium_v2.CiliumEndpointSlice) CESName {
	return c.createCES(ces.Name, ces.Namespace)
}

func (c *cesManager) initializeMappingCEPtoCES(cep *cilium_v2.CoreCiliumEndpoint, ns string, ces CESName) {
	cepName := GetCEPNameFromCCEP(cep, ns)
	c.mapping.insertCEP(cepName, ces)
}

func (c *cesManager) getCEPCountInCES(ces CESName) int {
	return c.mapping.countCEPsInCES(ces)
}

func (c *cesManager) getCESData(ces CESName) CESData {
	return c.mapping.getCESData(ces)
}

func (c *cesManager) getCEPinCES(ces CESName) []CEPName {
	return c.mapping.getCEPsInCES(ces)
}

func (c *cesManager) isCEPinCES(cep CEPName, ces CESName) bool {
	mappedCES, exists := c.mapping.getCESName(cep)
	return exists && mappedCES == ces
}
