// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/sirupsen/logrus"
)

var (
	// sequentialLetters contains lower case alphabets without vowels and few numbers.
	// skipped vowels and numbers [0, 1] to avoid generating controversial names.
	sequentialLetters = []rune("bcdfghjklmnpqrstvwxyz2456789")
)

// operations is an interface to all operations that a CES manager can perform.
type operations interface {
	// External APIs to Insert/Remove CEP in local dataStore
	UpdateCEPMapping(cep *cilium_v2.CoreCiliumEndpoint, ns string) []CESName
	RemoveCEPMapping(cep *cilium_v2.CoreCiliumEndpoint, ns string) CESName

	initializeMappingForCES(ces *cilium_v2.CiliumEndpointSlice) CESName
	initializeMappingCEPtoCES(cep *cilium_v2.CoreCiliumEndpoint, ns string, ces CESName)

	getCEPCountInCES(ces CESName) int
	getCEPinCES(ces CESName) []CEPName
	getCESData(ces CESName) CESData
	isCEPinCES(cep CEPName, ces CESName) bool
}

// cesMgr is used to batch CEP into a CES, based on FirstComeFirstServe. If a new CEP
// is inserted, then the CEP is queued in any one of the available CES. CEPs are
// inserted into CESs without any preference or any priority.
type cesMgr struct {
	// mapping is used to map CESName to CESTracker[i.e. list of CEPs],
	// as well as CEPName to CESName.
	mapping *CESToCEPMapping

	mutex lock.Mutex

	// maxCEPsInCES is the maximum number of CiliumCoreEndpoint(s) packed in
	// a CiliumEndpointSlice Resource.
	maxCEPsInCES int
}

// cesManagerFcfs use cesMgr by design, it inherits all the methods from the base cesMgr and there is no
// special handling required for cesManagerFcfs.
// cesManagerFcfs indicates ciliumEndpoints are batched based on FirstComeFirtServe algorithm.
// refer cesMgr comments for more information.
type cesManagerFcfs struct {
	cesMgr
}

// cesManagerIdentity is used to batch CEPs in CES based on CEP identity.
type cesManagerIdentity struct {
	cesMgr
	// CEP identity to cesTracker map
	identityToCES map[int64][]CESName
	// reverse map of identityToCES i.e. cesName to CEP identity
	cesToIdentity map[CESName]int64
}

// newCESManagerFcfs creates and initializes a new FirstComeFirstServe based CES
// manager, in this mode CEPs are batched based on FirstComeFirtServe algorithm.
func newCESManagerFcfs(maxCEPsInCES int) operations {
	return &cesManagerFcfs{
		cesMgr{
			mapping:      newCESToCEPMapping(),
			maxCEPsInCES: maxCEPsInCES,
		},
	}
}

// newCESManagerIdentity creates and initializes a new Identity based manager.
func newCESManagerIdentity(maxCEPsInCES int) operations {
	return &cesManagerIdentity{
		cesMgr: cesMgr{
			mapping:      newCESToCEPMapping(),
			maxCEPsInCES: maxCEPsInCES,
		},
		identityToCES: make(map[int64][]CESName),
		cesToIdentity: make(map[CESName]int64),
	}
}

// This function create a new ces and capacity to hold maximum ceps in a CES.
// This is called in 2 different scenarios:
//  1. During runtime, when ces manager decides to create a new ces, it calls
//     with an empty name, it generates a random unique name and assign it to the CES.
//  2. During operator warm boot [after crash or software upgrade], slicing manager
//     creates a CES, by passing unique name.
func (c *cesMgr) createCES(name, ns string) CESName {
	var cesName = name
	if name == "" {
		cesName = uniqueCESliceName(c.mapping)
	}
	c.mapping.insertCES(CESName(cesName), ns)
	log.WithFields(logrus.Fields{
		logfields.CESName: cesName,
	}).Debug("Generated CES")
	return CESName(cesName)
}

// UpdateCEPMapping is used to insert CEP in local cache, this may result in creating a new
// CES object or updating an existing CES object.
func (c *cesManagerFcfs) UpdateCEPMapping(cep *cilium_v2.CoreCiliumEndpoint, ns string) []CESName {
	log.WithFields(logrus.Fields{
		logfields.CEPName: GetCEPNameFromCCEP(cep, ns),
	}).Debug("Insert CEP in local cache")
	// check the given cep is already exists in any of the CES.
	// if yes, Update a ces with the given cep object.
	cepName := CEPName(GetCEPNameFromCCEP(cep, ns))
	cesName, exists := c.mapping.getCESName(cepName)
	if exists {
		log.WithFields(logrus.Fields{
			logfields.CEPName: cepName,
			logfields.CESName: cesName,
		}).Debug("CEP already mapped to CES")
		return []CESName{cesName}
	}

	// Get the largest available CES.
	// This ensures the minimum number of CES updates, as the CESs will be
	// consistently filled up in order.
	c.mutex.Lock()
	defer c.mutex.Unlock()
	cesName = c.getLargestAvailableCESForNamespace(ns)
	if cesName == "" {
		cesName = c.createCES("", ns)
	}
	c.mapping.insertCEP(cepName, cesName)
	log.WithFields(logrus.Fields{
		logfields.CEPName: cepName,
		logfields.CESName: cesName,
	}).Debug("CEP mapped to CES")
	return []CESName{cesName}
}

func (c *cesManagerFcfs) RemoveCEPMapping(cep *cilium_v2.CoreCiliumEndpoint, ns string) CESName {
	log.WithFields(logrus.Fields{
		logfields.CEPName: GetCEPNameFromCCEP(cep, ns),
	}).Debug("Removing CEP from local cache")
	cepName := CEPName(GetCEPNameFromCCEP(cep, ns))
	cesName, exists := c.mapping.getCESName(cepName)
	if exists {
		log.WithFields(logrus.Fields{
			logfields.CEPName: GetCEPNameFromCCEP(cep, ns),
			logfields.CESName: cesName,
		}).Debug("Removing CEP from CES")
		c.mapping.deleteCEP(cepName)
		if c.mapping.countCEPsInCES(cesName) == 0 {
			c.mutex.Lock()
			defer c.mutex.Unlock()
			if c.mapping.countCEPsInCES(cesName) == 0 {
				c.mapping.deleteCES(cesName)
			}
		}
		return cesName
	}
	return ""
}

// getLargestAvailableCESForNamespace returns the largest CES from cache for the
// specified namespace that has at least 1 CEP and 1 available spot (less than
// maximum CEPs). If it is not found, a nil is returned.
func (c *cesManagerFcfs) getLargestAvailableCESForNamespace(ns string) CESName {
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

// UpdateCEPMapping is used to insert CEP in local cache, this may result in creating a new
// CES object or updating an existing CES object. CEPs are grouped based on CEP identity.
func (c *cesManagerIdentity) UpdateCEPMapping(cep *cilium_v2.CoreCiliumEndpoint, ns string) []CESName {
	// check the given cep is already exists in any of the CES.
	// if yes, compare the given CEP Identity with the CEPs stored in CES.
	// If they are same UPDATE the CEP in the CES. This will trigger CES UPDATE to k8s-apiserver.
	// If the Identities differ, remove the CEP from the existing CES
	// and find a new CES to batch the given CEP in a CES. This will trigger following actions,
	// 1) CES UPDATE to k8s-apiserver, removing CEP in old CES
	// 2) CES CREATE to k8s-apiserver, inserting the given CEP in a new CES or
	// 3) CES UPDATE to k8s-apiserver, inserting the given CEP in existing CES
	log.WithFields(logrus.Fields{
		logfields.CEPName: GetCEPNameFromCCEP(cep, ns),
	}).Debug("Insert CEP in local cache")
	cepName := CEPName(GetCEPNameFromCCEP(cep, ns))
	var cesName CESName
	var exists bool
	removedFromCES := CESName("")
	if cesName, exists = c.mapping.getCESName(cepName); exists {
		if c.cesToIdentity[cesName] != cep.IdentityID {
			log.WithFields(logrus.Fields{
				logfields.CEPName: cepName,
				logfields.CESName: cesName,
			}).Debug("CEP already mapped to CES but identity has changed")
			removedFromCES = cesName
			c.mapping.deleteCEP(cepName)
		} else {
			log.WithFields(logrus.Fields{
				logfields.CEPName: cepName,
				logfields.CESName: cesName,
			}).Debug("CEP already mapped to CES")
			return []CESName{cesName}
		}
	}

	// If given cep object isn't packed in any of the CES. find a new ces
	// to pack this cep.
	c.mutex.Lock()
	defer c.mutex.Unlock()
	cesName = c.getLargestAvailableCESForIdentity(cep.IdentityID, ns)
	if cesName == "" {
		cesName = c.createCES("", ns)
		// Update the identityToCES and cesToIdentity maps respectively.
		c.identityToCES[cep.IdentityID] = append(c.identityToCES[cep.IdentityID], cesName)
		c.cesToIdentity[cesName] = cep.IdentityID
	}
	c.mapping.insertCEP(cepName, cesName)
	log.WithFields(logrus.Fields{
		logfields.CEPName: cepName,
		logfields.CESName: cesName,
	}).Debug("CEP mapped to CES")
	return []CESName{removedFromCES, cesName}
}

func (c *cesManagerIdentity) getLargestAvailableCESForIdentity(id int64, ns string) CESName {
	largestCEPCount := 0
	selectedCES := CESName("")
	if cess, exist := c.identityToCES[id]; exist {
		for _, ces := range cess {
			cepCount := c.mapping.countCEPsInCES(ces)
			if cepCount < c.maxCEPsInCES && cepCount > largestCEPCount && c.mapping.getCESData(ces).ns == ns {
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

func (c *cesManagerIdentity) RemoveCEPMapping(cep *cilium_v2.CoreCiliumEndpoint, ns string) CESName {
	log.WithFields(logrus.Fields{
		logfields.CEPName: GetCEPNameFromCCEP(cep, ns),
	}).Debug("Removing CEP from local cache")
	cepName := CEPName(GetCEPNameFromCCEP(cep, ns))
	cesName, exists := c.mapping.getCESName(cepName)
	if exists {
		log.WithFields(logrus.Fields{
			logfields.CEPName: GetCEPNameFromCCEP(cep, ns),
			logfields.CESName: cesName,
		}).Debug("Removing CEP from CES")
		c.mapping.deleteCEP(cepName)
		if c.mapping.countCEPsInCES(cesName) == 0 {
			c.mutex.Lock()
			defer c.mutex.Unlock()
			if c.mapping.countCEPsInCES(cesName) == 0 {
				c.removeCESToIdentity(cep.IdentityID, cesName)
				c.mapping.deleteCES(cesName)
			}
		}
		return cesName
	}
	return ""
}

func (c *cesManagerIdentity) removeCESToIdentity(id int64, cesName CESName) {
	cesSlice := c.identityToCES[id]
	for i, ces := range cesSlice {
		if ces == cesName {
			cesSlice[i] = cesSlice[len(cesSlice)-1]
		}
	}
	c.identityToCES[id] = cesSlice
	delete(c.cesToIdentity, cesName)
}

func (c *cesMgr) initializeMappingForCES(ces *cilium_v2.CiliumEndpointSlice) CESName {
	return c.createCES(ces.Name, ces.Namespace)
}

func (c *cesMgr) initializeMappingCEPtoCES(cep *cilium_v2.CoreCiliumEndpoint, ns string, ces CESName) {
	cepName := CEPName(GetCEPNameFromCCEP(cep, ns))
	c.mapping.insertCEP(cepName, ces)
}

func (c *cesMgr) getCEPCountInCES(ces CESName) int {
	return c.mapping.countCEPsInCES(ces)
}

func (c *cesMgr) getCESData(ces CESName) CESData {
	return c.mapping.getCESData(ces)
}

func (c *cesMgr) getCEPinCES(ces CESName) []CEPName {
	return c.mapping.getCEPsInCES(ces)
}

func (c *cesMgr) isCEPinCES(cep CEPName, ces CESName) bool {
	mappedCES, exists := c.mapping.getCESName(cep)
	return exists && string(mappedCES) == string(ces)
}
