// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumidentity

import (
	"strconv"

	"github.com/cilium/cilium/pkg/identity/key"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/lock"
)

// SecIDs is used to handle duplicate CIDs. Operator itself will not generate
// duplicate CIDs. This is required when migrating to Operator managing CIDs.
// Operator is compatible with Agents simultaneously managing CIDs.
type SecIDs struct {
	selectedID string
	ids        map[string]bool
}

type CIDState struct {
	// Maps CID name to a GlobalIdentity which holds labels.
	idToLabels map[string]*key.GlobalIdentity
	// Maps label string generated from GlobalIdentity.GetKey() to CID name.
	labelsToID map[string]*SecIDs
	mu         lock.RWMutex
}

func NewCIDState() *CIDState {
	cidState := &CIDState{
		idToLabels: make(map[string]*key.GlobalIdentity),
		labelsToID: make(map[string]*SecIDs),
	}

	return cidState
}

func (c *CIDState) Upsert(id string, k *key.GlobalIdentity) {
	if len(id) == 0 || k == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.idToLabels[id]; exists {
		return
	}

	c.idToLabels[id] = k
	c.addLabelsToID(id, k)
}

func (c *CIDState) addLabelsToID(id string, k *key.GlobalIdentity) {
	keyStr := k.GetKey()
	secIDs, exists := c.labelsToID[keyStr]
	if !exists || secIDs == nil {
		newSecIDs := &SecIDs{
			selectedID: id,
			ids:        make(map[string]bool),
		}
		c.labelsToID[keyStr] = newSecIDs
		secIDs = newSecIDs
	}

	secIDs.ids[id] = true
	if len(secIDs.selectedID) == 0 {
		secIDs.selectedID = id
	}
}

func (c *CIDState) Remove(id string) {
	if len(id) == 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	k, exists := c.idToLabels[id]
	if !exists {
		return
	}

	delete(c.idToLabels, id)
	c.removeLabelsToID(id, k)
}

func (c *CIDState) removeLabelsToID(id string, k *key.GlobalIdentity) {
	keyStr := k.GetKey()
	secIDs, exists := c.labelsToID[keyStr]
	if !exists {
		return
	}

	if secIDs == nil {
		delete(c.labelsToID, keyStr)
		return
	}

	delete(secIDs.ids, id)
	if len(secIDs.ids) == 0 {
		delete(c.labelsToID, keyStr)
		return
	}

	if secIDs.selectedID == id {
		for nextID := range secIDs.ids {
			secIDs.selectedID = nextID
			break
		}
	}
}

func (c *CIDState) LookupByID(id string) (*key.GlobalIdentity, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	k, exists := c.idToLabels[id]
	return k, exists
}

func (c *CIDState) LookupByKey(k *key.GlobalIdentity) (string, bool) {
	if k == nil {
		return "", false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	secIDs, exists := c.labelsToID[k.GetKey()]
	if !exists {
		return "", false
	}

	var id string
	if secIDs != nil {
		id = secIDs.selectedID
	}
	return id, true
}

type CIDUsageInPods struct {
	podToCID      map[string]string
	cidUsageCount map[string]int

	mu lock.RWMutex
}

func NewCIDUsageInPods() *CIDUsageInPods {
	return &CIDUsageInPods{
		podToCID:      make(map[string]string),
		cidUsageCount: make(map[string]int),
	}
}

// AssignCIDToPod updates the pod to CID map and increments the CID usage.
// It also decrements the previous CID usage and returns the CID name of
// previously set CID and its usage count after decrementing the CID usage.
// The return values are used to track when old CIDs are no longer used.
func (c *CIDUsageInPods) AssignCIDToPod(podName, cidName string) (string, int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var prevCIDUsageCount int
	prevCIDName, exists := c.podToCID[podName]
	if exists {
		if cidName == prevCIDName {
			return cidName, c.cidUsageCount[cidName]
		}

		prevCIDUsageCount = c.decrementUsage(prevCIDName)
	}

	c.podToCID[podName] = cidName
	c.cidUsageCount[cidName]++

	return prevCIDName, prevCIDUsageCount
}

// RemovePod removes the pod from the pod to CID map, decrements the CID usage
// and returns the CID name and its usage count after decrementing the usage.
// The return values are used to track when old CIDs are no longer used.
func (c *CIDUsageInPods) RemovePod(podName string) (string, int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	cidName, exists := c.podToCID[podName]
	if !exists {
		return "", 0
	}
	count := c.decrementUsage(cidName)
	delete(c.podToCID, podName)

	return cidName, count
}

func (c *CIDUsageInPods) CIDUsedByPod(podName string) (string, bool) {
	if len(podName) == 0 {
		return "", false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	cidName, exists := c.podToCID[podName]
	return cidName, exists
}

func (c *CIDUsageInPods) CIDUsageCount(cidName string) int {
	if len(cidName) == 0 {
		return 0
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.cidUsageCount[cidName]
}

// decrementUsage reduces the usage count for a CID and removes it from the map
// if the count is 0. Must be used only after aquiring the write lock.
func (c *CIDUsageInPods) decrementUsage(cidName string) int {
	c.cidUsageCount[cidName]--

	count := c.cidUsageCount[cidName]
	if count == 0 {
		delete(c.cidUsageCount, cidName)
	}

	return count
}

type CIDUsageInCES struct {
	cidUsageCount     map[int64]int
	prevCIDsUsedInCES map[string][]int64

	mu lock.RWMutex
}

func NewCIDUsageInCES() *CIDUsageInCES {
	return &CIDUsageInCES{
		cidUsageCount:     make(map[int64]int),
		prevCIDsUsedInCES: make(map[string][]int64),
	}
}

// ProcessCESUpsert updates the CID usage in CES based on the provided CES.
// When the CES is new, it will just add all used CIDs. When CES is updated, it
// uses previous CID usage for the same CES, that it tracks, to accordingly
// reduce CID usage in CES.
func (c *CIDUsageInCES) ProcessCESUpsert(ces *v2alpha1.CiliumEndpointSlice) []int64 {
	if ces == nil {
		return nil
	}

	var cidsWithNoCESUsage []int64

	c.mu.Lock()
	defer c.mu.Unlock()

	newUsedCIDs := make([]int64, len(ces.Endpoints))
	for i, cep := range ces.Endpoints {
		c.cidUsageCount[cep.IdentityID]++
		newUsedCIDs[i] = cep.IdentityID
	}

	for _, cid := range c.prevCIDsUsedInCES[ces.Name] {
		count := c.decrementUsage(cid)
		if count == 0 {
			cidsWithNoCESUsage = append(cidsWithNoCESUsage, cid)
		}
	}

	c.prevCIDsUsedInCES[ces.Name] = newUsedCIDs

	return cidsWithNoCESUsage
}

// ProcessCESUpsert reduces the CID usage in CES, based on the provided CES.
func (c *CIDUsageInCES) ProcessCESDelete(ces *v2alpha1.CiliumEndpointSlice) []int64 {
	if ces == nil {
		return nil
	}

	var cidsWithNoCESUsage []int64

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, cep := range ces.Endpoints {
		count := c.decrementUsage(cep.IdentityID)
		if count == 0 {
			cidsWithNoCESUsage = append(cidsWithNoCESUsage, cep.IdentityID)
		}
	}

	delete(c.prevCIDsUsedInCES, ces.Name)

	return cidsWithNoCESUsage
}

func (c *CIDUsageInCES) CIDUsageCount(cidName string) int {
	if len(cidName) == 0 {
		return 0
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	cidNum, err := strconv.Atoi(cidName)
	if err != nil {
		return 0
	}

	return c.cidUsageCount[int64(cidNum)]
}

// decrementUsage reduces the usage count for a CID and removes it from the map
// if the count is 0. Must be used only after aquiring the write lock.
func (c *CIDUsageInCES) decrementUsage(cidName int64) int {
	c.cidUsageCount[cidName]--
	count := c.cidUsageCount[cidName]

	if count == 0 {
		delete(c.cidUsageCount, cidName)
	}

	return count
}
