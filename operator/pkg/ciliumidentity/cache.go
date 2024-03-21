// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumidentity

import (
	"strconv"
	"time"

	"github.com/cilium/cilium/pkg/identity/key"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/sirupsen/logrus"
)

// SecIDs is used to handle duplicate CIDs. Operator itself will not generate
// duplicate CIDs. This is required when migrating to Operator managing CIDs.
// Operator is compatible with Agents simultaneously managing CIDs.
type SecIDs struct {
	selectedID string
	ids        map[string]struct{}
}

type CIDState struct {
	// Maps CID name to a GlobalIdentity which holds labels.
	idToLabels map[string]*key.GlobalIdentity
	// Maps label string generated from GlobalIdentity.GetKey() to CID name.
	labelsToID map[string]*SecIDs
	mu         lock.RWMutex

	logger logrus.FieldLogger
}

func NewCIDState(logger logrus.FieldLogger) *CIDState {
	cidState := &CIDState{
		idToLabels: make(map[string]*key.GlobalIdentity),
		labelsToID: make(map[string]*SecIDs),
		logger:     logger,
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

	c.logger.Infof("Upsert internal mapping between Cilium Identity %s and labels %s", id, k.Labels().String())

	c.idToLabels[id] = k

	keyStr := k.GetKey()
	secIDs, exists := c.labelsToID[keyStr]
	if !exists || secIDs == nil {
		c.labelsToID[keyStr] = &SecIDs{
			selectedID: id,
			ids:        map[string]struct{}{id: {}},
		}
		return
	}

	secIDs.ids[id] = struct{}{}
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

	c.logger.Infof("Remove internal mapping between Cilium Identity %s and labels %s", id, k.Labels().String())

	delete(c.idToLabels, id)

	keyStr := k.GetKey()
	secIDs := c.labelsToID[keyStr]

	delete(secIDs.ids, id)
	if len(secIDs.ids) == 0 {
		delete(c.labelsToID, keyStr)
		return
	}

	// After removing id, we need to set another one in selectedID by taking it
	// from the duplicates.
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

	return secIDs.selectedID, true
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
// and returns CID name, its usage count after decrementing the usage and if the
// pod is found in the cache.
// The return values are used to track when old CIDs are no longer used.
func (c *CIDUsageInPods) RemovePod(podName string) (string, int, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	cidName, exists := c.podToCID[podName]
	if !exists {
		return "", 0, false
	}
	count := c.decrementUsage(cidName)
	delete(c.podToCID, podName)

	return cidName, count, true
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
// if the count is 0. Must be used only after acquiring the write lock.
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
func (c *CIDUsageInCES) ProcessCESUpsert(cesName string, endpoints []v2alpha1.CoreCiliumEndpoint) []int64 {
	if cesName == "" {
		return nil
	}

	var cidsWithNoCESUsage []int64
	newUsedCIDs := make([]int64, len(endpoints))

	c.mu.Lock()
	defer c.mu.Unlock()

	for i, cep := range endpoints {
		c.cidUsageCount[cep.IdentityID]++
		newUsedCIDs[i] = cep.IdentityID
	}

	for _, cid := range c.prevCIDsUsedInCES[cesName] {
		count := c.decrementUsage(cid)
		if count == 0 {
			cidsWithNoCESUsage = append(cidsWithNoCESUsage, cid)
		}
	}

	c.prevCIDsUsedInCES[cesName] = newUsedCIDs

	return cidsWithNoCESUsage
}

// ProcessCESDelete reduces the CID usage in CES, based on the provided CES.
func (c *CIDUsageInCES) ProcessCESDelete(cesName string, endpoints []v2alpha1.CoreCiliumEndpoint) []int64 {
	if cesName == "" {
		return nil
	}

	var cidsWithNoCESUsage []int64

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, cep := range endpoints {
		count := c.decrementUsage(cep.IdentityID)
		if count == 0 {
			cidsWithNoCESUsage = append(cidsWithNoCESUsage, cep.IdentityID)
		}
	}

	delete(c.prevCIDsUsedInCES, cesName)

	return cidsWithNoCESUsage
}

func (c *CIDUsageInCES) CIDUsageCount(cidName string) int {
	if len(cidName) == 0 {
		return 0
	}

	cidNum, err := strconv.Atoi(cidName)
	if err != nil {
		return 0
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.cidUsageCount[int64(cidNum)]
}

// decrementUsage reduces the usage count for a CID and removes it from the map
// if the count is 0. Must be used only after acquiring the write lock.
func (c *CIDUsageInCES) decrementUsage(cidName int64) int {
	c.cidUsageCount[cidName]--
	count := c.cidUsageCount[cidName]

	if count == 0 {
		delete(c.cidUsageCount, cidName)
	}

	return count
}

type EnqueueTimeTracker struct {
	enqueuedAt map[string]time.Time
	mu         lock.Mutex
}

func (e *EnqueueTimeTracker) SetEnqueueTimeIfNotSet(item string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.enqueuedAt[item].IsZero() {
		e.enqueuedAt[item] = time.Now()
	}
}

func (e *EnqueueTimeTracker) GetEnqueueTimeAndReset(item string) (time.Time, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()

	enqueuedTime, exists := e.enqueuedAt[item]
	if !exists {
		return time.Time{}, false
	}

	delete(e.enqueuedAt, item)
	return enqueuedTime, true
}

// CIDDeletionTracker tracks which CIDs are marked for deletion.
// This is required for simultaneous CID management by both cilium-operator and
// cilium-agent.
type CIDDeletionTracker struct {
	markedForDeletion map[string]time.Time
	mu                lock.RWMutex

	logger logrus.FieldLogger
}

func NewCIDDeletionTracker(logger logrus.FieldLogger) *CIDDeletionTracker {
	return &CIDDeletionTracker{
		markedForDeletion: make(map[string]time.Time),
		logger:            logger,
	}
}

func (c *CIDDeletionTracker) Mark(cidName string) {
	if len(cidName) == 0 {
		return
	}

	c.logger.WithField(logfields.CIDName, cidName).Info("Add Cilium Identitiy deletion mark")

	c.mu.Lock()
	defer c.mu.Unlock()

	c.markedForDeletion[cidName] = time.Now()
}

func (c *CIDDeletionTracker) Unmark(cidName string) {
	if len(cidName) == 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.markedForDeletion[cidName]; !exists {
		return
	}

	c.logger.WithField(logfields.CIDName, cidName).Info("Remove Cilium Identity deletion mark")

	delete(c.markedForDeletion, cidName)
}

func (c *CIDDeletionTracker) MarkedTime(cidName string) (time.Time, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	markedTime, marked := c.markedForDeletion[cidName]
	return markedTime, marked
}
