// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mock

import (
	"fmt"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/trigger"
)

type mockMetrics struct {
	mutex                 lock.RWMutex
	allocationAttempts    map[string]histogram
	releaseAttempts       map[string]histogram
	ipAllocations         map[string]int64
	ipReleases            map[string]int64
	interfaceAllocations  map[string]int64
	allocatedIPs          map[string]int
	availableInterfaces   int
	interfaceCandidates   int
	emptyInterfaceSlots   int
	availableIPsPerSubnet map[string]int
	nodes                 map[string]int
	resyncCount           int64
	nodeIPAvailable       map[string]int
	nodeIPUsed            map[string]int
	nodeIPNeeded          map[string]int
}

type histogram struct {
	count int64
	sum   float64
}

// NewMockMetrics returns a new metrics implementation with a mocked backend
func NewMockMetrics() *mockMetrics {
	return &mockMetrics{
		allocationAttempts:    map[string]histogram{},
		releaseAttempts:       map[string]histogram{},
		interfaceAllocations:  map[string]int64{},
		ipAllocations:         map[string]int64{},
		ipReleases:            map[string]int64{},
		allocatedIPs:          map[string]int{},
		nodes:                 map[string]int{},
		availableIPsPerSubnet: map[string]int{},
		nodeIPAvailable:       map[string]int{},
		nodeIPUsed:            map[string]int{},
		nodeIPNeeded:          map[string]int{},
	}
}

func (m *mockMetrics) GetAllocationAttempts(typ, status, subnetID string) int64 {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.allocationAttempts[fmt.Sprintf("type=%s, status=%s, subnetId=%s", typ, status, subnetID)].count
}

func (m *mockMetrics) AllocationAttempt(typ, status, subnetID string, observer float64) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	key := fmt.Sprintf("type=%s, status=%s, subnetId=%s", typ, status, subnetID)
	value := m.allocationAttempts[key]
	value.count++
	value.sum += observer
	m.allocationAttempts[key] = value
}

func (m *mockMetrics) ReleaseAttempt(typ, status, subnetID string, observer float64) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	key := fmt.Sprintf("type=%s, status=%s, subnetId=%s", typ, status, subnetID)
	value := m.releaseAttempts[key]
	value.count++
	value.sum += observer
	m.releaseAttempts[key] = value
}

func (m *mockMetrics) IncInterfaceAllocation(subnetID string) {
	m.mutex.Lock()
	m.interfaceAllocations[fmt.Sprintf("subnetId=%s", subnetID)]++
	m.mutex.Unlock()
}

func (m *mockMetrics) IPAllocations(subnetID string) int64 {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.ipAllocations["subnetId="+subnetID]
}

func (m *mockMetrics) AddIPAllocation(subnetID string, allocated int64) {
	m.mutex.Lock()
	m.ipAllocations["subnetId="+subnetID] += allocated
	m.mutex.Unlock()
}

func (m *mockMetrics) AddIPRelease(subnetID string, released int64) {
	m.mutex.Lock()
	m.ipReleases["subnetId="+subnetID] += released
	m.mutex.Unlock()
}

func (m *mockMetrics) AllocatedIPs(typ string) int {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.allocatedIPs[typ]
}

func (m *mockMetrics) SetAllocatedIPs(typ string, allocated int) {
	m.mutex.Lock()
	m.allocatedIPs[typ] = allocated
	m.mutex.Unlock()
}

func (m *mockMetrics) AvailableInterfaces() int {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.availableInterfaces
}

func (m *mockMetrics) SetAvailableInterfaces(available int) {
	m.mutex.Lock()
	m.availableInterfaces = available
	m.mutex.Unlock()
}

func (m *mockMetrics) InterfaceCandidates() int {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.interfaceCandidates
}

func (m *mockMetrics) SetInterfaceCandidates(interfaceCandidates int) {
	m.mutex.Lock()
	m.interfaceCandidates = interfaceCandidates
	m.mutex.Unlock()
}

func (m *mockMetrics) EmptyInterfaceSlots() int {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.emptyInterfaceSlots
}

func (m *mockMetrics) SetEmptyInterfaceSlots(emptyInterfaceSlots int) {
	m.mutex.Lock()
	m.emptyInterfaceSlots = emptyInterfaceSlots
	m.mutex.Unlock()
}

func (m *mockMetrics) Nodes(category string) int {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.nodes[category]
}

func (m *mockMetrics) SetNodes(category string, nodes int) {
	m.mutex.Lock()
	m.nodes[category] = nodes
	m.mutex.Unlock()
}

func (m *mockMetrics) SetAvailableIPsPerSubnet(subnetID, availabilityZone string, available int) {
	m.mutex.Lock()
	m.availableIPsPerSubnet[fmt.Sprintf("subnetId=%s, availabilityZone=%s", subnetID, availabilityZone)] = available
	m.mutex.Unlock()
}

func (m *mockMetrics) ResyncCount() int64 {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return m.resyncCount
}

func (m *mockMetrics) IncResyncCount() {
	m.mutex.Lock()
	m.resyncCount++
	m.mutex.Unlock()
}

func (m *mockMetrics) SetIPAvailable(s string, n int) {
	m.mutex.Lock()
	m.nodeIPAvailable[s] = n
	m.mutex.Unlock()
}

func (m *mockMetrics) SetIPUsed(s string, n int) {
	m.mutex.Lock()
	m.nodeIPUsed[s] = n
	m.mutex.Unlock()
}

func (m *mockMetrics) SetIPNeeded(s string, n int) {
	m.mutex.Lock()
	m.nodeIPNeeded[s] = n
	m.mutex.Unlock()
}

func (m *mockMetrics) PoolMaintainerTrigger() trigger.MetricsObserver {
	return nil
}

func (m *mockMetrics) K8sSyncTrigger() trigger.MetricsObserver {
	return nil
}

func (m *mockMetrics) ResyncTrigger() trigger.MetricsObserver {
	return nil
}
