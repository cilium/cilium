// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/ipam/types"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/watchers/subscriber"
	"github.com/cilium/cilium/pkg/lock"
)

type fakeK8sCiliumNodeAPI struct {
	mutex lock.Mutex
	node  *ciliumv2.CiliumNode
	sub   subscriber.CiliumNode

	onUpsertEvent func()
	onDeleteEvent func()
}

func (f *fakeK8sCiliumNodeAPI) RegisterCiliumNodeSubscriber(s subscriber.CiliumNode) {
	f.sub = s
}

// UpdateStatus implements nodeUpdater
func (f *fakeK8sCiliumNodeAPI) UpdateStatus(_ context.Context, ciliumNode *ciliumv2.CiliumNode, _ v1.UpdateOptions) (*ciliumv2.CiliumNode, error) {
	err := f.updateNode(ciliumNode)
	return ciliumNode, err
}

// UpdateStatus implements nodeUpdater
func (f *fakeK8sCiliumNodeAPI) Update(_ context.Context, ciliumNode *ciliumv2.CiliumNode, _ v1.UpdateOptions) (*ciliumv2.CiliumNode, error) {
	err := f.updateNode(ciliumNode)
	return ciliumNode, err
}

// currentNode returns a the current snapshot of the node
func (f *fakeK8sCiliumNodeAPI) currentNode() *ciliumv2.CiliumNode {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	return f.node.DeepCopy()
}

// updateNode is to be invoked by the test code to simulate updates by the operator
func (f *fakeK8sCiliumNodeAPI) updateNode(newNode *ciliumv2.CiliumNode) error {
	f.mutex.Lock()
	oldNode := f.node
	if oldNode == nil {
		f.mutex.Unlock()
		return fmt.Errorf("failed to update CiliumNode %q: node not found", newNode.Name)
	}
	f.node = newNode.DeepCopy()

	sub := f.sub
	onUpsertEvent := f.onUpsertEvent
	f.mutex.Unlock()

	var err error
	if sub != nil {
		err = sub.OnUpdateCiliumNode(oldNode, newNode, nil)
	}
	if onUpsertEvent != nil {
		onUpsertEvent()
	}

	return err
}

// deleteNode is to be invoked by the test code to simulate an unexpected node deletion
func (f *fakeK8sCiliumNodeAPI) deleteNode() error {
	f.mutex.Lock()
	oldNode := f.node
	f.node = nil

	sub := f.sub
	onDeleteEvent := f.onDeleteEvent
	f.mutex.Unlock()

	var err error
	if sub != nil {
		err = sub.OnDeleteCiliumNode(oldNode, nil)
	}
	if onDeleteEvent != nil {
		onDeleteEvent()
	}
	return err
}

func TestPodCIDRPool(t *testing.T) {
	for _, tc := range []struct {
		family       Family
		podCIDR      string
		capacity     int
		inRangeIP    net.IP
		outOfRangeIP net.IP
	}{
		{
			family:       IPv4,
			podCIDR:      "192.168.0.0/27",
			capacity:     30,
			inRangeIP:    net.ParseIP("192.168.0.1"),
			outOfRangeIP: net.ParseIP("10.0.0.1"),
		},
		{
			family:       IPv6,
			podCIDR:      "1::/123",
			capacity:     30,
			inRangeIP:    net.ParseIP("1::1"),
			outOfRangeIP: net.ParseIP("2::1"),
		},
	} {
		t.Run(string(tc.family), func(t *testing.T) {
			RegisterTestingT(t)

			p := newPodCIDRPool(nil)

			// Test behavior when empty.
			ip, err := p.allocateNext()
			Expect(err).To(HaveOccurred())
			Expect(ip).To(BeNil())
			ipToOwner, usedIPs, availableIPs, numPodCIDRs, err := p.dump()
			Expect(err).ToNot(HaveOccurred())
			Expect(ipToOwner).To(BeEmpty())
			Expect(usedIPs).To(BeZero())
			Expect(availableIPs).To(BeZero())
			Expect(numPodCIDRs).To(BeZero())
			Expect(p.hasAvailableIPs()).To(BeFalse())
			Expect(p.clusterPoolV2Beta1Status(0, 0)).To(Equal(types.PodCIDRMap{}))

			// Add pod CIDRs.
			p.updatePool([]string{tc.podCIDR})
			Expect(p.hasAvailableIPs()).To(BeTrue())
			Expect(p.clusterPoolV2Beta1Status(0, 0)).To(Equal(types.PodCIDRMap{
				tc.podCIDR: {
					Status: types.PodCIDRStatusInUse,
				},
			}))

			// Test allocating a fixed IP.
			Expect(p.allocate(tc.inRangeIP)).To(Succeed())
			ipToOwner, usedIPs, availableIPs, numPodCIDRs, err = p.dump()
			Expect(err).ToNot(HaveOccurred())
			Expect(ipToOwner).To(Equal(map[string]string{
				tc.inRangeIP.String(): "",
			}))
			Expect(usedIPs).To(Equal(1))
			Expect(availableIPs).To(Equal(tc.capacity - 1))
			Expect(numPodCIDRs).To(Equal(1))
			p.release(tc.inRangeIP)

			// Test allocating an out-of-range IP.
			Expect(p.allocate(tc.outOfRangeIP)).ShouldNot(Succeed())
			p.release(tc.outOfRangeIP)

			// Test allocation of all IPs.
			ips := allocateNextN(p, tc.capacity, nil)

			// Test behavior when full.
			Expect(p.hasAvailableIPs()).To(BeFalse())
			ip, err = p.allocateNext()
			Expect(err).To(HaveOccurred())
			Expect(ip).To(BeNil())
			Expect(p.clusterPoolV2Beta1Status(0, 0)).To(Equal(types.PodCIDRMap{
				tc.podCIDR: {
					Status: types.PodCIDRStatusDepleted,
				},
			}))

			// Test release of all IPs.
			for i, ip := range ips {
				p.release(ip)
				Expect(p.hasAvailableIPs()).To(BeTrue())
				expectedStatus := types.PodCIDRStatusInUse
				if i+1 < defaults.IPAMPodCIDRAllocationThreshold {
					expectedStatus = types.PodCIDRStatusDepleted
				}
				Expect(p.clusterPoolV2Beta1Status(0, 0)).To(Equal(types.PodCIDRMap{
					tc.podCIDR: {
						Status: expectedStatus,
					},
				}))
			}

			// Test release of all pod CIDRs.
			p.updatePool(nil)
			ip, err = p.allocateNext()
			Expect(err).To(HaveOccurred())
			Expect(ip).To(BeNil())
			Expect(p.hasAvailableIPs()).To(BeFalse())
			Expect(p.clusterPoolV2Beta1Status(0, 0)).To(Equal(types.PodCIDRMap{}))
		})
	}
}

func TestPodCIDRPoolTwoPools(t *testing.T) {
	for _, tc := range []struct {
		family    Family
		podCIDR1  string
		capacity1 int
		podCIDR2  string
		capacity2 int
	}{
		{
			family:    IPv4,
			podCIDR1:  "192.168.0.0/27",
			capacity1: 30,
			podCIDR2:  "10.0.0.0/27",
			capacity2: 30,
		},
		{
			family:    IPv6,
			podCIDR1:  "1::/123",
			capacity1: 30,
			podCIDR2:  "2::/123",
			capacity2: 30,
		},
	} {
		t.Run(string(tc.family), func(t *testing.T) {
			RegisterTestingT(t)

			p := newPodCIDRPool(nil)
			p.updatePool([]string{tc.podCIDR1})

			// Test behavior with no allocations.
			Expect(p.clusterPoolV2Beta1Status(0, 0)).To(Equal(types.PodCIDRMap{
				tc.podCIDR1: {
					Status: types.PodCIDRStatusInUse,
				},
			}))

			_, podCIDR1, err := net.ParseCIDR(tc.podCIDR1)
			Expect(err).ToNot(HaveOccurred())
			_, podCIDR2, err := net.ParseCIDR(tc.podCIDR2)
			Expect(err).ToNot(HaveOccurred())

			// Test allocation and release of a single IP.
			ip, err := p.allocateNext()
			Expect(err).ToNot(HaveOccurred())
			Expect(ip).ToNot(BeNil())
			Expect(podCIDR1.Contains(ip)).To(BeTrue())
			p.release(ip)

			// Test fully allocating the first pod CIDR.
			ips1 := allocateNextN(p, tc.capacity1, podCIDR1)
			Expect(p.clusterPoolV2Beta1Status(0, 0)).To(Equal(types.PodCIDRMap{
				tc.podCIDR1: {
					Status: types.PodCIDRStatusDepleted,
				},
			}))

			// Allocate the second pod CIDR.
			p.updatePool([]string{tc.podCIDR1, tc.podCIDR2})
			Expect(p.clusterPoolV2Beta1Status(0, 0)).To(Equal(types.PodCIDRMap{
				tc.podCIDR1: {
					Status: types.PodCIDRStatusDepleted,
				},
				tc.podCIDR2: {
					Status: types.PodCIDRStatusInUse,
				},
			}))

			// Test fully allocating the second pod CIDR.
			ips2 := allocateNextN(p, tc.capacity2, podCIDR2)
			Expect(p.clusterPoolV2Beta1Status(0, 0)).To(Equal(types.PodCIDRMap{
				tc.podCIDR1: {
					Status: types.PodCIDRStatusDepleted,
				},
				tc.podCIDR2: {
					Status: types.PodCIDRStatusDepleted,
				},
			}))

			// Test that IP addresses are allocated from the first pod CIDR by
			// preference.
			p.release(ips1[0])
			p.release(ips2[0])
			ip, err = p.allocateNext()
			Expect(err).ToNot(HaveOccurred())
			Expect(ip).To(Equal(ips1[0]))
			ip, err = p.allocateNext()
			Expect(err).ToNot(HaveOccurred())
			Expect(ip).To(Equal(ips2[0]))

			// Test fully releasing the second pod CIDR.
			releaseAll(p, ips2)
			Expect(p.clusterPoolV2Beta1Status(0, 0)).To(Equal(types.PodCIDRMap{
				tc.podCIDR1: {
					Status: types.PodCIDRStatusDepleted,
				},
				tc.podCIDR2: {
					Status: types.PodCIDRStatusInUse,
				},
			}))

			// Test fully releasing the first pod CIDR.
			for i, ip := range ips1 {
				p.release(ip)

				ipToOwner, usedIPs, availableIPs, numPodCIDRs, err := p.dump()
				Expect(err).ToNot(HaveOccurred())
				Expect(ipToOwner).ToNot(BeNil())
				Expect(usedIPs).To(Equal(tc.capacity1 - i - 1))
				Expect(availableIPs).ToNot(BeZero())
				Expect(numPodCIDRs).To(Equal(2))

				var expectedStatus2 types.PodCIDRStatus
				if i+1 < defaults.IPAMPodCIDRReleaseThreshold {
					expectedStatus2 = types.PodCIDRStatusInUse
				} else {
					expectedStatus2 = types.PodCIDRStatusReleased
				}
				Expect(p.clusterPoolV2Beta1Status(0, 0)).To(Equal(types.PodCIDRMap{
					tc.podCIDR1: {
						Status: types.PodCIDRStatusInUse,
					},
					tc.podCIDR2: {
						Status: expectedStatus2,
					},
				}))
			}
			Expect(p.clusterPoolV2Beta1Status(0, 0)).To(Equal(types.PodCIDRMap{
				tc.podCIDR1: {
					Status: types.PodCIDRStatusInUse,
				},
				tc.podCIDR2: {
					Status: types.PodCIDRStatusReleased,
				},
			}))

			// Release the second pod CIDR.
			p.updatePool([]string{tc.podCIDR1})
			Expect(p.clusterPoolV2Beta1Status(0, 0)).To(Equal(types.PodCIDRMap{
				tc.podCIDR1: {
					Status: types.PodCIDRStatusInUse,
				},
			}))
		})
	}
}

func TestPodCIDRPoolRemoveInUse(t *testing.T) {
	for _, tc := range []struct {
		name           string
		family         Family
		podCIDRs       []string
		allocate       int
		afterPodCIDRs  []string
		expectedStatus types.PodCIDRMap
	}{
		{
			name:   "remove_first_unused",
			family: IPv4,
			podCIDRs: []string{
				"192.168.0.0/27",
			},
			afterPodCIDRs:  []string{},
			allocate:       0,
			expectedStatus: types.PodCIDRMap{},
		},
		{
			name:   "remove_first_in_use",
			family: IPv4,
			podCIDRs: []string{
				"192.168.0.0/27",
			},
			afterPodCIDRs: []string{},
			allocate:      1,
			expectedStatus: types.PodCIDRMap{
				"192.168.0.0/27": {
					Status: types.PodCIDRStatusDepleted,
				},
			},
		},
		{
			name:   "remove_second_unused",
			family: IPv4,
			podCIDRs: []string{
				"192.168.0.0/27",
				"192.168.1.0/27",
			},
			allocate: 1,
			afterPodCIDRs: []string{
				"192.168.0.0/27",
			},
			expectedStatus: types.PodCIDRMap{
				"192.168.0.0/27": {
					Status: types.PodCIDRStatusInUse,
				},
			},
		},
		{
			name:   "remove_second_in_use",
			family: IPv4,
			podCIDRs: []string{
				"192.168.0.0/27",
				"192.168.1.0/27",
			},
			allocate: 31,
			afterPodCIDRs: []string{
				"192.168.0.0/27",
			},
			expectedStatus: types.PodCIDRMap{
				"192.168.0.0/27": {
					Status: types.PodCIDRStatusDepleted,
				},
				"192.168.1.0/27": {
					Status: types.PodCIDRStatusDepleted,
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			RegisterTestingT(t)

			p := newPodCIDRPool(nil)
			p.updatePool(tc.podCIDRs)
			_ = allocateNextN(p, tc.allocate, nil)
			p.updatePool(tc.afterPodCIDRs)
			Expect(p.clusterPoolV2Beta1Status(0, 0)).To(Equal(tc.expectedStatus))
		})
	}
}

func TestPodCIDRPoolRemoveInUseWithRelease(t *testing.T) {
	RegisterTestingT(t)

	p := newPodCIDRPool(nil)

	// Allocate IP from all pod CIDRs.
	p.updatePool([]string{
		"192.168.0.0/27",
		"192.168.1.0/27",
		"192.168.2.0/27",
	})
	_ = allocateNextN(p, 30, mustParseCIDR("192.168.0.0/27"))
	ip2s := allocateNextN(p, 30, mustParseCIDR("192.168.1.0/27"))
	_ = allocateNextN(p, 1, mustParseCIDR("192.168.2.0/27"))
	Expect(p.clusterPoolV2Beta1Status(0, 0)).To(Equal(types.PodCIDRMap{
		"192.168.0.0/27": {
			Status: types.PodCIDRStatusDepleted,
		},
		"192.168.1.0/27": {
			Status: types.PodCIDRStatusDepleted,
		},
		"192.168.2.0/27": {
			Status: types.PodCIDRStatusInUse,
		},
	}))

	// Remove the second pod CIDR, which is in use.
	p.updatePool([]string{
		"192.168.0.0/27",
		"192.168.2.0/27",
	})
	Expect(p.clusterPoolV2Beta1Status(0, 0)).To(Equal(types.PodCIDRMap{
		"192.168.0.0/27": {
			Status: types.PodCIDRStatusDepleted,
		},
		"192.168.1.0/27": {
			Status: types.PodCIDRStatusDepleted,
		},
		"192.168.2.0/27": {
			Status: types.PodCIDRStatusInUse,
		},
	}))

	// Remove an IP from the second pod CIDR.
	p.release(ip2s[0])

	// Test that new IPs are not allocated from the second pod CIDR.
	ip, err := p.allocateNext()
	Expect(err).ToNot(HaveOccurred())
	Expect(mustParseCIDR("192.168.2.0/27").Contains(ip)).To(BeTrue())

	// Remove all remaining IPs from the second pod CIDR.
	releaseAll(p, ip2s[1:])
	Expect(p.clusterPoolV2Beta1Status(0, 0)).To(Equal(types.PodCIDRMap{
		"192.168.0.0/27": {
			Status: types.PodCIDRStatusDepleted,
		},
		"192.168.1.0/27": {
			Status: types.PodCIDRStatusReleased,
		},
		"192.168.2.0/27": {
			Status: types.PodCIDRStatusInUse,
		},
	}))
}

func TestPodCIDRPoolDuplicatePodCIDRs(t *testing.T) {
	RegisterTestingT(t)

	// Test that duplicate pod CIDRs are ignored.
	p := newPodCIDRPool(nil)
	p.updatePool([]string{
		"192.168.0.0/27",
		"192.168.0.0/27",
	})
	Expect(p.clusterPoolV2Beta1Status(0, 0)).To(Equal(types.PodCIDRMap{
		"192.168.0.0/27": {
			Status: types.PodCIDRStatusInUse,
		},
	}))
}

func TestPodCIDRPoolSmallAlloc(t *testing.T) {
	RegisterTestingT(t)

	p := newPodCIDRPool(nil)

	// Test that when only a small CIDR is allocated, the CIDR is marked as
	// depleted.
	p.updatePool([]string{
		"192.168.0.0/30", // Add 2 IPs.
	})
	Expect(p.clusterPoolV2Beta1Status(0, 0)).To(Equal(types.PodCIDRMap{
		"192.168.0.0/30": {
			Status: types.PodCIDRStatusDepleted,
		},
	}))

	// Test that while the number of available IPs is less than the depleted
	// threshold, all CIDRs are marked as depleted.
	p.updatePool([]string{
		"192.168.0.0/30", // Add 2 IPs.
		"192.168.1.0/30", // Add 2 IPs.
	})
	Expect(p.clusterPoolV2Beta1Status(0, 0)).To(Equal(types.PodCIDRMap{
		"192.168.0.0/30": {
			Status: types.PodCIDRStatusDepleted,
		},
		"192.168.1.0/30": {
			Status: types.PodCIDRStatusDepleted,
		},
	}))

	// Test that when the number of available IPs reaches the depleted
	// threshold, all CIDRs are marked as in use.
	p.updatePool([]string{
		"192.168.0.0/30", // Add 2 IPs.
		"192.168.1.0/30", // Add 2 IPs.
		"192.168.2.0/30", // Add 2 IPs.
		"192.168.3.0/30", // Add 2 IPs.
	})
	Expect(p.clusterPoolV2Beta1Status(0, 0)).To(Equal(types.PodCIDRMap{
		"192.168.0.0/30": {
			Status: types.PodCIDRStatusInUse,
		},
		"192.168.1.0/30": {
			Status: types.PodCIDRStatusInUse,
		},
		"192.168.2.0/30": {
			Status: types.PodCIDRStatusInUse,
		},
		"192.168.3.0/30": {
			Status: types.PodCIDRStatusInUse,
		},
	}))

	// Test that when a larger CIDR is allocated, the smaller CIDRs are marked as released.
	p.updatePool([]string{
		"192.168.0.0/30", // Add 2 IPs.
		"192.168.1.0/30", // Add 2 IPs.
		"192.168.2.0/30", // Add 2 IPs.
		"192.168.3.0/30", // Add 2 IPs.
		"192.168.4.0/27", // Add 30 IPs.
	})
	Expect(p.clusterPoolV2Beta1Status(0, 0)).To(Equal(types.PodCIDRMap{
		"192.168.0.0/30": {
			Status: types.PodCIDRStatusReleased,
		},
		"192.168.1.0/30": {
			Status: types.PodCIDRStatusReleased,
		},
		"192.168.2.0/30": {
			Status: types.PodCIDRStatusReleased,
		},
		"192.168.3.0/30": {
			Status: types.PodCIDRStatusReleased,
		},
		"192.168.4.0/27": {
			Status: types.PodCIDRStatusInUse,
		},
	}))
}

func TestPodCIDRPoolTooSmallAlloc(t *testing.T) {
	RegisterTestingT(t)

	p := newPodCIDRPool(nil)

	// Test that when only a small CIDR is allocated, the CIDR is immediately
	// released.
	p.updatePool([]string{
		"192.168.0.0/32", // 0 IPs.
	})
	Expect(p.clusterPoolV2Beta1Status(0, 0)).To(Equal(types.PodCIDRMap{
		"192.168.0.0/32": {
			Status: types.PodCIDRStatusReleased,
		},
	}))
	p.updatePool([]string{
		"192.168.0.0/31", // 0 IPs.
	})
	Expect(p.clusterPoolV2Beta1Status(0, 0)).To(Equal(types.PodCIDRMap{
		"192.168.0.0/31": {
			Status: types.PodCIDRStatusReleased,
		},
	}))

}

func TestNewCRDWatcher(t *testing.T) {
	for _, tc := range []struct {
		family    Family
		podCIDR1  string
		capacity1 int
		podCIDR2  string
		capacity2 int
	}{
		{
			family:    IPv4,
			podCIDR1:  "0.0.0.0/27",
			capacity1: 30,
			podCIDR2:  "1.0.0.0/27",
			capacity2: 30,
		},
		{
			family:    IPv6,
			podCIDR1:  "1::/123",
			capacity1: 30,
			podCIDR2:  "2::/123",
			capacity2: 30,
		},
	} {
		t.Run(string(tc.family), func(t *testing.T) {
			RegisterTestingT(t)

			fakeConfig := &testConfiguration{}
			fakeK8sEventRegister := &ownerMock{}
			events := make(chan string, 1)
			fakeK8sCiliumNodeAPI := &fakeK8sCiliumNodeAPI{
				node: &ciliumv2.CiliumNode{},
				onDeleteEvent: func() {
					events <- "delete"
				},
				onUpsertEvent: func() {
					events <- "upsert"
				},
			}

			// Test that the watcher updates the CiliumNode CRD.
			c := newCRDWatcher(fakeConfig, fakeK8sCiliumNodeAPI, fakeK8sEventRegister, fakeK8sCiliumNodeAPI)
			c.localNodeUpdated(&ciliumv2.CiliumNode{
				Spec: ciliumv2.NodeSpec{
					IPAM: types.IPAMSpec{
						PodCIDRs: []string{
							tc.podCIDR1,
						},
					},
				},
			})
			pool := <-c.waitForPool(tc.family)
			c.restoreFinished()
			Expect(<-events).To(Equal("upsert"))
			Expect(fakeK8sCiliumNodeAPI.currentNode()).NotTo(BeNil())
			Expect(fakeK8sCiliumNodeAPI.currentNode().Status.IPAM.PodCIDRs).To(Equal(types.PodCIDRMap{
				tc.podCIDR1: types.PodCIDRMapEntry{
					Status: types.PodCIDRStatusInUse,
				},
			}))

			// Deplete all IPs in the first pod CIDR.
			ip1s := allocateNextN(pool, tc.capacity1, nil)
			c.controller.TriggerController(clusterPoolStatusControllerName)
			Expect(<-events).To(Equal("upsert"))
			Expect(fakeK8sCiliumNodeAPI.currentNode().Status.IPAM.PodCIDRs).To(Equal(types.PodCIDRMap{
				tc.podCIDR1: types.PodCIDRMapEntry{
					Status: types.PodCIDRStatusDepleted,
				},
			}))

			// Allocate the second pod CIDR.
			c.localNodeUpdated(&ciliumv2.CiliumNode{
				Spec: ciliumv2.NodeSpec{
					IPAM: types.IPAMSpec{
						PodCIDRs: []string{
							tc.podCIDR1,
							tc.podCIDR2,
						},
					},
				},
			})
			c.controller.TriggerController(clusterPoolStatusControllerName)
			Expect(<-events).To(Equal("upsert"))
			Expect(fakeK8sCiliumNodeAPI.currentNode().Status.IPAM.PodCIDRs).To(Equal(types.PodCIDRMap{
				tc.podCIDR1: types.PodCIDRMapEntry{
					Status: types.PodCIDRStatusDepleted,
				},
				tc.podCIDR2: types.PodCIDRMapEntry{
					Status: types.PodCIDRStatusInUse,
				},
			}))

			// Allocate all IPs in the second pod CIDR.
			ip2s := allocateNextN(pool, tc.capacity2, nil)
			c.controller.TriggerController(clusterPoolStatusControllerName)
			Expect(<-events).To(Equal("upsert"))
			Expect(fakeK8sCiliumNodeAPI.currentNode().Status.IPAM.PodCIDRs).To(Equal(types.PodCIDRMap{
				tc.podCIDR1: types.PodCIDRMapEntry{
					Status: types.PodCIDRStatusDepleted,
				},
				tc.podCIDR2: types.PodCIDRMapEntry{
					Status: types.PodCIDRStatusDepleted,
				},
			}))

			// Release all IPs in the second pod CIDR.
			releaseAll(pool, ip2s)
			c.controller.TriggerController(clusterPoolStatusControllerName)
			Expect(<-events).To(Equal("upsert"))
			Expect(fakeK8sCiliumNodeAPI.currentNode().Status.IPAM.PodCIDRs).To(Equal(types.PodCIDRMap{
				tc.podCIDR1: types.PodCIDRMapEntry{
					Status: types.PodCIDRStatusDepleted,
				},
				tc.podCIDR2: types.PodCIDRMapEntry{
					Status: types.PodCIDRStatusInUse,
				},
			}))

			// Release all IPs in the first pod CIDR.
			releaseAll(pool, ip1s)
			c.controller.TriggerController(clusterPoolStatusControllerName)
			Expect(<-events).To(Equal("upsert"))
			Expect(fakeK8sCiliumNodeAPI.currentNode().Status.IPAM.PodCIDRs).To(Equal(types.PodCIDRMap{
				tc.podCIDR1: types.PodCIDRMapEntry{
					Status: types.PodCIDRStatusInUse,
				},
				tc.podCIDR2: types.PodCIDRMapEntry{
					Status: types.PodCIDRStatusReleased,
				},
			}))

			// Deallocate the second pod CIDR.
			c.localNodeUpdated(&ciliumv2.CiliumNode{
				Spec: ciliumv2.NodeSpec{
					IPAM: types.IPAMSpec{
						PodCIDRs: []string{
							tc.podCIDR1,
						},
					},
				},
			})
			c.controller.TriggerController(clusterPoolStatusControllerName)
			Expect(<-events).To(Equal("upsert"))
			Expect(fakeK8sCiliumNodeAPI.currentNode().Status.IPAM.PodCIDRs).To(Equal(types.PodCIDRMap{
				tc.podCIDR1: types.PodCIDRMapEntry{
					Status: types.PodCIDRStatusInUse,
				},
			}))

			// Delete the node.
			fakeK8sCiliumNodeAPI.deleteNode()
			c.controller.TriggerController(clusterPoolStatusControllerName)
			Expect(<-events).To(Equal("delete"))
			Expect(fakeK8sCiliumNodeAPI.currentNode()).To(BeNil())
		})
	}
}

func TestNewCRDWatcher_restoreFinished(t *testing.T) {
	RegisterTestingT(t)

	fakeConfig := &testConfiguration{}
	fakeK8sEventRegister := &ownerMock{}
	events := make(chan string, 1)
	fakeK8sCiliumNodeAPI := &fakeK8sCiliumNodeAPI{
		node: &ciliumv2.CiliumNode{},
		onDeleteEvent: func() {
			events <- "delete"
		},
		onUpsertEvent: func() {
			events <- "upsert"
		},
	}

	c := newCRDWatcher(fakeConfig, fakeK8sEventRegister, fakeK8sEventRegister, fakeK8sCiliumNodeAPI)
	c.localNodeUpdated(&ciliumv2.CiliumNode{
		Spec: ciliumv2.NodeSpec{
			IPAM: types.IPAMSpec{
				PodCIDRs: []string{
					"192.168.0.0/24",
					"192.168.1.0/24",
				},
			},
		},
	})

	// Test CiliumNode CRD is _not_ updated before restoredFinished is called
	c.triggerWithReason("unit test")
	select {
	case e := <-events:
		t.Fatalf("received unexpected event %q", e)
	case <-time.After(10 * time.Millisecond):
	}
	Expect(fakeK8sCiliumNodeAPI.currentNode()).To(Equal(&ciliumv2.CiliumNode{}))

	// Test CiliumNode CRD is updated after restore has finished
	c.restoreFinished()
	Expect(<-events).To(Equal("upsert"))
	Expect(fakeK8sCiliumNodeAPI.currentNode().Status.IPAM.PodCIDRs).To(Equal(types.PodCIDRMap{
		"192.168.0.0/24": types.PodCIDRMapEntry{
			Status: types.PodCIDRStatusInUse,
		},
		"192.168.1.0/24": types.PodCIDRMapEntry{
			Status: types.PodCIDRStatusReleased,
		},
	}))
}

// allocateNextN allocates the next n IPs from pool. If cidr is not nil then it
// expects that it will contain all allocated IPs.
func allocateNextN(p *podCIDRPool, n int, cidr *net.IPNet) []net.IP {
	ips := make([]net.IP, 0, n)
	for i := 0; i < n; i++ {
		ip, err := p.allocateNext()
		Expect(err).ToNot(HaveOccurred())
		Expect(ip).ToNot(BeNil())
		if cidr != nil {
			Expect(cidr.Contains(ip)).To(BeTrue())
		}
		ips = append(ips, ip)
	}
	return ips
}

// mustParseCIDR parses a CIDR from s.
func mustParseCIDR(s string) *net.IPNet {
	_, cidr, err := net.ParseCIDR(s)
	Expect(err).ToNot(HaveOccurred())
	return cidr
}

// releaseAll releases ips from the pool. It expects that all releases succeed.
func releaseAll(p *podCIDRPool, ips []net.IP) {
	for _, ip := range ips {
		p.release(ip)
	}
}
