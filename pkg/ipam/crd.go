// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ipam

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/aws/metadata"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/informer"
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/trigger"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
)

var (
	sharedNodeStore *nodeStore
	initNodeStore   sync.Once
)

const (
	// customResourceUpdateRate is the maximum rate in which a custom
	// resource is updated
	customResourceUpdateRate = 15 * time.Second
)

// nodeStore represents a CiliumNode custom resource and binds the CR to a list
// of allocators
type nodeStore struct {
	// mutex protects access to all members of this struct
	mutex lock.RWMutex

	// ownNode is the last known version of the own node resource
	ownNode *ciliumv2.CiliumNode

	// allocators is a list of allocators tied to this custom resource
	allocators []*crdAllocator

	// refreshTrigger is the configured trigger to synchronize updates to
	// the custom resource with rate limiting
	refreshTrigger *trigger.Trigger

	// availableIPs is the cached version of all available IPs
	availableIPs map[Family]int
}

// newNodeStore initializes a new store which reflects the CiliumNode custom
// resource of the specified node name
func newNodeStore(nodeName string) *nodeStore {
	log.Infof("Subscribed to CiliumNode custom resource for node %s", nodeName)

	store := &nodeStore{
		allocators:   []*crdAllocator{},
		availableIPs: map[Family]int{},
	}
	ciliumClient := k8s.CiliumClient()

	if option.Config.AutoCreateCiliumNodeResource {
		nodeResource := &ciliumv2.CiliumNode{
			ObjectMeta: metav1.ObjectMeta{
				Name: node.GetName(),
			},
		}

		// Tie the CiliumNode custom resource lifecycle to the
		// lifecycle of the Kubernetes node
		if k8sNode, err := k8s.GetNode(k8s.Client(), node.GetName()); err != nil {
			log.Warning("Kubernetes node resource representing own node is not available, cannot set OwnerReference")
		} else {
			nodeResource.ObjectMeta.OwnerReferences = []metav1.OwnerReference{{
				APIVersion: "v1",
				Kind:       "Node",
				Name:       node.GetName(),
				UID:        k8sNode.UID,
			}}
		}

		if option.Config.IPAM == option.IPAMENI {
			instanceID, instanceType, availabilityZone, vpcID, err := metadata.GetInstanceMetadata()
			if err != nil {
				log.WithError(err).Fatal("Unable to retrieve InstanceID of own EC2 instance")
			}

			nodeResource.Spec.ENI.VpcID = vpcID
			nodeResource.Spec.ENI.FirstInterfaceIndex = 1
			nodeResource.Spec.ENI.DeleteOnTermination = true
			nodeResource.Spec.ENI.PreAllocate = defaults.ENIPreAllocation

			nodeResource.Spec.ENI.InstanceID = instanceID
			nodeResource.Spec.ENI.InstanceType = instanceType
			nodeResource.Spec.ENI.AvailabilityZone = availabilityZone
		}

		_, err := ciliumClient.CiliumV2().CiliumNodes("default").Create(nodeResource)
		if err != nil {
			log.WithError(err).Error("Unable to create CiliumNode resource")
		}
	}

	t, err := trigger.NewTrigger(trigger.Parameters{
		Name:        "crd-allocator-node-refresher",
		MinInterval: customResourceUpdateRate,
		TriggerFunc: store.refreshNodeTrigger,
	})
	if err != nil {
		log.WithError(err).Fatal("Unable to initialize trigger")
	}
	store.refreshTrigger = t

	ciliumNodeSelector := fields.ParseSelectorOrDie("metadata.name=" + nodeName)
	ciliumNodeStore := cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
	ciliumNodeInformer := informer.NewInformerWithStore(
		cache.NewListWatchFromClient(ciliumClient.CiliumV2().RESTClient(),
			"ciliumnodes", v1.NamespaceAll, ciliumNodeSelector),
		&ciliumv2.CiliumNode{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				if node, ok := obj.(*ciliumv2.CiliumNode); ok {
					log.Infof("New CiliumNode %+v", node)
					store.updateNodeResource(node)
				} else {
					log.Warningf("Unknown CiliumNode object received: %+v", obj)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				if node, ok := newObj.(*ciliumv2.CiliumNode); ok {
					log.Debugf("Updated CiliumNode %+v", node)
					store.updateNodeResource(node)
				} else {
					log.Warningf("Unknown CiliumNode object received: %+v", newObj)
				}
			},
			DeleteFunc: func(obj interface{}) {
				if node, ok := obj.(*ciliumv2.CiliumNode); ok {
					log.Debugf("Deleted CiliumNode %+v", node)
					store.updateNodeResource(nil)
				} else {
					log.Warningf("Unknown CiliumNode object received: %+v", obj)
				}
			},
		},
		func(obj interface{}) interface{} {
			cnp, _ := obj.(*ciliumv2.CiliumNode)
			return cnp
		},
		ciliumNodeStore,
	)

	go ciliumNodeInformer.Run(wait.NeverStop)

	log.Infof("Waiting for CiliumNode custom resource %s to become available...", nodeName)
	if ok := cache.WaitForCacheSync(wait.NeverStop, ciliumNodeInformer.HasSynced); !ok {
		log.Fatalf("Unable to synchronize CiliumNode custom resource for node %s", nodeName)
	} else {
		log.Infof("Successfully synchronized CiliumNode custom resource for node %s", nodeName)
	}

	for {
		minimumReached, required, numAvailable := store.hasMinimumIPsAvailable()
		if minimumReached {
			break
		}

		log.Infof("Waiting for %d/%d IPs to become available in '%s' custom resource", numAvailable, required, nodeName)
		time.Sleep(5 * time.Second)
	}

	store.refreshTrigger.TriggerWithReason("initial sync")

	return store
}

// hasMinimumIPsAvailable returns true if the required number of IPs is
// available
func (n *nodeStore) hasMinimumIPsAvailable() (minimumReached bool, required, numAvailable int) {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	if n.ownNode == nil {
		return
	}

	switch {
	case n.ownNode.Spec.ENI.MinAllocate != 0:
		required = n.ownNode.Spec.ENI.MinAllocate
	case n.ownNode.Spec.ENI.PreAllocate != 0:
		required = n.ownNode.Spec.ENI.PreAllocate
	case option.Config.EnableHealthChecking:
		required = 2
	default:
		required = 1
	}

	if n.ownNode.Spec.IPAM.Available != nil {
		numAvailable = len(n.ownNode.Spec.IPAM.Available)
		if len(n.ownNode.Spec.IPAM.Available) >= required {
			minimumReached = true
		}
	}
	return
}

// updateNodeResource updates the available IPs based on the custom resource
// passed into the function
func (n *nodeStore) updateNodeResource(node *ciliumv2.CiliumNode) {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	if node != nil {
		n.ownNode = node.DeepCopy()
		n.availableIPs[IPv4] = 0
		n.availableIPs[IPv6] = 0
		if node.Spec.IPAM.Available != nil {
			for ipString := range node.Spec.IPAM.Available {
				if ip := net.ParseIP(ipString); ip != nil {
					if ip.To4() != nil {
						n.availableIPs[IPv4]++
					} else {
						n.availableIPs[IPv6]++
					}
				}
			}
		}
	} else {
		n.ownNode = nil
	}
}

// refreshNodeTrigger is called to refresh the custom resource after taking the
// configured rate limiting into account
func (n *nodeStore) refreshNodeTrigger(reasons []string) {
	if err := n.refreshNode(); err != nil {
		log.WithError(err).Warning("Unable to update CiliumNode custom resource")
		n.refreshTrigger.TriggerWithReason("retry after error")
	}
}

// refreshNode updates the custom resource in the apiserver based on the latest
// information in the local node store
func (n *nodeStore) refreshNode() error {
	n.mutex.RLock()
	if n.ownNode == nil {
		n.mutex.RUnlock()
		return nil
	}

	node := n.ownNode.DeepCopy()
	staleCopyOfAllocators := make([]*crdAllocator, len(n.allocators))
	copy(staleCopyOfAllocators, n.allocators)
	n.mutex.RUnlock()

	node.Status.IPAM.InUse = map[string]ciliumv2.AllocationIP{}

	for _, a := range staleCopyOfAllocators {
		a.mutex.RLock()
		for ip, ipInfo := range a.allocated {
			node.Status.IPAM.InUse[ip] = ipInfo
		}
		a.mutex.RUnlock()
	}

	var err error
	k8sCapabilities := k8sversion.Capabilities()
	ciliumClient := k8s.CiliumClient()
	switch {
	case k8sCapabilities.UpdateStatus:
		_, err = ciliumClient.CiliumV2().CiliumNodes("default").UpdateStatus(node)
	default:
		_, err = ciliumClient.CiliumV2().CiliumNodes("default").Update(node)
	}

	return err
}

// addAllocator adds a new CRD allocator to the node store
func (n *nodeStore) addAllocator(allocator *crdAllocator) {
	n.mutex.Lock()
	n.allocators = append(n.allocators, allocator)
	n.mutex.Unlock()
}

// allocate checks if a particular IP can be allocated or return an error
func (n *nodeStore) allocate(ip net.IP) (*ciliumv2.AllocationIP, error) {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	if n.ownNode == nil {
		return nil, fmt.Errorf("CiliumNode for own node is not available")
	}

	if n.ownNode.Spec.IPAM.Available == nil {
		return nil, fmt.Errorf("No IPs available")
	}

	ipInfo, ok := n.ownNode.Spec.IPAM.Available[ip.String()]
	if !ok {
		return nil, fmt.Errorf("IP %s is not available", ip.String())
	}

	return &ipInfo, nil
}

// allocateNext allocates the next available IP or returns an error
func (n *nodeStore) allocateNext(allocated map[string]ciliumv2.AllocationIP, family Family) (net.IP, *ciliumv2.AllocationIP, error) {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	if n.ownNode == nil {
		return nil, nil, fmt.Errorf("CiliumNode for own node is not available")
	}

	// FIXME: This is currently using a brute-force method that can be
	// optimized
	for ip, ipInfo := range n.ownNode.Spec.IPAM.Available {
		if _, ok := allocated[ip]; !ok {
			parsedIP := net.ParseIP(ip)
			if parsedIP == nil {
				log.Warningf("Unable to parse IP %s in CiliumNode %s", ip, n.ownNode.Name)
				continue
			}

			if DeriveFamily(parsedIP) != family {
				continue
			}

			return parsedIP, &ipInfo, nil
		}
	}

	return nil, nil, fmt.Errorf("No more IPs available")
}

// numAvailableIPs returns the total number of available IPs as known to the
// node store
func (n *nodeStore) numAvailableIPs() int {
	if n.ownNode != nil {
		return len(n.ownNode.Spec.IPAM.Available)
	}
	return 0
}

// crdAllocator implements the CRD-backed IP allocator
type crdAllocator struct {
	// store is the node store backing the custom resource
	store *nodeStore

	// mutex protects access to the allocated map
	mutex lock.RWMutex

	// allocated is a map of all allocated IPs
	allocated map[string]ciliumv2.AllocationIP

	// family is the address family this allocator is allocator for
	family Family
}

// newCRDAllocator creates a new CRD-backed IP allocator
func newCRDAllocator(family Family) Allocator {
	initNodeStore.Do(func() {
		sharedNodeStore = newNodeStore(node.GetName())
	})

	allocator := &crdAllocator{
		allocated: map[string]ciliumv2.AllocationIP{},
		family:    family,
		store:     sharedNodeStore,
	}

	sharedNodeStore.addAllocator(allocator)

	return allocator
}

func deriveGatewayIP(eni ciliumv2.ENI) string {
	subnetIP, _, err := net.ParseCIDR(eni.Subnet.CIDR)
	if err != nil {
		log.WithError(err).Warningf("Unable to parse AWS subnet CIDR %s", eni.Subnet.CIDR)
		return ""
	}

	addr := subnetIP.To4()

	// The gateway for a subnet and VPC is always x.x.x.1
	// Ref: https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Route_Tables.html
	return net.IPv4(addr[0], addr[1], addr[2], addr[3]+1).String()
}

func (a *crdAllocator) buildAllocationResult(ip net.IP, ipInfo *ciliumv2.AllocationIP) (result *AllocationResult, err error) {
	result = &AllocationResult{IP: ip}

	// In ENI mode, the Resource points to the ENI so we can derive the
	// master interface and all CIDRs of the VPC
	if option.Config.IPAM == option.IPAMENI {
		a.store.mutex.RLock()
		defer a.store.mutex.RUnlock()

		if a.store.ownNode == nil {
			return
		}

		for _, eni := range a.store.ownNode.Status.ENI.ENIs {
			if eni.ID == ipInfo.Resource {
				result.Master = eni.MAC
				result.CIDRs = []string{eni.VPC.PrimaryCIDR}
				result.CIDRs = append(result.CIDRs, eni.VPC.CIDRs...)
				if eni.Subnet.CIDR != "" {
					result.GatewayIP = deriveGatewayIP(eni)
				}

				return
			}
		}

		result = nil
		err = fmt.Errorf("unable to find ENI %s", ipInfo.Resource)
	}

	return
}

// Allocate will attempt to find the specified ip in the custom resourec and
// allocate it if it is available, if the IP is unavailable or already
// allocated, an error is return. The custom resource will be updated to
// reflected the newly allocated IP.
func (a *crdAllocator) Allocate(ip net.IP, owner string) (*AllocationResult, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if _, ok := a.allocated[ip.String()]; ok {
		return nil, fmt.Errorf("IP already in use")
	}

	ipInfo, err := a.store.allocate(ip)
	if err != nil {
		return nil, err
	}

	a.markAllocated(ip, owner, *ipInfo)

	return a.buildAllocationResult(ip, ipInfo)
}

// Release will release the specified IP or return an error if the IP has not
// been allocated before. The custom resource will be updated to reflect the
// released IP.
func (a *crdAllocator) Release(ip net.IP) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if _, ok := a.allocated[ip.String()]; !ok {
		return fmt.Errorf("IP %s is not allocated", ip.String())
	}

	delete(a.allocated, ip.String())
	a.store.refreshTrigger.TriggerWithReason(fmt.Sprintf("release of IP %s", ip.String()))

	return nil
}

// markAllocated marks a particular IP as allocated and triggers the custom
// resource update
func (a *crdAllocator) markAllocated(ip net.IP, owner string, ipInfo ciliumv2.AllocationIP) {
	ipInfo.Owner = owner
	a.allocated[ip.String()] = ipInfo
	a.store.refreshTrigger.TriggerWithReason(fmt.Sprintf("allocation of IP %s", ip.String()))
}

// AllocateNext allocates the next avalable IP as offered by the custom
// resource or return an error if no IP is available. The custom resource will
// be updated to reflect the newly allocated IP.
func (a *crdAllocator) AllocateNext(owner string) (*AllocationResult, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	ip, ipInfo, err := a.store.allocateNext(a.allocated, a.family)
	if err != nil {
		return nil, err
	}

	a.markAllocated(ip, owner, *ipInfo)

	return a.buildAllocationResult(ip, ipInfo)
}

// totalAvailableIPs returns the total number of IPs available for allocation.
// a.mutex must be held
func (a *crdAllocator) totalAvailableIPs() int {
	if num, ok := a.store.availableIPs[a.family]; ok {
		return num
	}
	return 0
}

// Dump provides a status report and lists all allocated IP addressess
func (a *crdAllocator) Dump() (map[string]string, string) {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	allocs := map[string]string{}
	for ip := range a.allocated {
		allocs[ip] = ""
	}

	status := fmt.Sprintf("%d/%d allocated", len(allocs), a.totalAvailableIPs())
	return allocs, status
}
