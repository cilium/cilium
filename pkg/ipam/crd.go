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
	"reflect"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/informer"
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/trigger"

	"github.com/sirupsen/logrus"
	"k8s.io/api/core/v1"
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

	fieldName = "name"
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

	// allocationPoolSize is the size of the IP pool for each address
	// family
	allocationPoolSize map[Family]int

	// signal for completion of restoration
	restoreFinished chan bool
}

// newNodeStore initializes a new store which reflects the CiliumNode custom
// resource of the specified node name
func newNodeStore(nodeName string, owner Owner, k8sEventReg K8sEventRegister) *nodeStore {
	log.WithField(fieldName, nodeName).Info("Subscribed to CiliumNode custom resource")

	store := &nodeStore{
		allocators:         []*crdAllocator{},
		allocationPoolSize: map[Family]int{},
	}
	store.restoreFinished = make(chan bool)
	ciliumClient := k8s.CiliumClient()

	t, err := trigger.NewTrigger(trigger.Parameters{
		Name:        "crd-allocator-node-refresher",
		MinInterval: customResourceUpdateRate,
		TriggerFunc: store.refreshNodeTrigger,
	})
	if err != nil {
		log.WithError(err).Fatal("Unable to initialize CiliumNode synchronization trigger")
	}
	store.refreshTrigger = t

	// Create the CiliumNode custom resource. This call will block until
	// the custom resource has been created
	owner.UpdateCiliumNodeResource()

	ciliumNodeSelector := fields.ParseSelectorOrDie("metadata.name=" + nodeName)
	ciliumNodeStore := cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
	ciliumNodeInformer := informer.NewInformerWithStore(
		cache.NewListWatchFromClient(ciliumClient.CiliumV2().RESTClient(),
			"ciliumnodes", v1.NamespaceAll, ciliumNodeSelector),
		&ciliumv2.CiliumNode{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k8sEventReg.K8sEventReceived("CiliumNode", "create", valid, equal) }()
				if node, ok := obj.(*ciliumv2.CiliumNode); ok {
					valid = true
					store.updateLocalNodeResource(node.DeepCopy())
					k8sEventReg.K8sEventProcessed("CiliumNode", "create", true)
				} else {
					log.Warningf("Unknown CiliumNode object type %s received: %+v", reflect.TypeOf(obj), obj)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				var valid, equal bool
				defer func() { k8sEventReg.K8sEventReceived("CiliumNode", "update", valid, equal) }()
				if node, ok := newObj.(*ciliumv2.CiliumNode); ok {
					valid = true
					store.updateLocalNodeResource(node.DeepCopy())
					k8sEventReg.K8sEventProcessed("CiliumNode", "update", true)
				} else {
					log.Warningf("Unknown CiliumNode object type %s received: %+v", reflect.TypeOf(newObj), newObj)
				}
			},
			DeleteFunc: func(obj interface{}) {
				// Given we are watching a single specific
				// resource using the node name, any delete
				// notification means that the resource
				// matching the local node name has been
				// removed. No attempt to cast is required.
				store.deleteLocalNodeResource()
				k8sEventReg.K8sEventProcessed("CiliumNode", "delete", true)
				k8sEventReg.K8sEventReceived("CiliumNode", "delete", true, false)
			},
		},
		func(obj interface{}) interface{} {
			cnp, _ := obj.(*ciliumv2.CiliumNode)
			return cnp
		},
		ciliumNodeStore,
	)

	go ciliumNodeInformer.Run(wait.NeverStop)

	log.WithField(fieldName, nodeName).Info("Waiting for CiliumNode custom resource to become available...")
	if ok := cache.WaitForCacheSync(wait.NeverStop, ciliumNodeInformer.HasSynced); !ok {
		log.WithField(fieldName, nodeName).Fatal("Unable to synchronize CiliumNode custom resource")
	} else {
		log.WithField(fieldName, nodeName).Info("Successfully synchronized CiliumNode custom resource")
	}

	for {
		minimumReached, required, numAvailable := store.hasMinimumIPsInPool()
		logFields := logrus.Fields{
			fieldName:   nodeName,
			"required":  required,
			"available": numAvailable,
		}
		if minimumReached {
			log.WithFields(logFields).Info("All required IPs are available in CRD-backed allocation pool")
			break
		}

		log.WithFields(logFields).Info("Waiting for IPs to become available in CRD-backed allocation pool")
		time.Sleep(5 * time.Second)
	}

	go func() {
		// Initial upstream sync must wait for the allocated IPs
		// to be restored
		<-store.restoreFinished
		store.refreshTrigger.TriggerWithReason("initial sync")
	}()

	return store
}

func deriveVpcCIDR(node *ciliumv2.CiliumNode) (result *cidr.CIDR) {
	if len(node.Status.ENI.ENIs) > 0 {
		// A node belongs to a single VPC so we can pick the first ENI
		// in the list and derive the VPC CIDR from it.
		for _, eni := range node.Status.ENI.ENIs {
			c, err := cidr.ParseCIDR(eni.VPC.PrimaryCIDR)
			if err == nil {
				result = c
			}
			return
		}
	}
	return
}

// hasMinimumIPsInPool returns true if the required number of IPs is available
// in the allocation pool. It also returns the number of IPs required and
// avalable.
func (n *nodeStore) hasMinimumIPsInPool() (minimumReached bool, required, numAvailable int) {
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

	if n.ownNode.Spec.IPAM.Pool != nil {
		numAvailable = len(n.ownNode.Spec.IPAM.Pool)
		if len(n.ownNode.Spec.IPAM.Pool) >= required {
			minimumReached = true
		}

		if option.Config.IPAM == option.IPAMENI {
			if vpcCIDR := deriveVpcCIDR(n.ownNode); vpcCIDR != nil {
				option.Config.SetIPv4NativeRoutingCIDR(vpcCIDR)
			} else {
				minimumReached = false
			}
		}
	}

	return
}

// deleteLocalNodeResource is called when the CiliumNode resource representing
// the local node has been deleted.
func (n *nodeStore) deleteLocalNodeResource() {
	n.mutex.Lock()
	n.ownNode = nil
	n.mutex.Unlock()
}

// updateLocalNodeResource is called when the CiliumNode resource representing
// the local node has been added or updated. It updates the available IPs based
// on the custom resource passed into the function.
func (n *nodeStore) updateLocalNodeResource(node *ciliumv2.CiliumNode) {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	n.ownNode = node
	n.allocationPoolSize[IPv4] = 0
	n.allocationPoolSize[IPv6] = 0
	if node.Spec.IPAM.Pool != nil {
		for ipString := range node.Spec.IPAM.Pool {
			if ip := net.ParseIP(ipString); ip != nil {
				if ip.To4() != nil {
					n.allocationPoolSize[IPv4]++
				} else {
					n.allocationPoolSize[IPv6]++
				}
			}
		}
	}
}

// refreshNodeTrigger is called to refresh the custom resource after taking the
// configured rate limiting into account
//
// Note: The function signature includes the reasons argument in order to
// implement the trigger.TriggerFunc interface despite the argument being
// unused.
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

	node.Status.IPAM.Used = map[string]ciliumv2.AllocationIP{}

	for _, a := range staleCopyOfAllocators {
		a.mutex.RLock()
		for ip, ipInfo := range a.allocated {
			node.Status.IPAM.Used[ip] = ipInfo
		}
		a.mutex.RUnlock()
	}

	var err error
	k8sCapabilities := k8sversion.Capabilities()
	ciliumClient := k8s.CiliumClient()
	switch {
	case k8sCapabilities.UpdateStatus:
		_, err = ciliumClient.CiliumV2().CiliumNodes().UpdateStatus(node)
	default:
		_, err = ciliumClient.CiliumV2().CiliumNodes().Update(node)
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

	if n.ownNode.Spec.IPAM.Pool == nil {
		return nil, fmt.Errorf("No IPs available")
	}

	ipInfo, ok := n.ownNode.Spec.IPAM.Pool[ip.String()]
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
	for ip, ipInfo := range n.ownNode.Spec.IPAM.Pool {
		if _, ok := allocated[ip]; !ok {
			parsedIP := net.ParseIP(ip)
			if parsedIP == nil {
				log.WithFields(logrus.Fields{
					fieldName: n.ownNode.Name,
					"ip":      ip,
				}).Warning("Unable to parse IP in CiliumNode custom resource")
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

// crdAllocator implements the CRD-backed IP allocator
type crdAllocator struct {
	// store is the node store backing the custom resource
	store *nodeStore

	// mutex protects access to the allocated map
	mutex lock.RWMutex

	// allocated is a map of all allocated IPs indexed by the allocated IP
	// represented as string
	allocated map[string]ciliumv2.AllocationIP

	// family is the address family this allocator is allocator for
	family Family
}

// newCRDAllocator creates a new CRD-backed IP allocator
func newCRDAllocator(family Family, owner Owner, k8sEventReg K8sEventRegister) Allocator {
	initNodeStore.Do(func() {
		sharedNodeStore = newNodeStore(node.GetName(), owner, k8sEventReg)
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

// Allocate will attempt to find the specified IP in the custom resource and
// allocate it if it is available. If the IP is unavailable or already
// allocated, an error is returned. The custom resource will be updated to
// reflect the newly allocated IP.
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
	// Update custom resource to reflect the newly allocated IP.
	a.store.refreshTrigger.TriggerWithReason(fmt.Sprintf("allocation of IP %s", ip.String()))

	return a.buildAllocationResult(ip, ipInfo)
}

// AllocateWithoutSyncUpstream will attempt to find the specified IP in the
// custom resource and allocate it if it is available. If the IP is
// unavailable or already allocated, an error is returned. The custom resource
// will not be updated.
func (a *crdAllocator) AllocateWithoutSyncUpstream(ip net.IP, owner string) (*AllocationResult, error) {
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
	// Update custom resource to reflect the newly released IP.
	a.store.refreshTrigger.TriggerWithReason(fmt.Sprintf("release of IP %s", ip.String()))

	return nil
}

// markAllocated marks a particular IP as allocated
func (a *crdAllocator) markAllocated(ip net.IP, owner string, ipInfo ciliumv2.AllocationIP) {
	ipInfo.Owner = owner
	a.allocated[ip.String()] = ipInfo
}

// AllocateNext allocates the next available IP as offered by the custom
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
	// Update custom resource to reflect the newly allocated IP.
	a.store.refreshTrigger.TriggerWithReason(fmt.Sprintf("allocation of IP %s", ip.String()))

	return a.buildAllocationResult(ip, ipInfo)
}

// AllocateNextWithoutSyncUpstream allocates the next available IP as offered
// by the custom resource or return an error if no IP is available. The custom
// resource will not be updated.
func (a *crdAllocator) AllocateNextWithoutSyncUpstream(owner string) (*AllocationResult, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	ip, ipInfo, err := a.store.allocateNext(a.allocated, a.family)
	if err != nil {
		return nil, err
	}

	a.markAllocated(ip, owner, *ipInfo)

	return a.buildAllocationResult(ip, ipInfo)
}

// totalPoolSize returns the total size of the allocation pool
// a.mutex must be held
func (a *crdAllocator) totalPoolSize() int {
	if num, ok := a.store.allocationPoolSize[a.family]; ok {
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

	status := fmt.Sprintf("%d/%d allocated", len(allocs), a.totalPoolSize())
	return allocs, status
}

// RestoreFinished marks the status of restoration as done
func (a *crdAllocator) RestoreFinished() {
	close(a.store.restoreFinished)
}
