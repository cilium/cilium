// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"

	alibabaCloud "github.com/cilium/cilium/pkg/alibabacloud/utils"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/ip"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/trigger"
)

var (
	sharedNodeStore *nodeStore
	initNodeStore   sync.Once
)

const (
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
	restoreFinished  chan struct{}
	restoreCloseOnce sync.Once

	clientset client.Clientset

	conf      *option.DaemonConfig
	mtuConfig MtuConfiguration
}

// newNodeStore initializes a new store which reflects the CiliumNode custom
// resource of the specified node name
func newNodeStore(nodeName string, conf *option.DaemonConfig, owner Owner, localNodeStore *node.LocalNodeStore, clientset client.Clientset, k8sEventReg K8sEventRegister, mtuConfig MtuConfiguration) *nodeStore {
	log.WithField(fieldName, nodeName).Info("Subscribed to CiliumNode custom resource")

	store := &nodeStore{
		allocators:         []*crdAllocator{},
		allocationPoolSize: map[Family]int{},
		conf:               conf,
		mtuConfig:          mtuConfig,
		clientset:          clientset,
	}
	store.restoreFinished = make(chan struct{})

	t, err := trigger.NewTrigger(trigger.Parameters{
		Name:        "crd-allocator-node-refresher",
		MinInterval: conf.IPAMCiliumNodeUpdateRate,
		TriggerFunc: store.refreshNodeTrigger,
	})
	if err != nil {
		log.WithError(err).Fatal("Unable to initialize CiliumNode synchronization trigger")
	}
	store.refreshTrigger = t

	// Create the CiliumNode custom resource. This call will block until
	// the custom resource has been created
	owner.UpdateCiliumNodeResource()
	apiGroup := "cilium/v2::CiliumNode"
	ciliumNodeSelector := fields.ParseSelectorOrDie("metadata.name=" + nodeName)
	_, ciliumNodeInformer := informer.NewInformer(
		utils.ListerWatcherWithFields(
			utils.ListerWatcherFromTyped[*ciliumv2.CiliumNodeList](clientset.CiliumV2().CiliumNodes()),
			ciliumNodeSelector),
		&ciliumv2.CiliumNode{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k8sEventReg.K8sEventReceived(apiGroup, "CiliumNode", "create", valid, equal) }()
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
				defer func() { k8sEventReg.K8sEventReceived(apiGroup, "CiliumNode", "update", valid, equal) }()
				if oldNode, ok := oldObj.(*ciliumv2.CiliumNode); ok {
					if newNode, ok := newObj.(*ciliumv2.CiliumNode); ok {
						valid = true
						newNode = newNode.DeepCopy()
						if oldNode.DeepEqual(newNode) {
							// The UpdateStatus call in refreshNode requires an up-to-date
							// CiliumNode.ObjectMeta.ResourceVersion. Therefore, we store the most
							// recent version here even if the nodes are equal, because
							// CiliumNode.DeepEqual will consider two nodes to be equal even if
							// their resource version differs.
							store.setOwnNodeWithoutPoolUpdate(newNode)
							equal = true
							return
						}
						store.updateLocalNodeResource(newNode)
						k8sEventReg.K8sEventProcessed("CiliumNode", "update", true)
					} else {
						log.Warningf("Unknown CiliumNode object type %T received: %+v", oldNode, oldNode)
					}
				} else {
					log.Warningf("Unknown CiliumNode object type %T received: %+v", oldNode, oldNode)
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
				k8sEventReg.K8sEventReceived(apiGroup, "CiliumNode", "delete", true, false)
			},
		},
		nil,
	)

	go ciliumNodeInformer.Run(wait.NeverStop)

	log.WithField(fieldName, nodeName).Info("Waiting for CiliumNode custom resource to become available...")
	if ok := cache.WaitForCacheSync(wait.NeverStop, ciliumNodeInformer.HasSynced); !ok {
		log.WithField(fieldName, nodeName).Fatal("Unable to synchronize CiliumNode custom resource")
	} else {
		log.WithField(fieldName, nodeName).Info("Successfully synchronized CiliumNode custom resource")
	}

	for {
		minimumReached, required, numAvailable := store.hasMinimumIPsInPool(localNodeStore)
		logFields := logrus.Fields{
			fieldName:   nodeName,
			"required":  required,
			"available": numAvailable,
		}
		if minimumReached {
			log.WithFields(logFields).Info("All required IPs are available in CRD-backed allocation pool")
			break
		}

		log.WithFields(logFields).WithField(
			logfields.HelpMessage,
			"Check if cilium-operator pod is running and does not have any warnings or error messages.",
		).Info("Waiting for IPs to become available in CRD-backed allocation pool")
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

func deriveVpcCIDRs(node *ciliumv2.CiliumNode) (primaryCIDR *cidr.CIDR, secondaryCIDRs []*cidr.CIDR) {
	// A node belongs to a single VPC so we can pick the first ENI
	// in the list and derive the VPC CIDR from it.
	for _, eni := range node.Status.ENI.ENIs {
		c, err := cidr.ParseCIDR(eni.VPC.PrimaryCIDR)
		if err == nil {
			primaryCIDR = c
			for _, sc := range eni.VPC.CIDRs {
				c, err = cidr.ParseCIDR(sc)
				if err == nil {
					secondaryCIDRs = append(secondaryCIDRs, c)
				}
			}
			return
		}
	}
	for _, azif := range node.Status.Azure.Interfaces {
		c, err := cidr.ParseCIDR(azif.CIDR)
		if err == nil {
			primaryCIDR = c
			return
		}
	}
	// return AlibabaCloud vpc CIDR
	if len(node.Status.AlibabaCloud.ENIs) > 0 {
		c, err := cidr.ParseCIDR(node.Spec.AlibabaCloud.CIDRBlock)
		if err == nil {
			primaryCIDR = c
		}
		for _, eni := range node.Status.AlibabaCloud.ENIs {
			for _, sc := range eni.VPC.SecondaryCIDRs {
				c, err = cidr.ParseCIDR(sc)
				if err == nil {
					secondaryCIDRs = append(secondaryCIDRs, c)
				}
			}
			return
		}
	}
	return
}

func (n *nodeStore) autoDetectIPv4NativeRoutingCIDR(localNodeStore *node.LocalNodeStore) bool {
	if primaryCIDR, secondaryCIDRs := deriveVpcCIDRs(n.ownNode); primaryCIDR != nil {
		allCIDRs := append([]*cidr.CIDR{primaryCIDR}, secondaryCIDRs...)
		if nativeCIDR := n.conf.IPv4NativeRoutingCIDR; nativeCIDR != nil {
			found := false
			for _, vpcCIDR := range allCIDRs {
				logFields := logrus.Fields{
					"vpc-cidr":                   vpcCIDR.String(),
					option.IPv4NativeRoutingCIDR: nativeCIDR.String(),
				}

				ranges4, _ := ip.CoalesceCIDRs([]*net.IPNet{nativeCIDR.IPNet, vpcCIDR.IPNet})
				if len(ranges4) != 1 {
					log.WithFields(logFields).Info("Native routing CIDR does not contain VPC CIDR, trying next")
				} else {
					found = true
					log.WithFields(logFields).Info("Native routing CIDR contains VPC CIDR, ignoring autodetected VPC CIDRs.")
					break
				}
			}
			if !found {
				log.Fatal("None of the VPC CIDRs contains the specified native routing CIDR")
			}
		} else {
			log.WithFields(logrus.Fields{
				"vpc-cidr": primaryCIDR.String(),
			}).Info("Using autodetected primary VPC CIDR.")
			localNodeStore.Update(func(n *node.LocalNode) {
				n.IPv4NativeRoutingCIDR = primaryCIDR
			})
		}
		return true
	} else {
		log.Info("Could not determine VPC CIDRs")
		return false
	}
}

// hasMinimumIPsInPool returns true if the required number of IPs is available
// in the allocation pool. It also returns the number of IPs required and
// available.
func (n *nodeStore) hasMinimumIPsInPool(localNodeStore *node.LocalNodeStore) (minimumReached bool, required, numAvailable int) {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	if n.ownNode == nil {
		return
	}

	switch {
	case n.ownNode.Spec.IPAM.MinAllocate != 0:
		required = n.ownNode.Spec.IPAM.MinAllocate
	case n.ownNode.Spec.IPAM.PreAllocate != 0:
		required = n.ownNode.Spec.IPAM.PreAllocate
	case n.conf.HealthCheckingEnabled():
		required = 2
	default:
		required = 1
	}

	if n.ownNode.Spec.IPAM.Pool != nil {
		for ip := range n.ownNode.Spec.IPAM.Pool {
			if !n.isIPInReleaseHandshake(ip) {
				numAvailable++
			}
		}
		if len(n.ownNode.Spec.IPAM.Pool) >= required {
			minimumReached = true
		}

		if n.conf.IPAMMode() == ipamOption.IPAMENI || n.conf.IPAMMode() == ipamOption.IPAMAzure || n.conf.IPAMMode() == ipamOption.IPAMAlibabaCloud {
			if !n.autoDetectIPv4NativeRoutingCIDR(localNodeStore) {
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

	if n.conf.IPAMMode() == ipamOption.IPAMENI {
		if err := configureENIDevices(n.ownNode, node, n.mtuConfig); err != nil {
			log.WithError(err).Errorf("Failed to update routes and rules for ENIs")
		}
	}

	n.ownNode = node
	n.allocationPoolSize[IPv4] = 0
	n.allocationPoolSize[IPv6] = 0
	for ipString := range node.Spec.IPAM.Pool {
		if ip := net.ParseIP(ipString); ip != nil {
			if ip.To4() != nil {
				n.allocationPoolSize[IPv4]++
			} else {
				n.allocationPoolSize[IPv6]++
			}
		}
	}

	releaseUpstreamSyncNeeded := false
	// ACK or NACK IPs marked for release by the operator
	for ip, status := range n.ownNode.Status.IPAM.ReleaseIPs {
		if n.ownNode.Spec.IPAM.Pool == nil {
			continue
		}
		// Ignore states that agent previously responded to.
		if status == ipamOption.IPAMReadyForRelease || status == ipamOption.IPAMDoNotRelease {
			continue
		}
		if _, ok := n.ownNode.Spec.IPAM.Pool[ip]; !ok {
			if status == ipamOption.IPAMReleased {
				// Remove entry from release-ips only when it is removed from .spec.ipam.pool as well
				delete(n.ownNode.Status.IPAM.ReleaseIPs, ip)
				releaseUpstreamSyncNeeded = true

				// Remove the unreachable route for this IP
				if n.conf.UnreachableRoutesEnabled() {
					parsedIP := net.ParseIP(ip)
					if parsedIP == nil {
						// Unable to parse IP, no point in trying to remove the route
						log.Warningf("Unable to parse IP %s", ip)
						continue
					}

					err := netlink.RouteDel(&netlink.Route{
						Dst:   &net.IPNet{IP: parsedIP, Mask: net.CIDRMask(32, 32)},
						Table: unix.RT_TABLE_MAIN,
						Type:  unix.RTN_UNREACHABLE,
					})
					if err != nil && !errors.Is(err, unix.ESRCH) {
						// We ignore ESRCH, as it means the entry was already deleted
						log.WithError(err).Warningf("Unable to delete unreachable route for IP %s", ip)
						continue
					}
				}
			} else if status == ipamOption.IPAMMarkForRelease {
				// NACK the IP, if this node doesn't own the IP
				n.ownNode.Status.IPAM.ReleaseIPs[ip] = ipamOption.IPAMDoNotRelease
				releaseUpstreamSyncNeeded = true
			}
			continue
		}

		// Ignore all other states, transition to do-not-release and ready-for-release are allowed only from
		// marked-for-release
		if status != ipamOption.IPAMMarkForRelease {
			continue
		}
		// Retrieve the appropriate allocator
		var allocator *crdAllocator
		var ipFamily Family
		if ipAddr := net.ParseIP(ip); ipAddr != nil {
			ipFamily = DeriveFamily(ipAddr)
		}
		if ipFamily == "" {
			continue
		}
		for _, a := range n.allocators {
			if a.family == ipFamily {
				allocator = a
			}
		}
		if allocator == nil {
			continue
		}

		// Some functions like crdAllocator.Allocate() acquire lock on allocator first and then on nodeStore.
		// So release nodestore lock before acquiring allocator lock to avoid potential deadlocks from inconsistent
		// lock ordering.
		n.mutex.Unlock()
		allocator.mutex.Lock()
		_, ok := allocator.allocated[ip]
		allocator.mutex.Unlock()
		n.mutex.Lock()

		if ok {
			// IP still in use, update the operator to stop releasing the IP.
			n.ownNode.Status.IPAM.ReleaseIPs[ip] = ipamOption.IPAMDoNotRelease
		} else {
			n.ownNode.Status.IPAM.ReleaseIPs[ip] = ipamOption.IPAMReadyForRelease
		}
		releaseUpstreamSyncNeeded = true
	}

	if releaseUpstreamSyncNeeded {
		n.refreshTrigger.TriggerWithReason("excess IP release")
	}
}

// setOwnNodeWithoutPoolUpdate overwrites the local node copy (e.g. to update
// its resourceVersion) without updating the available IP pool.
func (n *nodeStore) setOwnNodeWithoutPoolUpdate(node *ciliumv2.CiliumNode) {
	n.mutex.Lock()
	n.ownNode = node
	n.mutex.Unlock()
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

	node.Status.IPAM.Used = ipamTypes.AllocationMap{}

	for _, a := range staleCopyOfAllocators {
		a.mutex.RLock()
		for ip, ipInfo := range a.allocated {
			node.Status.IPAM.Used[ip] = ipInfo
		}
		a.mutex.RUnlock()
	}

	var err error
	_, err = n.clientset.CiliumV2().CiliumNodes().UpdateStatus(context.TODO(), node, metav1.UpdateOptions{})

	return err
}

// addAllocator adds a new CRD allocator to the node store
func (n *nodeStore) addAllocator(allocator *crdAllocator) {
	n.mutex.Lock()
	n.allocators = append(n.allocators, allocator)
	n.mutex.Unlock()
}

// allocate checks if a particular IP can be allocated or return an error
func (n *nodeStore) allocate(ip net.IP) (*ipamTypes.AllocationIP, error) {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	if n.ownNode == nil {
		return nil, fmt.Errorf("CiliumNode for own node is not available")
	}

	if n.ownNode.Spec.IPAM.Pool == nil {
		return nil, fmt.Errorf("No IPs available")
	}

	if n.isIPInReleaseHandshake(ip.String()) {
		return nil, fmt.Errorf("IP not available, marked or ready for release")
	}

	ipInfo, ok := n.ownNode.Spec.IPAM.Pool[ip.String()]
	if !ok {
		return nil, NewIPNotAvailableInPoolError(ip)
	}

	return &ipInfo, nil
}

// isIPInReleaseHandshake validates if a given IP is currently in the process of being released
func (n *nodeStore) isIPInReleaseHandshake(ip string) bool {
	if n.ownNode.Status.IPAM.ReleaseIPs == nil {
		return false
	}
	if status, ok := n.ownNode.Status.IPAM.ReleaseIPs[ip]; ok {
		if status == ipamOption.IPAMMarkForRelease || status == ipamOption.IPAMReadyForRelease || status == ipamOption.IPAMReleased {
			return true
		}
	}
	return false
}

// allocateNext allocates the next available IP or returns an error
func (n *nodeStore) allocateNext(allocated ipamTypes.AllocationMap, family Family, owner string) (net.IP, *ipamTypes.AllocationIP, error) {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	if n.ownNode == nil {
		return nil, nil, fmt.Errorf("CiliumNode for own node is not available")
	}

	// Check if IP has a custom owner (only supported in manual CRD mode)
	if n.conf.IPAMMode() == ipamOption.IPAMCRD && len(owner) != 0 {
		for ip, ipInfo := range n.ownNode.Spec.IPAM.Pool {
			if ipInfo.Owner == owner {
				parsedIP := net.ParseIP(ip)
				if parsedIP == nil {
					log.WithFields(logrus.Fields{
						fieldName: n.ownNode.Name,
						"ip":      ip,
					}).Warning("Unable to parse IP in CiliumNode custom resource")
					return nil, nil, fmt.Errorf("invalid custom ip %s for %s. ", ip, owner)
				}
				if DeriveFamily(parsedIP) != family {
					continue
				}
				return parsedIP, &ipInfo, nil
			}
		}
	}

	// FIXME: This is currently using a brute-force method that can be
	// optimized
	for ip, ipInfo := range n.ownNode.Spec.IPAM.Pool {
		if _, ok := allocated[ip]; !ok {

			if n.isIPInReleaseHandshake(ip) {
				continue // IP not available
			}
			if ipInfo.Owner != "" {
				continue // IP is used by another
			}
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

// totalPoolSize returns the total size of the allocation pool
func (n *nodeStore) totalPoolSize(family Family) int {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	if num, ok := n.allocationPoolSize[family]; ok {
		return num
	}
	return 0
}

// crdAllocator implements the CRD-backed IP allocator
type crdAllocator struct {
	// store is the node store backing the custom resource
	store *nodeStore

	// mutex protects access to the allocated map
	mutex lock.RWMutex

	// allocated is a map of all allocated IPs indexed by the allocated IP
	// represented as string
	allocated ipamTypes.AllocationMap

	// family is the address family this allocator is allocator for
	family Family

	conf *option.DaemonConfig
}

// newCRDAllocator creates a new CRD-backed IP allocator
func newCRDAllocator(family Family, c *option.DaemonConfig, owner Owner, localNodeStore *node.LocalNodeStore, clientset client.Clientset, k8sEventReg K8sEventRegister, mtuConfig MtuConfiguration) Allocator {
	initNodeStore.Do(func() {
		sharedNodeStore = newNodeStore(nodeTypes.GetName(), c, owner, localNodeStore, clientset, k8sEventReg, mtuConfig)
	})

	allocator := &crdAllocator{
		allocated: ipamTypes.AllocationMap{},
		family:    family,
		store:     sharedNodeStore,
		conf:      c,
	}

	sharedNodeStore.addAllocator(allocator)

	return allocator
}

// deriveGatewayIP accept the CIDR and the index of the IP in this CIDR.
func deriveGatewayIP(cidr string, index int) string {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		log.WithError(err).Warningf("Unable to parse subnet CIDR %s", cidr)
		return ""
	}
	gw := ip.GetIPAtIndex(*ipNet, int64(index))
	if gw == nil {
		return ""
	}
	return gw.String()
}

func (a *crdAllocator) buildAllocationResult(ip net.IP, ipInfo *ipamTypes.AllocationIP) (result *AllocationResult, err error) {
	result = &AllocationResult{IP: ip}

	a.store.mutex.RLock()
	defer a.store.mutex.RUnlock()

	if a.store.ownNode == nil {
		return
	}

	switch a.conf.IPAMMode() {

	// In ENI mode, the Resource points to the ENI so we can derive the
	// master interface and all CIDRs of the VPC
	case ipamOption.IPAMENI:
		for _, eni := range a.store.ownNode.Status.ENI.ENIs {
			if eni.ID == ipInfo.Resource {
				result.PrimaryMAC = eni.MAC
				result.CIDRs = []string{eni.VPC.PrimaryCIDR}
				result.CIDRs = append(result.CIDRs, eni.VPC.CIDRs...)
				// Add manually configured Native Routing CIDR
				if a.conf.IPv4NativeRoutingCIDR != nil {
					result.CIDRs = append(result.CIDRs, a.conf.IPv4NativeRoutingCIDR.String())
				}
				if eni.Subnet.CIDR != "" {
					// The gateway for a subnet and VPC is always x.x.x.1
					// Ref: https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Route_Tables.html
					result.GatewayIP = deriveGatewayIP(eni.Subnet.CIDR, 1)
				}
				result.InterfaceNumber = strconv.Itoa(eni.Number)

				return
			}
		}
		return nil, fmt.Errorf("unable to find ENI %s", ipInfo.Resource)

	// In Azure mode, the Resource points to the azure interface so we can
	// derive the master interface
	case ipamOption.IPAMAzure:
		for _, iface := range a.store.ownNode.Status.Azure.Interfaces {
			if iface.ID == ipInfo.Resource {
				result.PrimaryMAC = iface.MAC
				result.GatewayIP = iface.Gateway
				result.CIDRs = append(result.CIDRs, iface.CIDR)
				// For now, we can hardcode the interface number to a valid
				// integer because it will not be used in the allocation result
				// anyway. To elaborate, Azure IPAM mode automatically sets
				// option.Config.EgressMultiHomeIPRuleCompat to true, meaning
				// that the CNI will not use the interface number when creating
				// the pod rules and routes. We are hardcoding simply to bypass
				// the parsing errors when InterfaceNumber is empty. See
				// https://github.com/cilium/cilium/issues/15496.
				//
				// TODO: Once https://github.com/cilium/cilium/issues/14705 is
				// resolved, then we don't need to hardcode this anymore.
				result.InterfaceNumber = "0"
				return
			}
		}
		return nil, fmt.Errorf("unable to find ENI %s", ipInfo.Resource)

	// In AlibabaCloud mode, the Resource points to the ENI so we can derive the
	// master interface and all CIDRs of the VPC
	case ipamOption.IPAMAlibabaCloud:
		for _, eni := range a.store.ownNode.Status.AlibabaCloud.ENIs {
			if eni.NetworkInterfaceID != ipInfo.Resource {
				continue
			}
			result.PrimaryMAC = eni.MACAddress
			result.CIDRs = []string{eni.VSwitch.CIDRBlock}

			// Ref: https://www.alibabacloud.com/help/doc-detail/65398.html
			result.GatewayIP = deriveGatewayIP(eni.VSwitch.CIDRBlock, -3)
			result.InterfaceNumber = strconv.Itoa(alibabaCloud.GetENIIndexFromTags(eni.Tags))
			return
		}
		return nil, fmt.Errorf("unable to find ENI %s", ipInfo.Resource)
	}

	return
}

// Allocate will attempt to find the specified IP in the custom resource and
// allocate it if it is available. If the IP is unavailable or already
// allocated, an error is returned. The custom resource will be updated to
// reflect the newly allocated IP.
func (a *crdAllocator) Allocate(ip net.IP, owner string, pool Pool) (*AllocationResult, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if _, ok := a.allocated[ip.String()]; ok {
		return nil, fmt.Errorf("IP already in use")
	}

	ipInfo, err := a.store.allocate(ip)
	if err != nil {
		return nil, err
	}

	result, err := a.buildAllocationResult(ip, ipInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to associate IP %s inside CiliumNode: %w", ip, err)
	}

	a.markAllocated(ip, owner, *ipInfo)
	// Update custom resource to reflect the newly allocated IP.
	a.store.refreshTrigger.TriggerWithReason(fmt.Sprintf("allocation of IP %s", ip.String()))

	return result, nil
}

// AllocateWithoutSyncUpstream will attempt to find the specified IP in the
// custom resource and allocate it if it is available. If the IP is
// unavailable or already allocated, an error is returned. The custom resource
// will not be updated.
func (a *crdAllocator) AllocateWithoutSyncUpstream(ip net.IP, owner string, pool Pool) (*AllocationResult, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if _, ok := a.allocated[ip.String()]; ok {
		return nil, fmt.Errorf("IP already in use")
	}

	ipInfo, err := a.store.allocate(ip)
	if err != nil {
		return nil, err
	}

	result, err := a.buildAllocationResult(ip, ipInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to associate IP %s inside CiliumNode: %w", ip, err)
	}

	a.markAllocated(ip, owner, *ipInfo)

	return result, nil
}

// Release will release the specified IP or return an error if the IP has not
// been allocated before. The custom resource will be updated to reflect the
// released IP.
func (a *crdAllocator) Release(ip net.IP, pool Pool) error {
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
func (a *crdAllocator) markAllocated(ip net.IP, owner string, ipInfo ipamTypes.AllocationIP) {
	ipInfo.Owner = owner
	a.allocated[ip.String()] = ipInfo
}

// AllocateNext allocates the next available IP as offered by the custom
// resource or return an error if no IP is available. The custom resource will
// be updated to reflect the newly allocated IP.
func (a *crdAllocator) AllocateNext(owner string, pool Pool) (*AllocationResult, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	ip, ipInfo, err := a.store.allocateNext(a.allocated, a.family, owner)
	if err != nil {
		return nil, err
	}

	result, err := a.buildAllocationResult(ip, ipInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to associate IP %s inside CiliumNode: %w", ip, err)
	}

	a.markAllocated(ip, owner, *ipInfo)
	// Update custom resource to reflect the newly allocated IP.
	a.store.refreshTrigger.TriggerWithReason(fmt.Sprintf("allocation of IP %s", ip.String()))

	return result, nil
}

// AllocateNextWithoutSyncUpstream allocates the next available IP as offered
// by the custom resource or return an error if no IP is available. The custom
// resource will not be updated.
func (a *crdAllocator) AllocateNextWithoutSyncUpstream(owner string, pool Pool) (*AllocationResult, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	ip, ipInfo, err := a.store.allocateNext(a.allocated, a.family, owner)
	if err != nil {
		return nil, err
	}

	result, err := a.buildAllocationResult(ip, ipInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to associate IP %s inside CiliumNode: %w", ip, err)
	}

	a.markAllocated(ip, owner, *ipInfo)

	return result, nil
}

// Dump provides a status report and lists all allocated IP addresses
func (a *crdAllocator) Dump() (map[Pool]map[string]string, string) {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	allocs := make(map[string]string, len(a.allocated))
	for ip := range a.allocated {
		allocs[ip] = ""
	}

	status := fmt.Sprintf("%d/%d allocated", len(allocs), a.store.totalPoolSize(a.family))
	return map[Pool]map[string]string{PoolDefault(): allocs}, status
}

func (a *crdAllocator) Capacity() uint64 {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	return uint64(a.store.totalPoolSize(a.family))
}

// RestoreFinished marks the status of restoration as done
func (a *crdAllocator) RestoreFinished() {
	a.store.restoreCloseOnce.Do(func() {
		close(a.store.restoreFinished)
	})
}

// NewIPNotAvailableInPoolError returns an error resprenting the given IP not
// being available in the IPAM pool.
func NewIPNotAvailableInPoolError(ip net.IP) error {
	return &ErrIPNotAvailableInPool{ip: ip}
}

// ErrIPNotAvailableInPool represents an error when an IP is not available in
// the pool.
type ErrIPNotAvailableInPool struct {
	ip net.IP
}

func (e *ErrIPNotAvailableInPool) Error() string {
	return fmt.Sprintf("IP %s is not available", e.ip.String())
}

// Is provides this error type with the logic for use with errors.Is.
func (e *ErrIPNotAvailableInPool) Is(target error) bool {
	if e == nil || target == nil {
		return false
	}
	t, ok := target.(*ErrIPNotAvailableInPool)
	if !ok {
		return ok
	}
	if t == nil {
		return false
	}
	return t.ip.Equal(e.ip)
}
