// Copyright 2019-2020 Authors of Cilium
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
	"context"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	linuxrouting "github.com/cilium/cilium/pkg/datapath/linux/routing"
	"github.com/vishvananda/netlink"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	eniTypes "github.com/cilium/cilium/pkg/aws/eni/types"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/ip"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/trigger"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
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
	restoreFinished  chan struct{}
	restoreCloseOnce sync.Once

	conf Configuration
}

// newNodeStore initializes a new store which reflects the CiliumNode custom
// resource of the specified node name
func newNodeStore(nodeName string, conf Configuration, owner Owner, k8sEventReg K8sEventRegister) *nodeStore {
	log.WithField(fieldName, nodeName).Info("Subscribed to CiliumNode custom resource")

	store := &nodeStore{
		allocators:         []*crdAllocator{},
		allocationPoolSize: map[Family]int{},
		conf:               conf,
	}
	store.restoreFinished = make(chan struct{})
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
			ciliumv2.CNPluralName, corev1.NamespaceAll, ciliumNodeSelector),
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
				if oldNode, ok := oldObj.(*ciliumv2.CiliumNode); ok {
					if newNode, ok := newObj.(*ciliumv2.CiliumNode); ok {
						if oldNode.DeepEqual(newNode) {
							equal = true
							return
						}
						valid = true
						store.updateLocalNodeResource(newNode.DeepCopy())
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
				k8sEventReg.K8sEventReceived("CiliumNode", "delete", true, false)
			},
		},
		nil,
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

func updateENIRulesAndRoutes(oldNode, newNode *nodeTypes.Node) error {
	var oldInterfaces []nodeTypes.Interface
	if oldNode != nil {
		oldInterfaces = oldNode.Interfaces
	}

	log.WithField("old", oldNode).WithField("new", newNode).Info("!!! updateENIRulesAndRoutes")

	addedInterfaces, removedInterfaces := diffInterfaces(oldInterfaces, newNode.Interfaces)

	// Configure new interfaces.
	macToIfIndex := map[string]int{} // FIXME move this to nodeRulesAndRoutes?
	for _, addedInterface := range newNode.Interfaces {
		// mtu := n.nodeConfig.MtuConfig.GetDeviceMTU()
		mtu := 1500 // FIXME pass in real MTU
		ifIdx, err := linuxrouting.RetrieveIfIndexFromMAC(addedInterface.MAC, mtu)
		if err != nil {
			log.WithError(err).Errorf("Unable to configure interface index %d mac %s", addedInterface.Index, addedInterface.MAC)
		} else {
			macToIfIndex[addedInterface.MAC.String()] = ifIdx
		}
	}

	// Ignore removed interfaces for now.
	_ = removedInterfaces
	_ = addedInterfaces

	oldRules, oldRoutes := nodeRulesAndRoutes(oldNode, macToIfIndex)
	newRules, newRoutes := nodeRulesAndRoutes(newNode, macToIfIndex)
	addedRules, removedRules := diffRules(oldRules, newRules)
	addedRoutes, removedRoutes := diffRoutes(oldRoutes, newRoutes)

	log.WithFields(logrus.Fields{
		"addedRules":    addedRules,
		"removedRules":  removedRules,
		"addedRoutes":   addedRoutes,
		"removedRoutes": removedRoutes,
	}).Info("!!!! EXTRACTED DIFF")

	// Add and remove rules and routes. This has to succeed so we retry
	// multiple times.
	maxRetries := 3
	rulesToAdd, rulesToRemove := addedRules, removedRules
	routesToAdd, routesToRemove := addedRoutes, removedRoutes
	var failedAddRules, failedRemoveRules []*route.Rule
	var failedAddRoutes, failedRemoveRoutes []*netlink.Route
	for retry := 0; retry < maxRetries; retry++ {
		for _, rule := range rulesToAdd {
			if err := route.ReplaceRule(*rule); err != nil {
				log.WithError(err).Errorf("add rule %s failed", rule)
				failedAddRules = append(failedAddRules, rule)
			}
		}

		for _, rule := range rulesToRemove {
			if err := route.DeleteRule(*rule); err != nil {
				log.WithError(err).Errorf("delete rule %s failed", rule)
				failedRemoveRules = append(failedRemoveRules, rule)
			}
		}

		for _, route := range routesToAdd {
			if err := netlink.RouteReplace(route); err != nil {
				log.WithError(err).Errorf("add L2 nexthop route %s failed", route)
				failedAddRoutes = append(failedAddRoutes, route)
			}
		}

		for _, route := range routesToRemove {
			if err := netlink.RouteDel(route); err != nil {
				log.WithError(err).Errorf("remove L2 nexthop route %s failed", route)
				failedRemoveRoutes = append(failedRemoveRoutes, route)
			}
		}

		// If there were no failues, then we are done.
		if len(failedAddRules)+len(failedRemoveRules)+len(failedAddRoutes)+len(failedRemoveRoutes) == 0 {
			break
		}

		// Otherwise, retry with the failures and clear the list of failures.
		rulesToAdd, failedAddRules = failedAddRules, nil
		rulesToRemove, failedRemoveRules = failedRemoveRules, nil
		routesToAdd, failedAddRoutes = failedAddRoutes, nil
		routesToRemove, failedRemoveRoutes = failedRemoveRoutes, nil
	}

	// If there were still failures after retrying, then return an error.
	if failures := len(failedAddRules) + len(failedRemoveRules) + len(failedAddRoutes) + len(failedRemoveRoutes); failures > 0 {
		return fmt.Errorf("adding and removing %d rules and routes failed after %d retries", failures, maxRetries)
	}

	return nil
}

// nodeRulesAndRoutes returns the rules and routes required to configure node.
// It is based on pkg/datapath/linux/routing.Configure.
func nodeRulesAndRoutes(node *nodeTypes.Node, macToIfIndex map[string]int) (rules []*route.Rule, routes []*netlink.Route) {
	if node == nil {
		return nil, nil
	}

	nodeIPv4Nets, nodeIPv6Nets := ip.CoalesceCIDRs(nodeIPNets(node))
	_ = nodeIPv6Nets // Ignore IPv6 nets for now.

	for _, iface := range node.Interfaces {
		ifIndex, ok := macToIfIndex[iface.MAC.String()]
		if !ok {
			log.WithField("iface", iface).Warning("failed to retrieve interface index")
			continue
		}

		var egressPriority, tableID int
		if option.Config.EgressMultiHomeIPRuleCompat {
			egressPriority = linux_defaults.RulePriorityEgress
			tableID = ifIndex
		} else {
			egressPriority = linux_defaults.RulePriorityEgressv2
			// RoutingInfo.Configure is also using the ENI index here
			tableID = linuxrouting.ComputeTableIDFromIfaceNumber(iface.Index)
		}

		for _, endpointAddress := range iface.EndpointAddresses {
			ipWithMask := net.IPNet{
				IP:   endpointAddress,
				Mask: net.CIDRMask(32, 32),
			}

			// On ingress, route all traffic to the endpoint IP via the main
			// routing table. Egress rules are created in a per-ENI routing
			// table.
			ingressRule := &route.Rule{
				Priority: linux_defaults.RulePriorityIngress,
				To:       &ipWithMask,
				Table:    route.MainTable,
			}
			rules = append(rules, ingressRule)

			if option.Config.EnableIPv4Masquerade {
				// Lookup a VPC specific table for all traffic from an endpoint
				// to the CIDR configured for the VPC on which the endpoint has
				// the IP on.
				egressRules := make([]*route.Rule, 0, len(nodeIPv4Nets))
				for _, ipNet := range nodeIPv4Nets {
					egressRule := &route.Rule{
						Priority: egressPriority,
						From:     &ipWithMask,
						To:       ipNet,
						Table:    tableID,
					}
					egressRules = append(egressRules, egressRule)
				}
				rules = append(rules, egressRules...)
			} else {
				// Lookup a VPC specific table for all traffic from an endpoint.
				egressRule := &route.Rule{
					Priority: egressPriority,
					From:     &ipWithMask,
					Table:    tableID,
				}
				rules = append(rules, egressRule)
			}
		}

		// Nexthop route to the VPC or subnet gateway.
		//
		// Note: This is a /32 route to avoid any L2. The endpoint does no L2
		// either.
		nexthopRoute := &netlink.Route{
			LinkIndex: ifIndex,
			Dst: &net.IPNet{
				IP:   iface.Gateway.IP,
				Mask: net.CIDRMask(32, 32),
			},
			Scope: netlink.SCOPE_LINK,
			Table: tableID,
		}
		routes = append(routes, nexthopRoute)

		// Default route to the VPC or subnet gateway.
		defaultRoute := &netlink.Route{
			Dst: &net.IPNet{
				IP:   net.IPv4zero,
				Mask: net.CIDRMask(0, 32),
			},
			Table: tableID,
			Gw:    iface.Gateway.IP,
		}
		routes = append(routes, defaultRoute)
	}

	return
}

// nodeIPNets returns all natively routed CIDRs for node.
func nodeIPNets(node *nodeTypes.Node) []*net.IPNet {
	var ipNets []*net.IPNet
	if ipv4NativeRoutingCIDR := option.Config.IPv4NativeRoutingCIDR(); ipv4NativeRoutingCIDR != nil && ipv4NativeRoutingCIDR.IPNet != nil {
		ipNets = append(ipNets, ipv4NativeRoutingCIDR.IPNet)
	}
	for _, ipv4NativeRoutingCIDR := range node.IPv4NativeRoutingCIDRs {
		ipNets = append(ipNets, ipv4NativeRoutingCIDR.IPNet)
	}
	return ipNets
}

func diffInterfaces(old, new []nodeTypes.Interface) (added, removed []*nodeTypes.Interface) {
	newInterfaceSet := interfaceSet(new)
	for _, oldInterface := range old {
		if _, ok := newInterfaceSet[oldInterface.Index]; !ok {
			removed = append(removed, &oldInterface)
		}
	}

	oldInterfaceSet := interfaceSet(old)
	for _, newInterface := range new {
		if _, ok := oldInterfaceSet[newInterface.Index]; !ok {
			added = append(added, &newInterface)
		}
	}

	return
}

func interfaceSet(interfaces []nodeTypes.Interface) map[int]struct{} {
	interfaceSet := make(map[int]struct{})
	for _, iface := range interfaces {
		interfaceSet[iface.Index] = struct{}{}
	}
	return interfaceSet
}

// diffRules returns a list of added and removed rules between old and new.
//
// TODO this could be a lot more efficient, it makes a lot of calls to
// route.Rule.String() which could be a lot faster. As the order of rules is
// deterministic, we could also consider using a proper diff algorithm.
func diffRules(old, new []*route.Rule) (added, removed []*route.Rule) {
	newRuleSet := ruleSet(new)
	for _, oldRule := range old {
		if _, ok := newRuleSet[oldRule.String()]; !ok {
			removed = append(removed, oldRule)
		}
	}

	oldRuleSet := ruleSet(old)
	for _, newRule := range new {
		if _, ok := oldRuleSet[newRule.String()]; !ok {
			added = append(added, newRule)
		}
	}

	return
}

func ruleSet(rules []*route.Rule) map[string]struct{} {
	ruleSet := make(map[string]struct{})
	for _, rule := range rules {
		ruleSet[rule.String()] = struct{}{}
	}
	return ruleSet
}

func diffRoutes(old, new []*netlink.Route) (added, removed []*netlink.Route) {
	newRouteSet := routeSet(new)
	for _, oldRoute := range old {
		if _, ok := newRouteSet[oldRoute.String()]; !ok {
			removed = append(removed, oldRoute)
		}
	}

	oldRouteSet := routeSet(old)
	for _, newRoute := range new {
		if _, ok := oldRouteSet[newRoute.String()]; !ok {
			added = append(added, newRoute)
		}
	}

	return
}

func routeSet(routes []*netlink.Route) map[string]struct{} {
	routeSet := make(map[string]struct{})
	for _, route := range routes {
		routeSet[route.String()] = struct{}{}
	}
	return routeSet
}

// hasMinimumIPsInPool returns true if the required number of IPs is available
// in the allocation pool. It also returns the number of IPs required and
// available.
func (n *nodeStore) hasMinimumIPsInPool() (minimumReached bool, required, numAvailable int) {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	if n.ownNode == nil {
		return
	}

	switch {
	case n.ownNode.Spec.IPAM.MinAllocate != 0:
		required = n.ownNode.Spec.IPAM.MinAllocate
	case n.ownNode.Spec.ENI.MinAllocate != 0:
		required = n.ownNode.Spec.ENI.MinAllocate
	case n.ownNode.Spec.IPAM.PreAllocate != 0:
		required = n.ownNode.Spec.IPAM.PreAllocate
	case n.ownNode.Spec.ENI.PreAllocate != 0:
		required = n.ownNode.Spec.ENI.PreAllocate
	case n.conf.HealthCheckingEnabled():
		required = 2
	default:
		required = 1
	}

	if n.ownNode.Spec.IPAM.Pool != nil {
		numAvailable = len(n.ownNode.Spec.IPAM.Pool)
		if len(n.ownNode.Spec.IPAM.Pool) >= required {
			minimumReached = true
		}

		if n.conf.IPAMMode() == ipamOption.IPAMENI {
			if vpcCIDR := deriveVpcCIDR(n.ownNode); vpcCIDR != nil {
				if nativeCIDR := n.conf.IPv4NativeRoutingCIDR(); nativeCIDR != nil {
					logFields := logrus.Fields{
						"vpc-cidr":                   vpcCIDR.String(),
						option.IPv4NativeRoutingCIDR: nativeCIDR.String(),
					}

					ranges4, _ := ip.CoalesceCIDRs([]*net.IPNet{nativeCIDR.IPNet, vpcCIDR.IPNet})
					if len(ranges4) != 1 {
						log.WithFields(logFields).Fatal("Native routing CIDR does not contain VPC CIDR.")
					} else {
						log.WithFields(logFields).Info("Ignoring autodetected VPC CIDR.")
					}
				} else {
					log.WithFields(logrus.Fields{
						"vpc-cidr": vpcCIDR.String(),
					}).Info("Using autodetected VPC CIDR.")
					n.conf.SetIPv4NativeRoutingCIDR(vpcCIDR)
				}
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

	if n.conf.IPAMMode() == ipamOption.IPAMENI {
		// FIXME: no need to convert to nodeTypes.Node
		var newNode, oldNode *nodeTypes.Node
		if n.ownNode != nil {
			n := nodeTypes.ParseCiliumNode(n.ownNode)
			oldNode = &n
		}
		if node != nil {
			n := nodeTypes.ParseCiliumNode(node)
			newNode = &n
		}

		if err := updateENIRulesAndRoutes(oldNode, newNode); err != nil {
			log.WithError(err).Errorf("Failed to update routes and rules for ENIs")
		}
	}

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

	node.Status.IPAM.Used = ipamTypes.AllocationMap{}

	for _, a := range staleCopyOfAllocators {
		a.mutex.RLock()
		for ip, ipInfo := range a.allocated {
			node.Status.IPAM.Used[ip] = ipInfo
		}
		a.mutex.RUnlock()
	}

	var err error
	ciliumClient := k8s.CiliumClient()
	_, err = ciliumClient.CiliumV2().CiliumNodes().UpdateStatus(context.TODO(), node, metav1.UpdateOptions{})

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

	ipInfo, ok := n.ownNode.Spec.IPAM.Pool[ip.String()]
	if !ok {
		return nil, fmt.Errorf("IP %s is not available", ip.String())
	}

	return &ipInfo, nil
}

// allocateNext allocates the next available IP or returns an error
func (n *nodeStore) allocateNext(allocated ipamTypes.AllocationMap, family Family) (net.IP, *ipamTypes.AllocationIP, error) {
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
	allocated ipamTypes.AllocationMap

	// family is the address family this allocator is allocator for
	family Family

	conf Configuration
}

// newCRDAllocator creates a new CRD-backed IP allocator
func newCRDAllocator(family Family, c Configuration, owner Owner, k8sEventReg K8sEventRegister) Allocator {
	initNodeStore.Do(func() {
		sharedNodeStore = newNodeStore(nodeTypes.GetName(), c, owner, k8sEventReg)
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

func deriveGatewayIP(eni eniTypes.ENI) string {
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
				if a.conf.IPv4NativeRoutingCIDR() != nil {
					result.CIDRs = append(result.CIDRs, a.conf.IPv4NativeRoutingCIDR().String())
				}
				if eni.Subnet.CIDR != "" {
					result.GatewayIP = deriveGatewayIP(eni)
				}
				result.InterfaceNumber = strconv.Itoa(eni.Number)

				return
			}
		}

		result = nil
		err = fmt.Errorf("unable to find ENI %s", ipInfo.Resource)

	// In Azure mode, the Resource points to the azure interface so we can
	// derive the master interface
	case ipamOption.IPAMAzure:
		for _, iface := range a.store.ownNode.Status.Azure.Interfaces {
			if iface.ID == ipInfo.Resource {
				result.PrimaryMAC = iface.MAC
				result.GatewayIP = iface.GatewayIP
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
func (a *crdAllocator) markAllocated(ip net.IP, owner string, ipInfo ipamTypes.AllocationIP) {
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

// Dump provides a status report and lists all allocated IP addresses
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
	a.store.restoreCloseOnce.Do(func() {
		close(a.store.restoreFinished)
	})
}
