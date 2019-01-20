// Copyright 2018-2019 Authors of Cilium
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

package linux

import (
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/tunnel"
	"github.com/cilium/cilium/pkg/node"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

type linuxNodeHandler struct {
	mutex          lock.Mutex
	isInitialized  bool
	nodeConfig     datapath.LocalNodeConfiguration
	nodeAddressing datapath.NodeAddressing
	datapathConfig DatapathConfiguration
	nodes          map[node.Identity]*node.Node
}

// NewNodeHandler returns a new node handler to handle node events and
// implement the implications in the Linux datapath
func NewNodeHandler(datapathConfig DatapathConfiguration, nodeAddressing datapath.NodeAddressing) datapath.NodeHandler {
	return &linuxNodeHandler{
		nodeAddressing: nodeAddressing,
		datapathConfig: datapathConfig,
		nodes:          map[node.Identity]*node.Node{},
	}
}

// updateTunnelMapping is called when a node update is received while running
// with encapsulation mode enabled. The CIDR and IP of both the old and new
// node are provided as context. The caller expects the tunnel mapping in the
// datapath to be updated.
func updateTunnelMapping(oldCIDR, newCIDR *cidr.CIDR, oldIP, newIP net.IP, firstAddition, encapEnabled bool) {
	if !encapEnabled {
		// When the protocol family is disabled, the initial node addition will
		// trigger a deletion to clean up leftover entries. The deletion happens
		// in quiet mode as we don't know whether it exists or not
		if newCIDR != nil && firstAddition {
			deleteTunnelMapping(newCIDR, true)
		}

		return
	}

	if cidrNodeMappingUpdateRequired(oldCIDR, newCIDR, oldIP, newIP) {
		log.WithFields(logrus.Fields{
			logfields.IPAddr: newIP,
			"allocCIDR":      newCIDR,
		}).Debug("Updating tunnel map entry")

		if err := tunnel.TunnelMap.SetTunnelEndpoint(newCIDR.IP, newIP); err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				"allocCIDR": newCIDR,
			}).Error("bpf: Unable to update in tunnel endpoint map")
		}
	}

	// Determine whether an old tunnel mapping must be cleaned up. The
	// below switch lists all conditions in which case the oldCIDR must be
	// removed from the tunnel mapping
	switch {
	// CIDR no longer announced
	case newCIDR == nil && oldCIDR != nil:
		fallthrough
	// Node allocation CIDR has changed
	case oldCIDR != nil && newCIDR != nil && !oldCIDR.IP.Equal(newCIDR.IP):
		deleteTunnelMapping(oldCIDR, false)
	}
}

// cidrNodeMappingUpdateRequired returns true if the change from an old node
// CIDR and node IP to a new node CIDR and node IP requires to insert/update
// the new node CIDR.
func cidrNodeMappingUpdateRequired(oldCIDR, newCIDR *cidr.CIDR, oldIP, newIP net.IP) bool {
	// Newly announced CIDR
	if newCIDR != nil && oldCIDR == nil {
		return true
	}

	// Change in node IP
	if !oldIP.Equal(newIP) {
		return true
	}

	// CIDR changed
	return oldCIDR != nil && newCIDR != nil && !oldCIDR.IP.Equal(newCIDR.IP)
}

func deleteTunnelMapping(oldCIDR *cidr.CIDR, quietMode bool) {
	if oldCIDR == nil {
		return
	}

	log.WithField("allocCIDR", oldCIDR).Debug("Deleting tunnel map entry")

	if err := tunnel.TunnelMap.DeleteTunnelEndpoint(oldCIDR.IP); err != nil {
		if !quietMode {
			log.WithError(err).WithFields(logrus.Fields{
				"allocCIDR": oldCIDR,
			}).Error("Unable to delete in tunnel endpoint map")
		}
	}
}

func createDirectRouteSpec(CIDR *cidr.CIDR, nodeIP net.IP) (routeSpec *netlink.Route, err error) {
	var routes []netlink.Route

	routeSpec = &netlink.Route{
		Dst: CIDR.IPNet,
		Gw:  nodeIP,
	}

	routes, err = netlink.RouteGet(nodeIP)
	if err != nil {
		err = fmt.Errorf("unable to lookup route for node %s: %s", nodeIP, err)
		return
	}

	if len(routes) == 0 {
		err = fmt.Errorf("no route found to destination %s", nodeIP.String())
		return
	}

	if routes[0].Gw != nil && !routes[0].Gw.IsUnspecified() {
		err = fmt.Errorf("route to destination %s contains gateway %s, must be directly reachable",
			nodeIP, routes[0].Gw.String())
		return
	}

	linkIndex := routes[0].LinkIndex

	// Special treatment if the route points to the loopback, lookup the
	// local route and use that ifindex
	if linkIndex == 1 {
		family := netlink.FAMILY_V4
		dst := &net.IPNet{IP: nodeIP, Mask: net.CIDRMask(32, 32)}
		if nodeIP.To4() == nil {
			family = netlink.FAMILY_V6
			dst.Mask = net.CIDRMask(128, 128)
		}

		filter := &netlink.Route{
			Table: 255, // local table
			Dst:   dst,
		}

		routes, err = netlink.RouteListFiltered(family, filter, netlink.RT_FILTER_DST|netlink.RT_FILTER_TABLE)
		if err != nil {
			err = fmt.Errorf("unable to find local route for destination %s: %s", nodeIP, err)
			return
		}

		if len(routes) == 0 {
			err = fmt.Errorf("unable to find local route for destination %s which is routed over loopback", nodeIP)
			return
		}

		linkIndex = routes[0].LinkIndex
	}

	routeSpec.LinkIndex = linkIndex

	return
}

func installDirectRoute(CIDR *cidr.CIDR, nodeIP net.IP) (routeSpec *netlink.Route, err error) {
	routeSpec, err = createDirectRouteSpec(CIDR, nodeIP)
	if err != nil {
		return
	}

	err = netlink.RouteReplace(routeSpec)
	return
}

func (n *linuxNodeHandler) lookupDirectRoute(CIDR *cidr.CIDR, nodeIP net.IP) ([]netlink.Route, error) {
	routeSpec, err := createDirectRouteSpec(CIDR, nodeIP)
	if err != nil {
		return nil, err
	}

	family := netlink.FAMILY_V4
	if nodeIP.To4() == nil {
		family = netlink.FAMILY_V6
	}
	return netlink.RouteListFiltered(family, routeSpec, netlink.RT_FILTER_DST|netlink.RT_FILTER_GW|netlink.RT_FILTER_OIF)
}

func (n *linuxNodeHandler) updateDirectRoute(oldCIDR, newCIDR *cidr.CIDR, oldIP, newIP net.IP, firstAddition, directRouteEnabled bool) error {
	if !directRouteEnabled {
		// When the protocol family is disabled, the initial node addition will
		// trigger a deletion to clean up leftover entries. The deletion happens
		// in quiet mode as we don't know whether it exists or not
		if newCIDR != nil && firstAddition {
			n.deleteDirectRoute(newCIDR, newIP)
		}
		return nil
	}

	if cidrNodeMappingUpdateRequired(oldCIDR, newCIDR, oldIP, newIP) {
		log.WithFields(logrus.Fields{
			logfields.IPAddr: newIP,
			"allocCIDR":      newCIDR,
		}).Debug("Updating direct route")

		if routeSpec, err := installDirectRoute(newCIDR, newIP); err != nil {
			log.WithError(err).Warningf("Unable to install direct node route %s", routeSpec.String())
			return err
		}
	}

	// Determine whether an old route must be deleted. The below switch
	// lists all conditions in which case the route derived from oldCIDR
	// and oldIP must be deleted.
	switch {
	// CIDR no longer announced
	case newCIDR == nil && oldCIDR != nil:
		fallthrough
	// node IP has changed
	case !oldIP.Equal(newIP):
		fallthrough
	// Node allocation CIDR has changed
	case oldCIDR != nil && newCIDR != nil && !oldCIDR.IP.Equal(newCIDR.IP):
		n.deleteDirectRoute(oldCIDR, oldIP)
	}

	return nil
}

func (n *linuxNodeHandler) deleteDirectRoute(CIDR *cidr.CIDR, nodeIP net.IP) {
	if CIDR == nil {
		return
	}

	family := netlink.FAMILY_V4
	if CIDR.IP.To4() == nil {
		family = netlink.FAMILY_V6
	}

	filter := &netlink.Route{
		Dst: CIDR.IPNet,
		Gw:  nodeIP,
	}

	routes, err := netlink.RouteListFiltered(family, filter, netlink.RT_FILTER_DST|netlink.RT_FILTER_GW)
	if err != nil {
		log.WithError(err).Error("Unable to list direct routes")
		return
	}

	for _, rt := range routes {
		if err := netlink.RouteDel(&rt); err != nil {
			log.WithError(err).Warningf("Unable to delete direct node route %s", rt.String())
		}
	}
}

// createNodeRoute creates a route that points the specified prefix to the host
// device via the router IP
//
// Example:
// 10.10.0.0/24 via 10.10.0.1 dev cilium_host src 10.10.0.1
// f00d::a0a:0:0:0/112 via f00d::a0a:0:0:1 dev cilium_host src fd04::11 metric 1024 pref medium
//
func (n *linuxNodeHandler) createNodeRoute(prefix *cidr.CIDR) route.Route {
	var local, nexthop net.IP
	if prefix.IP.To4() != nil {
		nexthop = n.nodeAddressing.IPv4().Router()
		local = nexthop
	} else {
		nexthop = n.nodeAddressing.IPv6().Router()
		local = n.nodeAddressing.IPv6().PrimaryExternal()
	}

	return route.Route{
		Nexthop: &nexthop,
		Local:   local,
		Device:  n.datapathConfig.HostDevice,
		Prefix:  *prefix.IPNet,
	}
}

func (n *linuxNodeHandler) lookupNodeRoute(prefix *cidr.CIDR) (*route.Route, error) {
	return route.Lookup(n.createNodeRoute(prefix))
}

func (n *linuxNodeHandler) updateNodeRoute(prefix *cidr.CIDR, addressFamilyEnabled bool) error {
	if prefix == nil || !addressFamilyEnabled {
		return nil
	}

	nodeRoute := n.createNodeRoute(prefix)
	if _, err := route.Upsert(nodeRoute, n.nodeConfig.MtuConfig); err != nil {
		log.WithError(err).WithFields(nodeRoute.LogFields()).Warning("Unable to update route")
		return err
	}

	return nil
}

func (n *linuxNodeHandler) deleteNodeRoute(prefix *cidr.CIDR) error {
	if prefix == nil {
		return nil
	}

	nodeRoute := n.createNodeRoute(prefix)
	if err := route.Delete(nodeRoute); err != nil {
		log.WithError(err).WithFields(nodeRoute.LogFields()).Warning("Unable to delete route")
		return err
	}

	return nil
}

func (n *linuxNodeHandler) familyEnabled(c *cidr.CIDR) bool {
	return (c.IP.To4() != nil && n.nodeConfig.EnableIPv4) || (c.IP.To4() == nil && n.nodeConfig.EnableIPv6)
}

func (n *linuxNodeHandler) updateOrRemoveNodeRoutes(old, new []*cidr.CIDR) {
	addedAuxRoutes, removedAuxRoutes := cidr.DiffCIDRLists(old, new)
	for _, prefix := range addedAuxRoutes {
		n.updateNodeRoute(prefix, n.familyEnabled(prefix))
	}
	for _, prefix := range removedAuxRoutes {
		if rt, _ := n.lookupNodeRoute(prefix); rt != nil {
			n.deleteNodeRoute(prefix)
		}
	}
}

func (n *linuxNodeHandler) NodeAdd(newNode node.Node) error {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	n.nodes[newNode.Identity()] = &newNode

	if n.isInitialized {
		return n.nodeUpdate(nil, &newNode)
	}

	return nil
}

func (n *linuxNodeHandler) NodeUpdate(oldNode, newNode node.Node) error {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	n.nodes[newNode.Identity()] = &newNode

	if n.isInitialized {
		return n.nodeUpdate(&oldNode, &newNode)
	}

	return nil
}

func (n *linuxNodeHandler) nodeUpdate(oldNode, newNode *node.Node) error {
	var (
		oldIP4Cidr, oldIP6Cidr *cidr.CIDR
		oldIP4, oldIP6         net.IP
		newIP4                 = newNode.GetNodeIP(false)
		newIP6                 = newNode.GetNodeIP(true)
		firstAddition          = oldNode == nil
	)

	if oldNode != nil {
		oldIP4Cidr = cidr.NewCIDR(oldNode.IPv4AllocCIDR)
		oldIP6Cidr = cidr.NewCIDR(oldNode.IPv6AllocCIDR)
		oldIP4 = oldNode.GetNodeIP(false)
		oldIP6 = oldNode.GetNodeIP(true)
	}

	if newNode.IsLocal() {
		if n.nodeConfig.EnableLocalNodeRoute {
			n.updateOrRemoveNodeRoutes([]*cidr.CIDR{oldIP4Cidr}, []*cidr.CIDR{cidr.NewCIDR(newNode.IPv4AllocCIDR)})
			n.updateOrRemoveNodeRoutes([]*cidr.CIDR{oldIP6Cidr}, []*cidr.CIDR{cidr.NewCIDR(newNode.IPv6AllocCIDR)})
		}
		return nil
	}

	if n.nodeConfig.EnableAutoDirectRouting {
		n.updateDirectRoute(oldIP4Cidr, cidr.NewCIDR(newNode.IPv4AllocCIDR), oldIP4, newIP4, firstAddition, n.nodeConfig.EnableIPv4)
		n.updateDirectRoute(oldIP6Cidr, cidr.NewCIDR(newNode.IPv6AllocCIDR), oldIP6, newIP6, firstAddition, n.nodeConfig.EnableIPv6)
		return nil
	} else if oldNode == nil {
		// When direct routing is disabled, then the initial node
		// addition triggers a removal of eventual old tunnel map
		// entries.
		n.deleteDirectRoute(cidr.NewCIDR(newNode.IPv4AllocCIDR), newIP4)
		n.deleteDirectRoute(cidr.NewCIDR(newNode.IPv6AllocCIDR), newIP6)
	}

	if n.nodeConfig.EnableEncapsulation {
		// Update the tunnel mapping of the node. In case the
		// node has changed its CIDR range, a new entry in the
		// map is created and the old entry is removed.
		updateTunnelMapping(oldIP4Cidr, cidr.NewCIDR(newNode.IPv4AllocCIDR), oldIP4, newIP4, firstAddition, n.nodeConfig.EnableIPv4)
		// Not a typo, the IPv4 host IP is used to build the IPv6 overlay
		updateTunnelMapping(oldIP6Cidr, cidr.NewCIDR(newNode.IPv6AllocCIDR), oldIP4, newIP4, firstAddition, n.nodeConfig.EnableIPv6)

		if !n.nodeConfig.UseSingleClusterRoute {
			n.updateOrRemoveNodeRoutes([]*cidr.CIDR{oldIP4Cidr}, []*cidr.CIDR{cidr.NewCIDR(newNode.IPv4AllocCIDR)})
			n.updateOrRemoveNodeRoutes([]*cidr.CIDR{oldIP6Cidr}, []*cidr.CIDR{cidr.NewCIDR(newNode.IPv6AllocCIDR)})
		}

		return nil
	} else if oldNode == nil {
		ip4CIDR := cidr.NewCIDR(newNode.IPv4AllocCIDR)
		ip6CIDR := cidr.NewCIDR(newNode.IPv6AllocCIDR)

		// When encapsulation is disabled, then the initial node addition
		// triggers a removal of eventual old tunnel map entries.
		deleteTunnelMapping(ip4CIDR, true)
		deleteTunnelMapping(ip6CIDR, true)

		if rt, _ := n.lookupNodeRoute(ip4CIDR); rt != nil {
			n.deleteNodeRoute(ip4CIDR)
		}
		if rt, _ := n.lookupNodeRoute(ip6CIDR); rt != nil {
			n.deleteNodeRoute(ip6CIDR)
		}
	}

	return nil
}

func (n *linuxNodeHandler) NodeDelete(oldNode node.Node) error {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	nodeIdentity := oldNode.Identity()
	if oldCachedNode, nodeExists := n.nodes[nodeIdentity]; nodeExists {
		delete(n.nodes, nodeIdentity)

		if n.isInitialized {
			return n.nodeDelete(oldCachedNode)
		}
	}

	return nil
}

func (n *linuxNodeHandler) nodeDelete(oldNode *node.Node) error {
	if oldNode.IsLocal() {
		return nil
	}

	oldIP4 := oldNode.GetNodeIP(false)
	oldIP6 := oldNode.GetNodeIP(true)

	if n.nodeConfig.EnableAutoDirectRouting {
		n.deleteDirectRoute(cidr.NewCIDR(oldNode.IPv4AllocCIDR), oldIP4)
		n.deleteDirectRoute(cidr.NewCIDR(oldNode.IPv6AllocCIDR), oldIP6)
	}

	if n.nodeConfig.EnableEncapsulation {
		deleteTunnelMapping(cidr.NewCIDR(oldNode.IPv4AllocCIDR), false)
		deleteTunnelMapping(cidr.NewCIDR(oldNode.IPv6AllocCIDR), false)

		if !n.nodeConfig.UseSingleClusterRoute {
			n.deleteNodeRoute(cidr.NewCIDR(oldNode.IPv4AllocCIDR))
			n.deleteNodeRoute(cidr.NewCIDR(oldNode.IPv6AllocCIDR))
		}
	}

	return nil
}

func (n *linuxNodeHandler) updateOrRemoveClusterRoute(addressing datapath.NodeAddressingFamily, addressFamilyEnabled bool) {
	allocCIDR := addressing.AllocationCIDR()
	if addressFamilyEnabled {
		n.updateNodeRoute(allocCIDR, addressFamilyEnabled)
	} else if rt, _ := n.lookupNodeRoute(allocCIDR); rt != nil {
		n.deleteNodeRoute(allocCIDR)
	}
}

// NodeConfigurationChanged is called when the LocalNodeConfiguration has changed
func (n *linuxNodeHandler) NodeConfigurationChanged(newConfig datapath.LocalNodeConfiguration) error {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	prevConfig := n.nodeConfig
	n.nodeConfig = newConfig

	n.updateOrRemoveNodeRoutes(prevConfig.AuxiliaryPrefixes, newConfig.AuxiliaryPrefixes)

	if newConfig.UseSingleClusterRoute {
		n.updateOrRemoveClusterRoute(n.nodeAddressing.IPv4(), newConfig.EnableIPv4)
		n.updateOrRemoveClusterRoute(n.nodeAddressing.IPv6(), newConfig.EnableIPv6)
	} else if prevConfig.UseSingleClusterRoute {
		// single cluster route has been disabled, remove route
		n.deleteNodeRoute(n.nodeAddressing.IPv4().AllocationCIDR())
		n.deleteNodeRoute(n.nodeAddressing.IPv6().AllocationCIDR())
	}

	if !n.isInitialized {
		n.isInitialized = true
		if !n.nodeConfig.UseSingleClusterRoute {
			for _, unlinkedNode := range n.nodes {
				n.nodeUpdate(nil, unlinkedNode)
			}
		}
	}

	return nil
}

// NodeValidateImplementation is called to validate the implementation of the
// node in the datapath
func (n *linuxNodeHandler) NodeValidateImplementation(nodeToValidate node.Node) error {
	return n.nodeUpdate(nil, &nodeToValidate)
}
