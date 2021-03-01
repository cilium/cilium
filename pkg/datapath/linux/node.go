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
	"context"
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/counter"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/datapath/linux/arp"
	"github.com/cilium/cilium/pkg/datapath/linux/ipsec"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/neighborsmap"
	"github.com/cilium/cilium/pkg/maps/tunnel"
	"github.com/cilium/cilium/pkg/metrics"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	wildcardIPv4 = "0.0.0.0"
	wildcardIPv6 = "0::0"
	success      = "success"
	failed       = "failed"
)

type linuxNodeHandler struct {
	mutex                lock.Mutex
	isInitialized        bool
	nodeConfig           datapath.LocalNodeConfiguration
	nodeAddressing       datapath.NodeAddressing
	datapathConfig       DatapathConfiguration
	nodes                map[nodeTypes.Identity]*nodeTypes.Node
	enableNeighDiscovery bool
	neighNextHopByNode   map[nodeTypes.Identity]string // val = string(net.IP)
	neighNextHopRefCount counter.StringCounter
	neighByNextHop       map[string]*netlink.Neigh // key = string(net.IP)
}

// NewNodeHandler returns a new node handler to handle node events and
// implement the implications in the Linux datapath
func NewNodeHandler(datapathConfig DatapathConfiguration, nodeAddressing datapath.NodeAddressing) datapath.NodeHandler {
	return &linuxNodeHandler{
		nodeAddressing:       nodeAddressing,
		datapathConfig:       datapathConfig,
		nodes:                map[nodeTypes.Identity]*nodeTypes.Node{},
		neighNextHopByNode:   map[nodeTypes.Identity]string{},
		neighNextHopRefCount: counter.StringCounter{},
		neighByNextHop:       map[string]*netlink.Neigh{},
	}
}

// updateTunnelMapping is called when a node update is received while running
// with encapsulation mode enabled. The CIDR and IP of both the old and new
// node are provided as context. The caller expects the tunnel mapping in the
// datapath to be updated.
func updateTunnelMapping(oldCIDR, newCIDR *cidr.CIDR, oldIP, newIP net.IP, firstAddition, encapEnabled bool, oldEncryptKey, newEncryptKey uint8) {
	if !encapEnabled {
		// When the protocol family is disabled, the initial node addition will
		// trigger a deletion to clean up leftover entries. The deletion happens
		// in quiet mode as we don't know whether it exists or not
		if newCIDR != nil && firstAddition {
			deleteTunnelMapping(newCIDR, true)
		}

		return
	}

	if cidrNodeMappingUpdateRequired(oldCIDR, newCIDR, oldIP, newIP, oldEncryptKey, newEncryptKey) {
		log.WithFields(logrus.Fields{
			logfields.IPAddr: newIP,
			"allocCIDR":      newCIDR,
		}).Debug("Updating tunnel map entry")

		if err := tunnel.TunnelMap.SetTunnelEndpoint(newEncryptKey, newCIDR.IP, newIP); err != nil {
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
func cidrNodeMappingUpdateRequired(oldCIDR, newCIDR *cidr.CIDR, oldIP, newIP net.IP, oldKey, newKey uint8) bool {
	// No CIDR provided
	if newCIDR == nil {
		return false
	}
	// Newly announced CIDR
	if oldCIDR == nil {
		return true
	}

	// Change in node IP
	if !oldIP.Equal(newIP) {
		return true
	}

	if newKey != oldKey {
		return true
	}

	// CIDR changed
	return !oldCIDR.IP.Equal(newCIDR.IP)
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

	if routes[0].Gw != nil && !routes[0].Gw.IsUnspecified() && !routes[0].Gw.Equal(nodeIP) {
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

	if cidrNodeMappingUpdateRequired(oldCIDR, newCIDR, oldIP, newIP, 0, 0) {
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

// createNodeRouteSpec creates a route spec that points the specified prefix to the host
// device via the router IP. The route is configured with a computed MTU for non-local
// nodes (i.e isLocalNode is set to false).
//
// Example:
// 10.10.0.0/24 via 10.10.0.1 dev cilium_host src 10.10.0.1
// f00d::a0a:0:0:0/112 via f00d::a0a:0:0:1 dev cilium_host src fd04::11 metric 1024 pref medium
//
func (n *linuxNodeHandler) createNodeRouteSpec(prefix *cidr.CIDR, isLocalNode bool) (route.Route, error) {
	var (
		local, nexthop net.IP
		mtu            int
	)
	if prefix.IP.To4() != nil {
		if n.nodeAddressing.IPv4() == nil {
			return route.Route{}, fmt.Errorf("IPv4 addressing unavailable")
		}

		if n.nodeAddressing.IPv4().Router() == nil {
			return route.Route{}, fmt.Errorf("IPv4 router address unavailable")
		}

		nexthop = n.nodeAddressing.IPv4().Router()
		local = nexthop
	} else {
		if n.nodeAddressing.IPv6() == nil {
			return route.Route{}, fmt.Errorf("IPv6 addressing unavailable")
		}

		if n.nodeAddressing.IPv6().Router() == nil {
			return route.Route{}, fmt.Errorf("IPv6 router address unavailable")
		}

		if n.nodeAddressing.IPv6().PrimaryExternal() == nil {
			return route.Route{}, fmt.Errorf("External IPv6 address unavailable")
		}

		nexthop = n.nodeAddressing.IPv6().Router()
		local = n.nodeAddressing.IPv6().PrimaryExternal()
	}

	if !isLocalNode {
		mtu = n.nodeConfig.MtuConfig.GetRouteMTU()
	}

	// The default routing table accounts for encryption overhead for encrypt-node traffic
	return route.Route{
		Nexthop: &nexthop,
		Local:   local,
		Device:  n.datapathConfig.HostDevice,
		Prefix:  *prefix.IPNet,
		MTU:     mtu,
	}, nil
}

func (n *linuxNodeHandler) lookupNodeRoute(prefix *cidr.CIDR, isLocalNode bool) (*route.Route, error) {
	if prefix == nil {
		return nil, nil
	}

	routeSpec, err := n.createNodeRouteSpec(prefix, isLocalNode)
	if err != nil {
		return nil, err
	}

	return route.Lookup(routeSpec)
}

func (n *linuxNodeHandler) updateNodeRoute(prefix *cidr.CIDR, addressFamilyEnabled bool, isLocalNode bool) error {
	if prefix == nil || !addressFamilyEnabled {
		return nil
	}

	nodeRoute, err := n.createNodeRouteSpec(prefix, isLocalNode)
	if err != nil {
		return err
	}
	if _, err := route.Upsert(nodeRoute); err != nil {
		log.WithError(err).WithFields(nodeRoute.LogFields()).Warning("Unable to update route")
		return err
	}

	return nil
}

func (n *linuxNodeHandler) deleteNodeRoute(prefix *cidr.CIDR, isLocalNode bool) error {
	if prefix == nil {
		return nil
	}

	nodeRoute, err := n.createNodeRouteSpec(prefix, isLocalNode)
	if err != nil {
		return err
	}
	if err := route.Delete(nodeRoute); err != nil {
		log.WithError(err).WithFields(nodeRoute.LogFields()).Warning("Unable to delete route")
		return err
	}

	return nil
}

func (n *linuxNodeHandler) familyEnabled(c *cidr.CIDR) bool {
	return (c.IP.To4() != nil && n.nodeConfig.EnableIPv4) || (c.IP.To4() == nil && n.nodeConfig.EnableIPv6)
}

func (n *linuxNodeHandler) updateOrRemoveNodeRoutes(old, new []*cidr.CIDR, isLocalNode bool) {
	addedAuxRoutes, removedAuxRoutes := cidr.DiffCIDRLists(old, new)
	for _, prefix := range addedAuxRoutes {
		if prefix != nil {
			n.updateNodeRoute(prefix, n.familyEnabled(prefix), isLocalNode)
		}
	}
	for _, prefix := range removedAuxRoutes {
		if rt, _ := n.lookupNodeRoute(prefix, isLocalNode); rt != nil {
			n.deleteNodeRoute(prefix, isLocalNode)
		}
	}
}

func (n *linuxNodeHandler) NodeAdd(newNode nodeTypes.Node) error {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	n.nodes[newNode.Identity()] = &newNode

	if n.isInitialized {
		return n.nodeUpdate(nil, &newNode, true)
	}

	return nil
}

func (n *linuxNodeHandler) NodeUpdate(oldNode, newNode nodeTypes.Node) error {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	n.nodes[newNode.Identity()] = &newNode

	if n.isInitialized {
		return n.nodeUpdate(&oldNode, &newNode, false)
	}

	return nil
}

func upsertIPsecLog(err error, spec string, loc, rem *net.IPNet, spi uint8) {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.Reason: spec,
		"local-ip":       loc,
		"remote-ip":      rem,
		"spi":            spi,
	})
	if err != nil {
		scopedLog.WithError(err).Error("IPsec enable failed")
	} else {
		scopedLog.Debug("IPsec enable succeeded")
	}
}

func getLinkLocalIp(family int) (*net.IPNet, error) {
	link, err := netlink.LinkByName(option.Config.EncryptInterface)
	if err != nil {
		return nil, err
	}
	addr, err := netlink.AddrList(link, family)
	if err != nil {
		return nil, err
	}
	return addr[0].IPNet, nil
}

func getV4LinkLocalIp() (*net.IPNet, error) {
	return getLinkLocalIp(netlink.FAMILY_V4)
}

func getV6LinkLocalIp() (*net.IPNet, error) {
	return getLinkLocalIp(netlink.FAMILY_V6)
}

func (n *linuxNodeHandler) enableSubnetIPsec(v4CIDR, v6CIDR []*net.IPNet) {
	var spi uint8
	var err error
	zeroMark := false

	n.replaceHostRules()

	// In endpoint routes mode we use the stack to route packets after
	// the packet is decrypted so set skb->mark to zero from XFRM stack
	// to avoid confusion in netfilters and conntract that may be using
	// the mark fields. This uses XFRM_OUTPUT_MARK added in 4.14 kernels.
	if option.Config.EnableEndpointRoutes {
		zeroMark = true
	}

	for _, cidr := range v4CIDR {
		ipsecIPv4Wildcard := &net.IPNet{IP: net.ParseIP(wildcardIPv4), Mask: net.IPv4Mask(0, 0, 0, 0)}

		if !option.Config.EnableEndpointRoutes {
			n.replaceNodeIPSecInRoute(cidr)
		}

		n.replaceNodeIPSecOutRoute(cidr)
		spi, err = ipsec.UpsertIPsecEndpoint(ipsecIPv4Wildcard, cidr, ipsecIPv4Wildcard, ipsec.IPSecDirOut, zeroMark)
		upsertIPsecLog(err, "CNI Out IPv4", ipsecIPv4Wildcard, cidr, spi)

		if n.nodeConfig.EncryptNode {
			n.replaceNodeExternalIPSecOutRoute(cidr)
		} else {
			linkAddr, err := getV4LinkLocalIp()
			if err != nil {
				upsertIPsecLog(err, "getV4LinkLocalIP failed", ipsecIPv4Wildcard, cidr, spi)
			}
			spi, err := ipsec.UpsertIPsecEndpoint(linkAddr, ipsecIPv4Wildcard, cidr, ipsec.IPSecDirIn, zeroMark)
			upsertIPsecLog(err, "CNI In IPv4", linkAddr, ipsecIPv4Wildcard, spi)
		}
	}

	for _, cidr := range v6CIDR {
		ipsecIPv6Wildcard := &net.IPNet{IP: net.ParseIP(wildcardIPv6), Mask: net.CIDRMask(0, 0)}

		n.replaceNodeIPSecInRoute(cidr)

		n.replaceNodeIPSecOutRoute(cidr)
		spi, err := ipsec.UpsertIPsecEndpoint(ipsecIPv6Wildcard, cidr, ipsecIPv6Wildcard, ipsec.IPSecDirOut, zeroMark)
		upsertIPsecLog(err, "CNI Out IPv6", cidr, ipsecIPv6Wildcard, spi)

		if n.nodeConfig.EncryptNode {
			n.replaceNodeExternalIPSecOutRoute(cidr)
		} else {
			linkAddr, err := getV6LinkLocalIp()
			if err != nil {
				upsertIPsecLog(err, "getV6LinkLocalIP failed", ipsecIPv6Wildcard, cidr, spi)
			}
			spi, err := ipsec.UpsertIPsecEndpoint(linkAddr, ipsecIPv6Wildcard, cidr, ipsec.IPSecDirIn, zeroMark)
			upsertIPsecLog(err, "CNI In IPv6", linkAddr, ipsecIPv6Wildcard, spi)
		}
	}
}

func (n *linuxNodeHandler) encryptNode(newNode *nodeTypes.Node) {
	var spi uint8
	var err error

	if n.nodeConfig.EnableIPv4 && n.nodeConfig.EncryptNode {
		internalIPv4 := n.nodeAddressing.IPv4().PrimaryExternal()
		exactMask := net.IPv4Mask(255, 255, 255, 255)
		ipsecLocal := &net.IPNet{IP: internalIPv4, Mask: exactMask}
		if newNode.IsLocal() {
			ipsecIPv4Wildcard := &net.IPNet{IP: net.ParseIP(wildcardIPv4), Mask: net.IPv4Mask(0, 0, 0, 0)}
			n.replaceNodeIPSecInRoute(ipsecLocal)
			spi, err = ipsec.UpsertIPsecEndpoint(ipsecLocal, ipsecIPv4Wildcard, ipsecLocal, ipsec.IPSecDirIn, false)
			upsertIPsecLog(err, "EncryptNode local IPv4", ipsecLocal, ipsecIPv4Wildcard, spi)
		} else {
			if remoteIPv4 := newNode.GetNodeIP(false); remoteIPv4 != nil {
				ipsecRemote := &net.IPNet{IP: remoteIPv4, Mask: exactMask}
				n.replaceNodeExternalIPSecOutRoute(ipsecRemote)
				spi, err = ipsec.UpsertIPsecEndpoint(ipsecLocal, ipsecRemote, ipsecLocal, ipsec.IPSecDirOutNode, false)
				upsertIPsecLog(err, "EncryptNode IPv4", ipsecLocal, ipsecRemote, spi)
			}
			remoteIPv4 := newNode.GetCiliumInternalIP(false)
			if remoteIPv4 != nil && !n.subnetEncryption() {
				mask := newNode.IPv4AllocCIDR.Mask
				ipsecRemoteRoute := &net.IPNet{IP: remoteIPv4.Mask(mask), Mask: mask}
				ipsecRemote := &net.IPNet{IP: remoteIPv4, Mask: mask}
				ipsecWildcard := &net.IPNet{IP: net.ParseIP(wildcardIPv4), Mask: net.IPv4Mask(0, 0, 0, 0)}

				n.replaceNodeExternalIPSecOutRoute(ipsecRemoteRoute)
				if remoteIPv4T := newNode.GetNodeIP(false); remoteIPv4T != nil {
					ipsecRemoteT := &net.IPNet{IP: remoteIPv4T, Mask: exactMask}
					err = ipsec.UpsertIPsecEndpointPolicy(ipsecWildcard, ipsecRemote, ipsecLocal, ipsecRemoteT, ipsec.IPSecDirOutNode)
				}
				upsertIPsecLog(err, "EncryptNode Cilium IPv4", ipsecWildcard, ipsecRemote, spi)
			}
		}
	}

	if n.nodeConfig.EnableIPv6 && n.nodeConfig.EncryptNode {
		internalIPv6 := n.nodeAddressing.IPv6().PrimaryExternal()
		exactMask := net.CIDRMask(128, 128)
		ipsecLocal := &net.IPNet{IP: internalIPv6, Mask: exactMask}
		if newNode.IsLocal() {
			ipsecIPv6Wildcard := &net.IPNet{IP: net.ParseIP(wildcardIPv6), Mask: net.CIDRMask(0, 0)}
			n.replaceNodeIPSecInRoute(ipsecLocal)
			spi, err = ipsec.UpsertIPsecEndpoint(ipsecLocal, ipsecIPv6Wildcard, ipsecLocal, ipsec.IPSecDirIn, false)
			upsertIPsecLog(err, "EncryptNode local IPv6", ipsecLocal, ipsecIPv6Wildcard, spi)
		} else {
			if remoteIPv6 := newNode.GetNodeIP(true); remoteIPv6 != nil {
				ipsecRemote := &net.IPNet{IP: remoteIPv6, Mask: exactMask}
				n.replaceNodeExternalIPSecOutRoute(ipsecRemote)
				spi, err = ipsec.UpsertIPsecEndpoint(ipsecLocal, ipsecRemote, ipsecLocal, ipsec.IPSecDirOut, false)
				upsertIPsecLog(err, "EncryptNode IPv6", ipsecLocal, ipsecRemote, spi)
			}
			remoteIPv6 := newNode.GetCiliumInternalIP(true)
			if remoteIPv6 != nil && !n.subnetEncryption() {
				mask := newNode.IPv6AllocCIDR.Mask
				ipsecRemoteRoute := &net.IPNet{IP: remoteIPv6.Mask(mask), Mask: mask}
				ipsecRemote := &net.IPNet{IP: remoteIPv6, Mask: mask}
				ipsecWildcard := &net.IPNet{IP: net.ParseIP(wildcardIPv6), Mask: net.CIDRMask(0, 0)}

				n.replaceNodeExternalIPSecOutRoute(ipsecRemoteRoute)
				if remoteIPv6T := newNode.GetNodeIP(true); remoteIPv6T != nil {
					ipsecRemoteT := &net.IPNet{IP: remoteIPv6T, Mask: exactMask}
					err = ipsec.UpsertIPsecEndpointPolicy(ipsecWildcard, ipsecRemote, ipsecLocal, ipsecRemoteT, ipsec.IPSecDirOutNode)
				}
				upsertIPsecLog(err, "EncryptNode Cilium IPv6", ipsecWildcard, ipsecRemote, spi)
			}
		}
	}

}

func (n *linuxNodeHandler) getSrcAndNextHopIPv4(nodeIPv4 net.IP, ifaceName string) (srcIPv4, nextHopIPv4 net.IP, err error) {
	// Figure out whether nodeIPv4 is directly reachable (i.e. in the same L2)
	routes, err := netlink.RouteGet(nodeIPv4)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to retrieve route for remote node IP: %w", err)
	}

	if len(routes) == 0 {
		return nil, nil, fmt.Errorf("remote node IP is non-routable")
	}

	// Use the first available route by default
	srcIPv4 = make(net.IP, net.IPv4len)
	nextHopIPv4 = nodeIPv4
	copy(srcIPv4, routes[0].Src.To4())

	for _, route := range routes {
		if route.Gw != nil {
			// nodeIPv4 is in a different L2 subnet, so it must be reachable through
			// a gateway. Send arping to the gw IP addr instead of nodeIPv4.
			// NOTE: we currently don't handle multipath, so only one gw can be used.
			copy(srcIPv4, route.Src.To4())
			copy(nextHopIPv4, route.Gw.To4())
			break
		}
	}
	return srcIPv4, nextHopIPv4, nil
}

// insertNeighbor inserts a permanent ARP entry for a nexthop to the given
// "newNode" (ip route get newNodeIP.GetNodeIP()). The L2 addr of the nexthop
// is determined by sending ARP request for the nexthop from an iface specified
// by the given "ifaceName".
//
// The given "refresh" param denotes whether the method is called by a controller
// which tries to update ARP entries previously inserted by insertNeighbor(). In
// this case it does not bail out early if the ARP entry already exists, and
// sends the ARP request anyway.
//
// The method must be called with linuxNodeHandler.mutex held.
func (n *linuxNodeHandler) insertNeighbor(ctx context.Context, newNode *nodeTypes.Node, ifaceName string, refresh bool) {
	if newNode.IsLocal() {
		return
	}

	newNodeIP := newNode.GetNodeIP(false).To4()
	nextHopIPv4 := make(net.IP, len(newNodeIP))
	copy(nextHopIPv4, newNodeIP)

	scopedLog := log.WithFields(logrus.Fields{
		logfields.LogSubsys: "node-neigh",
		logfields.Interface: ifaceName,
		logfields.IPAddr:    newNodeIP,
	})

	srcIPv4, nextHopIPv4, err := n.getSrcAndNextHopIPv4(nextHopIPv4, ifaceName)
	if err != nil {
		scopedLog.WithError(err).Error("Failed to determine source and nexthop IP addr")
		return
	}

	scopedLog = scopedLog.WithField(logfields.IPAddr, nextHopIPv4)

	nextHopStr := nextHopIPv4.String()
	if existingNextHopStr, found := n.neighNextHopByNode[newNode.Identity()]; found {
		if existingNextHopStr == nextHopStr {
			// We already know about the nextHop of the given newNode. Can happen
			// when insertNeighbor is called by NodeUpdate multiple times for
			// the same node.
			if !refresh {
				// In the case of refresh, don't return early, as we want to
				// update the related neigh entry even if the nextHop is the same
				// (e.g. to detect the GW MAC addr change).
				return
			}
		} else if n.neighNextHopRefCount.Delete(existingNextHopStr) {
			// nextHop has changed and nobody else is using it, so remove the old one.
			neigh, found := n.neighByNextHop[existingNextHopStr]
			if found {
				if err := netlink.NeighDel(neigh); err != nil {
					scopedLog.WithFields(logrus.Fields{
						logfields.IPAddr:       neigh.IP,
						logfields.HardwareAddr: neigh.HardwareAddr,
						logfields.LinkIndex:    neigh.LinkIndex,
					}).WithError(err).Warn("Failed to remove neighbor entry")
				}
				delete(n.neighByNextHop, nextHopStr)
				if option.Config.NodePortHairpin {
					neighborsmap.NeighRetire(net.ParseIP(existingNextHopStr))
				}
			}
		}
	}

	n.neighNextHopByNode[newNode.Identity()] = nextHopStr

	nextHopIsNew := false
	if !refresh {
		nextHopIsNew = n.neighNextHopRefCount.Add(nextHopStr)
	}

	// nextHop hasn't been arpinged before OR we are refreshing neigh entry
	if nextHopIsNew || refresh {
		linkAttr, err := netlink.LinkByName(ifaceName)
		if err != nil {
			scopedLog.WithError(err).Error("Failed to retrieve iface by name (netlink)")
			return
		}
		link := linkAttr.Attrs().Index

		hwAddr, err := arp.PingOverLink(linkAttr, srcIPv4, nextHopIPv4)
		if err != nil {
			scopedLog.WithError(err).Error("arping failed")
			metrics.ArpingRequestsTotal.WithLabelValues(failed).Inc()
			return
		}
		metrics.ArpingRequestsTotal.WithLabelValues(success).Inc()

		if prevHwAddr, found := n.neighByNextHop[nextHopStr]; found && prevHwAddr.String() == hwAddr.String() {
			// Nothing to update, return early to avoid calling to netlink. This
			// is based on the assumption that n.neighByNextHop gets populated
			// after the netlink call to insert the neigh has succeeded.
			return
		}

		if option.Config.NodePortHairpin {
			defer func() {
				// Remove nextHopIPv4 entry in the neigh BPF map. Otherwise,
				// we risk to silently blackhole packets instead of emitting
				// DROP_NO_FIB if the netlink.NeighSet() below fails.
				neighborsmap.NeighRetire(nextHopIPv4)
			}()
		}

		scopedLog = scopedLog.WithField(logfields.HardwareAddr, hwAddr)

		neigh := netlink.Neigh{
			LinkIndex:    link,
			IP:           nextHopIPv4,
			HardwareAddr: hwAddr,
			State:        netlink.NUD_PERMANENT,
		}
		// Don't proceed if the refresh controller cancelled the context
		select {
		case <-ctx.Done():
			return
		default:
		}
		if err := netlink.NeighSet(&neigh); err != nil {
			scopedLog.WithError(err).Error("Failed to insert neighbor")
			return
		}
		n.neighByNextHop[nextHopStr] = &neigh
	}
}

func (n *linuxNodeHandler) refreshNeighbor(ctx context.Context, nodeToRefresh *nodeTypes.Node, ifaceName string, completed chan struct{}) {
	defer close(completed)

	n.mutex.Lock()
	defer n.mutex.Unlock()

	n.insertNeighbor(ctx, nodeToRefresh, ifaceName, true)
}

// Must be called with linuxNodeHandler.mutex held.
func (n *linuxNodeHandler) deleteNeighbor(oldNode *nodeTypes.Node) {
	nextHopStr, found := n.neighNextHopByNode[oldNode.Identity()]
	if !found {
		return
	}
	defer func() { delete(n.neighNextHopByNode, oldNode.Identity()) }()

	if n.neighNextHopRefCount.Delete(nextHopStr) {
		neigh, found := n.neighByNextHop[nextHopStr]
		delete(n.neighByNextHop, nextHopStr)

		if found {
			if err := netlink.NeighDel(neigh); err != nil {
				log.WithFields(logrus.Fields{
					logfields.LogSubsys:    "node-neigh",
					logfields.IPAddr:       neigh.IP,
					logfields.HardwareAddr: neigh.HardwareAddr,
					logfields.LinkIndex:    neigh.LinkIndex,
				}).WithError(err).Warn("Failed to remove neighbor entry")
				return
			}

			if option.Config.NodePortHairpin {
				neighborsmap.NeighRetire(neigh.IP)
			}
		}
	}
}

func (n *linuxNodeHandler) enableIPsec(newNode *nodeTypes.Node) {
	var spi uint8
	var err error

	if newNode.IsLocal() {
		n.replaceHostRules()
	}

	if n.nodeConfig.EnableIPv4 && newNode.IPv4AllocCIDR != nil {
		new4Net := &net.IPNet{IP: newNode.IPv4AllocCIDR.IP, Mask: newNode.IPv4AllocCIDR.Mask}
		if newNode.IsLocal() {
			n.replaceNodeIPSecInRoute(new4Net)
			ciliumInternalIPv4 := newNode.GetCiliumInternalIP(false)
			if ciliumInternalIPv4 != nil {
				ipsecLocal := &net.IPNet{IP: ciliumInternalIPv4, Mask: n.nodeAddressing.IPv4().AllocationCIDR().Mask}
				ipsecIPv4Wildcard := &net.IPNet{IP: net.ParseIP(wildcardIPv4), Mask: net.IPv4Mask(0, 0, 0, 0)}
				spi, err = ipsec.UpsertIPsecEndpoint(ipsecLocal, ipsecIPv4Wildcard, ipsecLocal, ipsec.IPSecDirIn, false)
				upsertIPsecLog(err, "local IPv4", ipsecLocal, ipsecIPv4Wildcard, spi)
			}
		} else {
			if ciliumInternalIPv4 := newNode.GetCiliumInternalIP(false); ciliumInternalIPv4 != nil {
				ipsecLocal := &net.IPNet{IP: n.nodeAddressing.IPv4().Router(), Mask: n.nodeAddressing.IPv4().AllocationCIDR().Mask}
				ipsecRemote := &net.IPNet{IP: ciliumInternalIPv4, Mask: newNode.IPv4AllocCIDR.Mask}
				n.replaceNodeIPSecOutRoute(new4Net)
				spi, err = ipsec.UpsertIPsecEndpoint(ipsecLocal, ipsecRemote, ipsecLocal, ipsec.IPSecDirOut, false)
				upsertIPsecLog(err, "IPv4", ipsecLocal, ipsecRemote, spi)
			}
		}
	}

	if n.nodeConfig.EnableIPv6 && newNode.IPv6AllocCIDR != nil {
		new6Net := &net.IPNet{IP: newNode.IPv6AllocCIDR.IP, Mask: newNode.IPv6AllocCIDR.Mask}
		if newNode.IsLocal() {
			n.replaceNodeIPSecInRoute(new6Net)
			ciliumInternalIPv6 := newNode.GetCiliumInternalIP(true)
			if ciliumInternalIPv6 != nil {
				ipsecLocal := &net.IPNet{IP: ciliumInternalIPv6, Mask: n.nodeAddressing.IPv6().AllocationCIDR().Mask}
				ipsecIPv6Wildcard := &net.IPNet{IP: net.ParseIP(wildcardIPv6), Mask: net.CIDRMask(0, 0)}
				spi, err = ipsec.UpsertIPsecEndpoint(ipsecLocal, ipsecIPv6Wildcard, ipsecLocal, ipsec.IPSecDirIn, false)
				upsertIPsecLog(err, "local IPv6", ipsecLocal, ipsecIPv6Wildcard, spi)
			}
		} else {
			if ciliumInternalIPv6 := newNode.GetCiliumInternalIP(true); ciliumInternalIPv6 != nil {
				ipsecLocal := &net.IPNet{IP: n.nodeAddressing.IPv6().Router(), Mask: net.CIDRMask(0, 0)}
				ipsecRemote := &net.IPNet{IP: ciliumInternalIPv6, Mask: newNode.IPv6AllocCIDR.Mask}
				n.replaceNodeIPSecOutRoute(new6Net)
				spi, err := ipsec.UpsertIPsecEndpoint(ipsecLocal, ipsecRemote, ipsecLocal, ipsec.IPSecDirOut, false)
				upsertIPsecLog(err, "IPv6", ipsecLocal, ipsecRemote, spi)
			}
		}
	}
}

func (n *linuxNodeHandler) subnetEncryption() bool {
	return len(n.nodeConfig.IPv4PodSubnets) > 0 || len(n.nodeConfig.IPv6PodSubnets) > 0
}

// Must be called with linuxNodeHandler.mutex held.
func (n *linuxNodeHandler) nodeUpdate(oldNode, newNode *nodeTypes.Node, firstAddition bool) error {
	var (
		oldIP4Cidr, oldIP6Cidr *cidr.CIDR
		oldIP4, oldIP6         net.IP
		newIP4                 = newNode.GetNodeIP(false)
		newIP6                 = newNode.GetNodeIP(true)
		oldKey, newKey         uint8
		isLocalNode            = false
	)

	if oldNode != nil {
		oldIP4Cidr = oldNode.IPv4AllocCIDR
		oldIP6Cidr = oldNode.IPv6AllocCIDR
		oldIP4 = oldNode.GetNodeIP(false)
		oldIP6 = oldNode.GetNodeIP(true)
		oldKey = oldNode.EncryptionKey
	}

	if n.nodeConfig.EnableIPSec && !n.subnetEncryption() && !n.nodeConfig.EncryptNode {
		n.enableIPsec(newNode)
		newKey = newNode.EncryptionKey
	}

	if n.enableNeighDiscovery {
		var ifaceName string
		if option.Config.EnableNodePort {
			ifaceName = option.Config.DirectRoutingDevice
		} else {
			ifaceName = option.Config.EncryptInterface
		}
		n.insertNeighbor(context.Background(), newNode, ifaceName, false)
	}

	if n.nodeConfig.EnableIPSec && !n.subnetEncryption() {
		n.encryptNode(newNode)
	}

	if newNode.IsLocal() {
		isLocalNode = true
		if n.nodeConfig.EnableLocalNodeRoute {
			n.updateOrRemoveNodeRoutes([]*cidr.CIDR{oldIP4Cidr}, []*cidr.CIDR{newNode.IPv4AllocCIDR}, isLocalNode)
			n.updateOrRemoveNodeRoutes([]*cidr.CIDR{oldIP6Cidr}, []*cidr.CIDR{newNode.IPv6AllocCIDR}, isLocalNode)
		}
		if n.subnetEncryption() {
			n.enableSubnetIPsec(n.nodeConfig.IPv4PodSubnets, n.nodeConfig.IPv6PodSubnets)
		}
		return nil
	}

	if n.nodeConfig.EnableAutoDirectRouting {
		n.updateDirectRoute(oldIP4Cidr, newNode.IPv4AllocCIDR, oldIP4, newIP4, firstAddition, n.nodeConfig.EnableIPv4)
		n.updateDirectRoute(oldIP6Cidr, newNode.IPv6AllocCIDR, oldIP6, newIP6, firstAddition, n.nodeConfig.EnableIPv6)
		return nil
	}

	if n.nodeConfig.EnableEncapsulation {
		// Update the tunnel mapping of the node. In case the
		// node has changed its CIDR range, a new entry in the
		// map is created and the old entry is removed.
		updateTunnelMapping(oldIP4Cidr, newNode.IPv4AllocCIDR, oldIP4, newIP4, firstAddition, n.nodeConfig.EnableIPv4, oldKey, newKey)
		// Not a typo, the IPv4 host IP is used to build the IPv6 overlay
		updateTunnelMapping(oldIP6Cidr, newNode.IPv6AllocCIDR, oldIP4, newIP4, firstAddition, n.nodeConfig.EnableIPv6, oldKey, newKey)

		if !n.nodeConfig.UseSingleClusterRoute {
			n.updateOrRemoveNodeRoutes([]*cidr.CIDR{oldIP4Cidr}, []*cidr.CIDR{newNode.IPv4AllocCIDR}, isLocalNode)
			n.updateOrRemoveNodeRoutes([]*cidr.CIDR{oldIP6Cidr}, []*cidr.CIDR{newNode.IPv6AllocCIDR}, isLocalNode)
		}

		return nil
	} else if firstAddition {
		// When encapsulation is disabled, then the initial node addition
		// triggers a removal of eventual old tunnel map entries.
		deleteTunnelMapping(newNode.IPv4AllocCIDR, true)
		deleteTunnelMapping(newNode.IPv6AllocCIDR, true)

		if rt, _ := n.lookupNodeRoute(newNode.IPv4AllocCIDR, isLocalNode); rt != nil {
			n.deleteNodeRoute(newNode.IPv4AllocCIDR, isLocalNode)
		}
		if rt, _ := n.lookupNodeRoute(newNode.IPv6AllocCIDR, isLocalNode); rt != nil {
			n.deleteNodeRoute(newNode.IPv6AllocCIDR, isLocalNode)
		}
	}

	return nil
}

func (n *linuxNodeHandler) NodeDelete(oldNode nodeTypes.Node) error {
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

// Must be called with linuxNodeHandler.mutex held.
func (n *linuxNodeHandler) nodeDelete(oldNode *nodeTypes.Node) error {
	if oldNode.IsLocal() {
		return nil
	}

	oldIP4 := oldNode.GetNodeIP(false)
	oldIP6 := oldNode.GetNodeIP(true)

	if n.nodeConfig.EnableAutoDirectRouting {
		n.deleteDirectRoute(oldNode.IPv4AllocCIDR, oldIP4)
		n.deleteDirectRoute(oldNode.IPv6AllocCIDR, oldIP6)
	}

	if n.nodeConfig.EnableEncapsulation {
		deleteTunnelMapping(oldNode.IPv4AllocCIDR, false)
		deleteTunnelMapping(oldNode.IPv6AllocCIDR, false)

		if !n.nodeConfig.UseSingleClusterRoute {
			n.deleteNodeRoute(oldNode.IPv4AllocCIDR, false)
			n.deleteNodeRoute(oldNode.IPv6AllocCIDR, false)
		}
	}

	if n.enableNeighDiscovery {
		n.deleteNeighbor(oldNode)
	}

	if n.nodeConfig.EnableIPSec {
		n.deleteIPsec(oldNode)
	}

	return nil
}

func (n *linuxNodeHandler) updateOrRemoveClusterRoute(addressing datapath.NodeAddressingFamily, addressFamilyEnabled bool) {
	allocCIDR := addressing.AllocationCIDR()
	if addressFamilyEnabled {
		n.updateNodeRoute(allocCIDR, addressFamilyEnabled, false)
	} else if rt, _ := n.lookupNodeRoute(allocCIDR, false); rt != nil {
		n.deleteNodeRoute(allocCIDR, false)
	}
}

func (n *linuxNodeHandler) replaceHostRules() error {
	rule := route.Rule{
		Priority: 1,
		Mask:     linux_defaults.RouteMarkMask,
		Table:    linux_defaults.RouteTableIPSec,
	}

	if n.nodeConfig.EnableIPv4 {
		if !option.Config.EnableEndpointRoutes {
			rule.Mark = linux_defaults.RouteMarkDecrypt
			if err := route.ReplaceRule(rule); err != nil {
				log.WithError(err).Error("Replace IPv4 route decrypt rule failed")
				return err
			}
		}
		rule.Mark = linux_defaults.RouteMarkEncrypt
		if err := route.ReplaceRule(rule); err != nil {
			log.WithError(err).Error("Replace IPv4 route encrypt rule failed")
			return err
		}
	}

	if n.nodeConfig.EnableIPv6 {
		rule.Mark = linux_defaults.RouteMarkDecrypt
		if err := route.ReplaceRuleIPv6(rule); err != nil {
			log.WithError(err).Error("Replace IPv6 route decrypt rule failed")
			return err
		}
		rule.Mark = linux_defaults.RouteMarkEncrypt
		if err := route.ReplaceRuleIPv6(rule); err != nil {
			log.WithError(err).Error("Replace IPv6 route ecrypt rule failed")
			return err
		}
	}

	return nil
}

func (n *linuxNodeHandler) removeEncryptRules() error {
	rule := route.Rule{
		Priority: 1,
		Mask:     linux_defaults.RouteMarkMask,
		Table:    linux_defaults.RouteTableIPSec,
	}

	rule.Mark = linux_defaults.RouteMarkDecrypt
	if err := route.DeleteRule(rule); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("Delete previous IPv4 decrypt rule failed: %s", err)
		}
	}

	rule.Mark = linux_defaults.RouteMarkEncrypt
	if err := route.DeleteRule(rule); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("Delete previousa IPv4 encrypt rule failed: %s", err)
		}
	}

	rule.Mark = linux_defaults.RouteMarkDecrypt
	if err := route.DeleteRuleIPv6(rule); err != nil {
		if !os.IsNotExist(err) && !errors.Is(err, unix.EAFNOSUPPORT) {
			return fmt.Errorf("Delete previous IPv6 decrypt rule failed: %s", err)
		}
	}

	rule.Mark = linux_defaults.RouteMarkEncrypt
	if err := route.DeleteRuleIPv6(rule); err != nil {
		if !os.IsNotExist(err) && !errors.Is(err, unix.EAFNOSUPPORT) {
			return fmt.Errorf("Delete previous IPv6 encrypt rule failed: %s", err)
		}
	}
	return nil
}

func (n *linuxNodeHandler) createNodeIPSecInRoute(ip *net.IPNet) route.Route {
	var device string

	if option.Config.Tunnel == option.TunnelDisabled {
		device = n.datapathConfig.EncryptInterface
	} else {
		device = linux_defaults.TunnelDeviceName
	}
	return route.Route{
		Nexthop: nil,
		Device:  device,
		Prefix:  *ip,
		Table:   linux_defaults.RouteTableIPSec,
		Proto:   linux_defaults.RouteProtocolIPSec,
		Type:    route.RTN_LOCAL,
	}
}

func (n *linuxNodeHandler) createNodeIPSecOutRoute(ip *net.IPNet) route.Route {
	return route.Route{
		Nexthop: nil,
		Device:  n.datapathConfig.HostDevice,
		Prefix:  *ip,
		Table:   linux_defaults.RouteTableIPSec,
		MTU:     n.nodeConfig.MtuConfig.GetRoutePostEncryptMTU(),
	}
}

func (n *linuxNodeHandler) createNodeExternalIPSecOutRoute(ip *net.IPNet, dflt bool) route.Route {
	var tbl int
	var dev string
	var mtu int

	if dflt {
		dev = n.datapathConfig.HostDevice
		mtu = n.nodeConfig.MtuConfig.GetRouteMTU()
	} else {
		tbl = linux_defaults.RouteTableIPSec
		dev = n.datapathConfig.HostDevice
		mtu = n.nodeConfig.MtuConfig.GetRoutePostEncryptMTU()
	}

	// The default routing table accounts for encryption overhead for encrypt-node traffic
	return route.Route{
		Device: dev,
		Prefix: *ip,
		Table:  tbl,
		Proto:  route.EncryptRouteProtocol,
		MTU:    mtu,
	}
}

// replaceNodeIPSecOutRoute replace the out IPSec route in the host routing table
// with the new route. If no route exists the route is installed on the host.
func (n *linuxNodeHandler) replaceNodeIPSecOutRoute(ip *net.IPNet) {
	if ip == nil {
		return
	}

	if ip.IP.To4() != nil {
		if !n.nodeConfig.EnableIPv4 {
			return
		}
	} else {
		if !n.nodeConfig.EnableIPv6 {
			return
		}
	}

	_, err := route.Upsert(n.createNodeIPSecOutRoute(ip))
	if err != nil {
		log.WithError(err).Error("Unable to replace the IPSec route OUT the host routing table")
	}
}

// replaceNodeExternalIPSecOutRoute replace the out IPSec route in the host routing table
// with the new route. If no route exists the route is installed on the host.
func (n *linuxNodeHandler) replaceNodeExternalIPSecOutRoute(ip *net.IPNet) {
	if ip == nil {
		return
	}

	if ip.IP.To4() != nil {
		if !n.nodeConfig.EnableIPv4 {
			return
		}
	} else {
		if !n.nodeConfig.EnableIPv6 {
			return
		}
	}

	_, err := route.Upsert(n.createNodeExternalIPSecOutRoute(ip, true))
	if err != nil {
		log.WithError(err).Error("Unable to replace the IPSec route OUT the default routing table")
	}
	_, err = route.Upsert(n.createNodeExternalIPSecOutRoute(ip, false))
	if err != nil {
		log.WithError(err).Error("Unable to replace the IPSec route OUT the host routing table")
	}
}

func (n *linuxNodeHandler) deleteNodeIPSecOutRoute(ip *net.IPNet) {
	if ip == nil {
		return
	}

	if ip.IP.To4() != nil {
		if !n.nodeConfig.EnableIPv4 {
			return
		}
	} else {
		if !n.nodeConfig.EnableIPv6 {
			return
		}
	}

	if err := route.Delete(n.createNodeIPSecOutRoute(ip)); err != nil {
		log.WithError(err).Error("Unable to delete the IPsec route OUT from the host routing table")
	}
}

func (n *linuxNodeHandler) deleteNodeExternalIPSecOutRoute(ip *net.IPNet) {
	if ip == nil {
		return
	}

	if ip.IP.To4() != nil {
		if !n.nodeConfig.EnableIPv4 {
			return
		}
	} else {
		if !n.nodeConfig.EnableIPv6 {
			return
		}
	}

	if err := route.Delete(n.createNodeExternalIPSecOutRoute(ip, true)); err != nil {
		log.WithError(err).Error("Unable to delete the IPsec route External OUT from the ipsec routing table")
	}

	if err := route.Delete(n.createNodeExternalIPSecOutRoute(ip, false)); err != nil {
		log.WithError(err).Error("Unable to delete the IPsec route External OUT from the host routing table")
	}
}

// replaceNodeIPSecoInRoute replace the in IPSec routes in the host routing table
// with the new route. If no route exists the route is installed on the host.
func (n *linuxNodeHandler) replaceNodeIPSecInRoute(ip *net.IPNet) {
	if ip == nil {
		return
	}

	if ip.IP.To4() != nil {
		if !n.nodeConfig.EnableIPv4 {
			return
		}
	} else {
		if !n.nodeConfig.EnableIPv6 {
			return
		}
	}

	_, err := route.Upsert(n.createNodeIPSecInRoute(ip))
	if err != nil {
		log.WithError(err).Error("Unable to replace the IPSec route IN the host routing table")
	}
}

func (n *linuxNodeHandler) deleteIPsec(oldNode *nodeTypes.Node) {
	if n.nodeConfig.EnableIPv4 && oldNode.IPv4AllocCIDR != nil {
		ciliumInternalIPv4 := oldNode.GetCiliumInternalIP(false)
		old4Net := &net.IPNet{IP: ciliumInternalIPv4, Mask: oldNode.IPv4AllocCIDR.Mask}
		old4RouteNet := &net.IPNet{IP: oldNode.IPv4AllocCIDR.IP, Mask: oldNode.IPv4AllocCIDR.Mask}
		n.deleteNodeIPSecOutRoute(old4RouteNet)
		ipsec.DeleteIPsecEndpoint(old4Net)
		if n.nodeConfig.EncryptNode {
			if remoteIPv4 := oldNode.GetNodeIP(false); remoteIPv4 != nil {
				exactMask := net.IPv4Mask(255, 255, 255, 255)
				ipsecRemote := &net.IPNet{IP: remoteIPv4, Mask: exactMask}
				n.deleteNodeExternalIPSecOutRoute(ipsecRemote)
			}
		}
	}

	if n.nodeConfig.EnableIPv6 && oldNode.IPv6AllocCIDR != nil {
		ciliumInternalIPv6 := oldNode.GetCiliumInternalIP(true)
		old6Net := &net.IPNet{IP: ciliumInternalIPv6, Mask: oldNode.IPv6AllocCIDR.Mask}
		old6RouteNet := &net.IPNet{IP: oldNode.IPv6AllocCIDR.IP, Mask: oldNode.IPv6AllocCIDR.Mask}
		n.deleteNodeIPSecOutRoute(old6RouteNet)
		ipsec.DeleteIPsecEndpoint(old6Net)
		if n.nodeConfig.EncryptNode {
			if remoteIPv6 := oldNode.GetNodeIP(true); remoteIPv6 != nil {
				exactMask := net.CIDRMask(128, 128)
				ipsecRemote := &net.IPNet{IP: remoteIPv6, Mask: exactMask}
				n.deleteNodeExternalIPSecOutRoute(ipsecRemote)
			}
		}
	}
}

// NodeConfigurationChanged is called when the LocalNodeConfiguration has changed
func (n *linuxNodeHandler) NodeConfigurationChanged(newConfig datapath.LocalNodeConfiguration) error {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	prevConfig := n.nodeConfig
	n.nodeConfig = newConfig

	n.enableNeighDiscovery = n.nodeConfig.EnableIPv4 &&
		(option.Config.EnableNodePort ||
			(n.nodeConfig.EnableIPSec && option.Config.Tunnel == option.TunnelDisabled))

	n.updateOrRemoveNodeRoutes(prevConfig.AuxiliaryPrefixes, newConfig.AuxiliaryPrefixes, true)

	if newConfig.EnableIPSec {
		if err := n.replaceHostRules(); err != nil {
			log.WithError(err).Warning("Cannot replace Host rules")
		}
	} else {
		err := n.removeEncryptRules()
		if err != nil {
			log.WithError(err).Warning("Cannot cleanup previous encryption rule state.")
		}
		ipsec.DeleteXfrm()
	}

	if newConfig.UseSingleClusterRoute {
		n.updateOrRemoveClusterRoute(n.nodeAddressing.IPv4(), newConfig.EnableIPv4)
		n.updateOrRemoveClusterRoute(n.nodeAddressing.IPv6(), newConfig.EnableIPv6)
	} else if prevConfig.UseSingleClusterRoute {
		// single cluster route has been disabled, remove route
		n.deleteNodeRoute(n.nodeAddressing.IPv4().AllocationCIDR(), false)
		n.deleteNodeRoute(n.nodeAddressing.IPv6().AllocationCIDR(), false)
	}

	if !n.isInitialized {
		n.isInitialized = true
		if !n.nodeConfig.UseSingleClusterRoute {
			for _, unlinkedNode := range n.nodes {
				n.nodeUpdate(nil, unlinkedNode, true)
			}
		}
	}

	return nil
}

// NodeValidateImplementation is called to validate the implementation of the
// node in the datapath
func (n *linuxNodeHandler) NodeValidateImplementation(nodeToValidate nodeTypes.Node) error {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	return n.nodeUpdate(nil, &nodeToValidate, false)
}

// NodeNeighDiscoveryEnabled returns whether node neighbor discovery is enabled
func (n *linuxNodeHandler) NodeNeighDiscoveryEnabled() bool {
	return n.enableNeighDiscovery
}

// NodeNeighborRefresh is called to refresh node neighbor table.
// This is currently triggered by controller neighbor-table-refresh
func (n *linuxNodeHandler) NodeNeighborRefresh(ctx context.Context, nodeToRefresh nodeTypes.Node) {
	n.mutex.Lock()
	isInitialized := n.isInitialized
	n.mutex.Unlock()
	if !isInitialized {
		// Wait until the node is initialized. When it's not, insertNeighbor()
		// is not invoked, so there is nothing to refresh.
		return
	}

	var ifaceName string
	if option.Config.EnableNodePort {
		ifaceName = option.Config.DirectRoutingDevice
	} else if option.Config.EnableIPSec {
		ifaceName = option.Config.EncryptInterface
	}
	refreshComplete := make(chan struct{})
	go n.refreshNeighbor(ctx, &nodeToRefresh, ifaceName, refreshComplete)
	for {
		select {
		case <-ctx.Done():
			return
		case <-refreshComplete:
			return
		}
	}
}

// NodeDeviceNameWithDefaultRoute returns the node's device name which
// handles the default route in the current namespace
func NodeDeviceNameWithDefaultRoute() (string, error) {
	link, err := route.NodeDeviceWithDefaultRoute(option.Config.EnableIPv4, option.Config.EnableIPv6)
	if err != nil {
		return "", err
	}
	return link.Attrs().Name, nil
}
