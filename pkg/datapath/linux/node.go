// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/counter"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/datapath/link"
	"github.com/cilium/cilium/pkg/datapath/linux/ipsec"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/datapath/types"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/tunnel"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
)

const (
	wildcardIPv4 = "0.0.0.0"
	wildcardIPv6 = "0::0"
)

const (
	neighFileName = "neigh-link.json"
)

// NeighLink contains the details of a NeighLink
type NeighLink struct {
	Name string `json:"link-name"`
}

type linuxNodeHandler struct {
	mutex                lock.Mutex
	isInitialized        bool
	nodeConfig           datapath.LocalNodeConfiguration
	nodeAddressing       types.NodeAddressing
	datapathConfig       DatapathConfiguration
	nodes                map[nodeTypes.Identity]*nodeTypes.Node
	enableNeighDiscovery bool
	neighLock            lock.Mutex // protects neigh* fields below
	neighDiscoveryLink   netlink.Link
	neighNextHopByNode4  map[nodeTypes.Identity]string // val = string(net.IP)
	neighNextHopByNode6  map[nodeTypes.Identity]string // val = string(net.IP)
	// All three mappings below hold both IPv4 and IPv6 entries.
	neighNextHopRefCount   counter.StringCounter
	neighByNextHop         map[string]*netlink.Neigh // key = string(net.IP)
	neighLastPingByNextHop map[string]time.Time      // key = string(net.IP)
	wgAgent                datapath.WireguardAgent

	ipsecMetricCollector prometheus.Collector
}

// NewNodeHandler returns a new node handler to handle node events and
// implement the implications in the Linux datapath
func NewNodeHandler(datapathConfig DatapathConfiguration, nodeAddressing types.NodeAddressing, wgAgent datapath.WireguardAgent) datapath.NodeHandler {
	return &linuxNodeHandler{
		nodeAddressing:         nodeAddressing,
		datapathConfig:         datapathConfig,
		nodes:                  map[nodeTypes.Identity]*nodeTypes.Node{},
		neighNextHopByNode4:    map[nodeTypes.Identity]string{},
		neighNextHopByNode6:    map[nodeTypes.Identity]string{},
		neighNextHopRefCount:   counter.StringCounter{},
		neighByNextHop:         map[string]*netlink.Neigh{},
		neighLastPingByNextHop: map[string]time.Time{},
		wgAgent:                wgAgent,
		ipsecMetricCollector:   ipsec.NewXFRMCollector(),
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
	case oldCIDR != nil && newCIDR != nil && !oldCIDR.Equal(newCIDR):
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
	return !oldCIDR.Equal(newCIDR)
}

func deleteTunnelMapping(oldCIDR *cidr.CIDR, quietMode bool) {
	if oldCIDR == nil {
		return
	}

	log.WithFields(logrus.Fields{
		"allocCIDR": oldCIDR,
		"quietMode": quietMode,
	}).Debug("Deleting tunnel map entry")

	if !quietMode {
		if err := tunnel.TunnelMap.DeleteTunnelEndpoint(oldCIDR.IP); err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				"allocCIDR": oldCIDR,
			}).Error("Unable to delete in tunnel endpoint map")
		}
	} else {
		_ = tunnel.TunnelMap.SilentDeleteTunnelEndpoint(oldCIDR.IP)

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

func (n *linuxNodeHandler) updateDirectRoutes(oldCIDRs, newCIDRs []*cidr.CIDR, oldIP, newIP net.IP, firstAddition, directRouteEnabled bool) error {
	if !directRouteEnabled {
		// When the protocol family is disabled, the initial node addition will
		// trigger a deletion to clean up leftover entries. The deletion happens
		// in quiet mode as we don't know whether it exists or not
		if firstAddition {
			n.deleteAllDirectRoutes(newCIDRs, newIP)
		}
		return nil
	}

	var addedCIDRs, removedCIDRs []*cidr.CIDR
	if oldIP.Equal(newIP) {
		addedCIDRs, removedCIDRs = cidr.DiffCIDRLists(oldCIDRs, newCIDRs)
	} else {
		// if the node IP changed, then we need to update all routes with the
		// new IP, but we also want to remove any of the old routes with the
		// old IP, in case the output device changed
		addedCIDRs, removedCIDRs = newCIDRs, oldCIDRs
	}

	log.WithFields(logrus.Fields{
		"newIP":        newIP,
		"oldIP":        oldIP,
		"addedCIDRs":   addedCIDRs,
		"removedCIDRs": removedCIDRs,
	}).Debug("Updating direct route")

	for _, cidr := range addedCIDRs {
		if routeSpec, err := installDirectRoute(cidr, newIP); err != nil {
			log.WithError(err).Warningf("Unable to install direct node route %s", routeSpec.String())
			return err
		}
	}
	n.deleteAllDirectRoutes(removedCIDRs, oldIP)

	return nil
}

func (n *linuxNodeHandler) deleteAllDirectRoutes(CIDRs []*cidr.CIDR, nodeIP net.IP) {
	for _, cidr := range CIDRs {
		n.deleteDirectRoute(cidr, nodeIP)
	}
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
		Nexthop:  &nexthop,
		Local:    local,
		Device:   n.datapathConfig.HostDevice,
		Prefix:   *prefix.IPNet,
		MTU:      mtu,
		Priority: option.Config.RouteMetric,
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
	if err := route.Upsert(nodeRoute); err != nil {
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

// getDefaultEncryptionInterface() is needed to find the interface used when
// populating neighbor table and doing arpRequest. For most configurations
// there is only a single interface so choosing [0] works by choosing the only
// interface. However EKS, uses multiple interfaces, but fortunately for us
// in EKS any interface would work so pick the [0] index here as well.
func getDefaultEncryptionInterface() string {
	iface := ""
	if len(option.Config.EncryptInterface) > 0 {
		iface = option.Config.EncryptInterface[0]
	}
	return iface
}

func getLinkLocalIp(family int) (*net.IPNet, error) {
	iface := getDefaultEncryptionInterface()
	link, err := netlink.LinkByName(iface)
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

func tunnelEnabled() bool {
	return option.Config.Tunnel != option.TunnelDisabled
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
		spi, err = ipsec.UpsertIPsecEndpoint(ipsecIPv4Wildcard, cidr, ipsecIPv4Wildcard, ipsec.IPSecDirOut, zeroMark, tunnelEnabled())
		upsertIPsecLog(err, "CNI Out IPv4", ipsecIPv4Wildcard, cidr, spi)

		if n.nodeConfig.EncryptNode {
			n.replaceNodeExternalIPSecOutRoute(cidr)
		} else {
			linkAddr, err := getV4LinkLocalIp()
			if err != nil {
				upsertIPsecLog(err, "getV4LinkLocalIP failed", ipsecIPv4Wildcard, cidr, spi)
			}
			spi, err := ipsec.UpsertIPsecEndpoint(linkAddr, ipsecIPv4Wildcard, cidr, ipsec.IPSecDirIn, zeroMark, tunnelEnabled())
			upsertIPsecLog(err, "CNI In IPv4", linkAddr, ipsecIPv4Wildcard, spi)
		}
	}

	for _, cidr := range v6CIDR {
		ipsecIPv6Wildcard := &net.IPNet{IP: net.ParseIP(wildcardIPv6), Mask: net.CIDRMask(0, 0)}

		n.replaceNodeIPSecInRoute(cidr)

		n.replaceNodeIPSecOutRoute(cidr)
		spi, err := ipsec.UpsertIPsecEndpoint(ipsecIPv6Wildcard, cidr, ipsecIPv6Wildcard, ipsec.IPSecDirOut, zeroMark, tunnelEnabled())
		upsertIPsecLog(err, "CNI Out IPv6", cidr, ipsecIPv6Wildcard, spi)

		if n.nodeConfig.EncryptNode {
			n.replaceNodeExternalIPSecOutRoute(cidr)
		} else {
			linkAddr, err := getV6LinkLocalIp()
			if err != nil {
				upsertIPsecLog(err, "getV6LinkLocalIP failed", ipsecIPv6Wildcard, cidr, spi)
			}
			spi, err := ipsec.UpsertIPsecEndpoint(linkAddr, ipsecIPv6Wildcard, cidr, ipsec.IPSecDirIn, zeroMark, tunnelEnabled())
			upsertIPsecLog(err, "CNI In IPv6", linkAddr, ipsecIPv6Wildcard, spi)
		}
	}
}

// encryptNode handles setting the IPsec state for node encryption (subnet
// encryption = disabled).
func (n *linuxNodeHandler) encryptNode(newNode *nodeTypes.Node) {
	var spi uint8
	var err error

	if n.nodeConfig.EnableIPv4 {
		internalIPv4 := n.nodeAddressing.IPv4().PrimaryExternal()
		exactMask := net.IPv4Mask(255, 255, 255, 255)
		ipsecLocal := &net.IPNet{IP: internalIPv4, Mask: exactMask}
		if newNode.IsLocal() {
			ipsecIPv4Wildcard := &net.IPNet{IP: net.ParseIP(wildcardIPv4), Mask: net.IPv4Mask(0, 0, 0, 0)}
			n.replaceNodeIPSecInRoute(ipsecLocal)
			spi, err = ipsec.UpsertIPsecEndpoint(ipsecLocal, ipsecIPv4Wildcard, ipsecLocal, ipsec.IPSecDirIn, false, tunnelEnabled())
			upsertIPsecLog(err, "EncryptNode local IPv4", ipsecLocal, ipsecIPv4Wildcard, spi)
		} else {
			if remoteIPv4 := newNode.GetNodeIP(false); remoteIPv4 != nil {
				ipsecRemote := &net.IPNet{IP: remoteIPv4, Mask: exactMask}
				n.replaceNodeExternalIPSecOutRoute(ipsecRemote)
				spi, err = ipsec.UpsertIPsecEndpoint(ipsecLocal, ipsecRemote, ipsecLocal, ipsec.IPSecDirOutNode, false, tunnelEnabled())
				upsertIPsecLog(err, "EncryptNode IPv4", ipsecLocal, ipsecRemote, spi)
			}
			remoteIPv4 := newNode.GetCiliumInternalIP(false)
			if remoteIPv4 != nil {
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

	if n.nodeConfig.EnableIPv6 {
		internalIPv6 := n.nodeAddressing.IPv6().PrimaryExternal()
		exactMask := net.CIDRMask(128, 128)
		ipsecLocal := &net.IPNet{IP: internalIPv6, Mask: exactMask}
		if newNode.IsLocal() {
			ipsecIPv6Wildcard := &net.IPNet{IP: net.ParseIP(wildcardIPv6), Mask: net.CIDRMask(0, 0)}
			n.replaceNodeIPSecInRoute(ipsecLocal)
			spi, err = ipsec.UpsertIPsecEndpoint(ipsecLocal, ipsecIPv6Wildcard, ipsecLocal, ipsec.IPSecDirIn, false, tunnelEnabled())
			upsertIPsecLog(err, "EncryptNode local IPv6", ipsecLocal, ipsecIPv6Wildcard, spi)
		} else {
			if remoteIPv6 := newNode.GetNodeIP(true); remoteIPv6 != nil {
				ipsecRemote := &net.IPNet{IP: remoteIPv6, Mask: exactMask}
				n.replaceNodeExternalIPSecOutRoute(ipsecRemote)
				spi, err = ipsec.UpsertIPsecEndpoint(ipsecLocal, ipsecRemote, ipsecLocal, ipsec.IPSecDirOut, false, tunnelEnabled())
				upsertIPsecLog(err, "EncryptNode IPv6", ipsecLocal, ipsecRemote, spi)
			}
			remoteIPv6 := newNode.GetCiliumInternalIP(true)
			if remoteIPv6 != nil {
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

func getNextHopIP(nodeIP net.IP) (nextHopIP net.IP, err error) {
	// Figure out whether nodeIP is directly reachable (i.e. in the same L2)
	routes, err := netlink.RouteGet(nodeIP)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve route for remote node IP: %w", err)
	}
	if len(routes) == 0 {
		return nil, fmt.Errorf("remote node IP is non-routable")
	}

	nextHopIP = nodeIP
	for _, route := range routes {
		if route.Gw != nil {
			// nodeIP is in a different L2 subnet, so it must be reachable through
			// a gateway. Perform neighbor discovery to the gw IP addr instead of
			// nodeIP. NOTE: We currently don't handle multipath, so only one gw
			// can be used.
			copy(nextHopIP, route.Gw.To16())
			break
		}
	}
	return nextHopIP, nil
}

type NextHop struct {
	Name  string
	IP    net.IP
	IsNew bool
}

func (n *linuxNodeHandler) insertNeighborCommon(scopedLog *logrus.Entry, ctx context.Context, nextHop NextHop, link netlink.Link, refresh bool) {
	if refresh {
		if lastPing, found := n.neighLastPingByNextHop[nextHop.Name]; found &&
			time.Now().Sub(lastPing) < option.Config.ARPPingRefreshPeriod {
			// Last ping was issued less than option.Config.ARPPingRefreshPeriod
			// ago, so skip it (e.g. to avoid ddos'ing the same GW if nodes are
			// L3 connected)
			return
		}
	}

	// Don't proceed if the refresh controller cancelled the context
	select {
	case <-ctx.Done():
		return
	default:
	}

	n.neighLastPingByNextHop[nextHop.Name] = time.Now()

	neigh := netlink.Neigh{
		LinkIndex:    link.Attrs().Index,
		IP:           nextHop.IP,
		Flags:        netlink.NTF_EXT_LEARNED | netlink.NTF_USE,
		HardwareAddr: nil,
	}
	if option.Config.ARPPingKernelManaged {
		neigh.Flags = netlink.NTF_EXT_LEARNED
		neigh.FlagsExt = netlink.NTF_EXT_MANAGED
	} else if nextHop.IsNew {
		// Quirk for older kernels above. We cannot directly create a
		// dynamic NUD_* with NTF_EXT_LEARNED|NTF_USE without having
		// the following kernel fixes:
		//   e4400bbf5b15 ("net, neigh: Fix NTF_EXT_LEARNED in combination with NTF_USE")
		//   3dc20f4762c6 ("net, neigh: Enable state migration between NUD_PERMANENT and NTF_USE")
		// Thus, first initialize the neighbor as NTF_EXT_LEARNED and
		// then do the subsequent ping via NTF_USE.
		//
		// Notes on use of the NUD_STALE state. We have two scenarios:
		// 1) Old entry was a PERMANENT one. In this case, the kernel
		// takes the PERMANENT's lladdr in __neigh_update() and uses
		// it for temporary STALE state. This ensures that whoever
		// does a lookup in this short window can continue keep using
		// the lladdr. The subsequent NTF_USE will trigger a fresh
		// resolution in neigh_event_send() given STALE dictates it
		// (as opposed to REACHABLE).
		// 2) Old entry was a dynamic + externally learned one. This
		// is similar as the PERMANENT one if the entry was NUD_VALID
		// before. The subsequent NTF_USE will trigger a new resolution.
		// 3) Old entry was non-existent. Given we don't push down a
		// corresponding lladdr, the neighbor entry gets created by the
		// kernel, but given prior state was not NUD_VALID then the
		// __neigh_update() will error out (EINVAL). However, the entry
		// is in the kernel, and subsequent NTF_USE will trigger a proper
		// resolution. Hence, below NeighSet() does _not_ bail out given
		// errors are expected in this case.
		neighInit := netlink.Neigh{
			LinkIndex:    link.Attrs().Index,
			IP:           nextHop.IP,
			State:        netlink.NUD_STALE,
			Flags:        netlink.NTF_EXT_LEARNED,
			HardwareAddr: nil,
		}
		if err := netlink.NeighSet(&neighInit); err != nil {
			scopedLog.WithError(err).WithFields(logrus.Fields{
				"neighbor": fmt.Sprintf("%+v", neighInit),
			}).Debug("Unable to insert new next hop")
		}
	}
	if err := netlink.NeighSet(&neigh); err != nil {
		scopedLog.WithError(err).WithFields(logrus.Fields{
			"neighbor": fmt.Sprintf("%+v", neigh),
		}).Info("Unable to refresh next hop")
		return
	}
	n.neighByNextHop[nextHop.Name] = &neigh
}

func (n *linuxNodeHandler) insertNeighbor4(ctx context.Context, newNode *nodeTypes.Node, link netlink.Link, refresh bool) {
	newNodeIP := newNode.GetNodeIP(false)
	nextHopIPv4 := make(net.IP, len(newNodeIP))
	copy(nextHopIPv4, newNodeIP)

	scopedLog := log.WithFields(logrus.Fields{
		logfields.LogSubsys: "node-neigh-debug",
		logfields.Interface: link.Attrs().Name,
		logfields.IPAddr:    newNodeIP,
	})

	nextHopIPv4, err := getNextHopIP(nextHopIPv4)
	if err != nil {
		scopedLog.WithError(err).Info("Unable to determine next hop address")
		return
	}
	nextHopStr := nextHopIPv4.String()
	scopedLog = scopedLog.WithField(logfields.NextHop, nextHopIPv4)

	n.neighLock.Lock()
	defer n.neighLock.Unlock()

	nextHopIsNew := false
	if existingNextHopStr, found := n.neighNextHopByNode4[newNode.Identity()]; found {
		if existingNextHopStr != nextHopStr {
			if n.neighNextHopRefCount.Delete(existingNextHopStr) {
				neigh, found := n.neighByNextHop[existingNextHopStr]
				if found {
					// Note that we don't move the removal via netlink which might
					// block from the hot path (e.g. with defer), as this case can
					// happen very rarely.
					//
					// The neighbor's HW address is ignored on delete. Only the IP
					// address and device is checked.
					if err := netlink.NeighDel(neigh); err != nil {
						scopedLog.WithFields(logrus.Fields{
							logfields.NextHop:   neigh.IP,
							logfields.LinkIndex: neigh.LinkIndex,
						}).WithError(err).Info("Unable to remove next hop")
					}
					delete(n.neighByNextHop, existingNextHopStr)
					delete(n.neighLastPingByNextHop, existingNextHopStr)
				}
			}
			// Given nextHop has changed and we removed the old one, we
			// now need to increment ref counter for the new one.
			nextHopIsNew = n.neighNextHopRefCount.Add(nextHopStr)
		}
	} else {
		// nextHop for the given node was previously not found, so let's
		// increment ref counter. This can happen upon regular NodeUpdate
		// event or by the periodic ARP refresher which got executed before
		// NodeUpdate().
		nextHopIsNew = n.neighNextHopRefCount.Add(nextHopStr)
	}

	n.neighNextHopByNode4[newNode.Identity()] = nextHopStr
	nh := NextHop{
		Name:  nextHopStr,
		IP:    nextHopIPv4,
		IsNew: nextHopIsNew,
	}
	n.insertNeighborCommon(scopedLog, ctx, nh, link, refresh)
}

func (n *linuxNodeHandler) insertNeighbor6(ctx context.Context, newNode *nodeTypes.Node, link netlink.Link, refresh bool) {
	newNodeIP := newNode.GetNodeIP(true)
	nextHopIPv6 := make(net.IP, len(newNodeIP))
	copy(nextHopIPv6, newNodeIP)

	scopedLog := log.WithFields(logrus.Fields{
		logfields.LogSubsys: "node-neigh-debug",
		logfields.Interface: link.Attrs().Name,
		logfields.IPAddr:    newNodeIP,
	})

	nextHopIPv6, err := getNextHopIP(nextHopIPv6)
	if err != nil {
		scopedLog.WithError(err).Info("Unable to determine next hop address")
		return
	}
	nextHopStr := nextHopIPv6.String()
	scopedLog = scopedLog.WithField(logfields.NextHop, nextHopIPv6)

	n.neighLock.Lock()
	defer n.neighLock.Unlock()

	nextHopIsNew := false
	if existingNextHopStr, found := n.neighNextHopByNode6[newNode.Identity()]; found {
		if existingNextHopStr != nextHopStr {
			if n.neighNextHopRefCount.Delete(existingNextHopStr) {
				// nextHop has changed and nobody else is using it, so remove the old one.
				neigh, found := n.neighByNextHop[existingNextHopStr]
				if found {
					// Note that we don't move the removal via netlink which might
					// block from the hot path (e.g. with defer), as this case can
					// happen very rarely.
					//
					// The neighbor's HW address is ignored on delete. Only the IP
					// address and device is checked.
					if err := netlink.NeighDel(neigh); err != nil {
						scopedLog.WithFields(logrus.Fields{
							logfields.NextHop:   neigh.IP,
							logfields.LinkIndex: neigh.LinkIndex,
						}).WithError(err).Info("Unable to remove next hop")
					}
					delete(n.neighByNextHop, existingNextHopStr)
					delete(n.neighLastPingByNextHop, existingNextHopStr)
				}
			}
			// Given nextHop has changed and we removed the old one, we
			// now need to increment ref counter for the new one.
			nextHopIsNew = n.neighNextHopRefCount.Add(nextHopStr)
		}
	} else {
		// nextHop for the given node was previously not found, so let's
		// increment ref counter. This can happen upon regular NodeUpdate
		// event or by the periodic ARP refresher which got executed before
		// NodeUpdate().
		nextHopIsNew = n.neighNextHopRefCount.Add(nextHopStr)
	}

	n.neighNextHopByNode6[newNode.Identity()] = nextHopStr
	nh := NextHop{
		Name:  nextHopStr,
		IP:    nextHopIPv6,
		IsNew: nextHopIsNew,
	}
	n.insertNeighborCommon(scopedLog, ctx, nh, link, refresh)
}

// insertNeighbor inserts a non-GC'able neighbor entry for a nexthop to the given
// "newNode" (ip route get newNodeIP.GetNodeIP()). The L2 addr of the nexthop is
// determined by the Linux kernel's neighboring subsystem. The related iface for
// the neighbor is specified by n.neighDiscoveryLink.
//
// The given "refresh" param denotes whether the method is called by a controller
// which tries to update neighbor entries previously inserted by insertNeighbor().
// In this case the kernel refreshes the entry via NTF_USE.
func (n *linuxNodeHandler) insertNeighbor(ctx context.Context, newNode *nodeTypes.Node, refresh bool) {
	var link netlink.Link

	n.neighLock.Lock()
	if n.neighDiscoveryLink == nil || reflect.ValueOf(n.neighDiscoveryLink).IsNil() {
		n.neighLock.Unlock()
		// Nothing to do - the discovery link was not set yet
		return
	}
	link = n.neighDiscoveryLink
	n.neighLock.Unlock()

	if newNode.GetNodeIP(false).To4() != nil {
		n.insertNeighbor4(ctx, newNode, link, refresh)
	}
	if newNode.GetNodeIP(true).To16() != nil {
		n.insertNeighbor6(ctx, newNode, link, refresh)
	}
}

func (n *linuxNodeHandler) refreshNeighbor(ctx context.Context, nodeToRefresh *nodeTypes.Node, completed chan struct{}) {
	defer close(completed)

	n.insertNeighbor(ctx, nodeToRefresh, true)
}

func (n *linuxNodeHandler) deleteNeighborCommon(nextHopStr string) {
	if n.neighNextHopRefCount.Delete(nextHopStr) {
		neigh, found := n.neighByNextHop[nextHopStr]
		delete(n.neighByNextHop, nextHopStr)
		delete(n.neighLastPingByNextHop, nextHopStr)
		if found {
			// Neighbor's HW address is ignored on delete. Only IP
			// address and device is checked.
			if err := netlink.NeighDel(neigh); err != nil {
				log.WithFields(logrus.Fields{
					logfields.LogSubsys: "node-neigh-debug",
					logfields.NextHop:   neigh.IP,
					logfields.LinkIndex: neigh.LinkIndex,
				}).WithError(err).Info("Unable to remove next hop")
			}
		}
	}
}

func (n *linuxNodeHandler) deleteNeighbor4(oldNode *nodeTypes.Node) {
	n.neighLock.Lock()
	defer n.neighLock.Unlock()
	nextHopStr, found := n.neighNextHopByNode4[oldNode.Identity()]
	if !found {
		return
	}
	defer func() { delete(n.neighNextHopByNode4, oldNode.Identity()) }()
	n.deleteNeighborCommon(nextHopStr)
}

func (n *linuxNodeHandler) deleteNeighbor6(oldNode *nodeTypes.Node) {
	n.neighLock.Lock()
	defer n.neighLock.Unlock()
	nextHopStr, found := n.neighNextHopByNode6[oldNode.Identity()]
	if !found {
		return
	}
	defer func() { delete(n.neighNextHopByNode6, oldNode.Identity()) }()
	n.deleteNeighborCommon(nextHopStr)
}

func (n *linuxNodeHandler) deleteNeighbor(oldNode *nodeTypes.Node) {
	n.deleteNeighbor4(oldNode)
	n.deleteNeighbor6(oldNode)
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
				spi, err = ipsec.UpsertIPsecEndpoint(ipsecLocal, ipsecIPv4Wildcard, ipsecLocal, ipsec.IPSecDirIn, false, tunnelEnabled())
				upsertIPsecLog(err, "local IPv4", ipsecLocal, ipsecIPv4Wildcard, spi)
			}
		} else {
			if ciliumInternalIPv4 := newNode.GetCiliumInternalIP(false); ciliumInternalIPv4 != nil {
				ipsecLocal := &net.IPNet{IP: n.nodeAddressing.IPv4().Router(), Mask: n.nodeAddressing.IPv4().AllocationCIDR().Mask}
				ipsecRemote := &net.IPNet{IP: ciliumInternalIPv4, Mask: newNode.IPv4AllocCIDR.Mask}
				n.replaceNodeIPSecOutRoute(new4Net)
				spi, err = ipsec.UpsertIPsecEndpoint(ipsecLocal, ipsecRemote, ipsecLocal, ipsec.IPSecDirOut, false, tunnelEnabled())
				upsertIPsecLog(err, "IPv4", ipsecLocal, ipsecRemote, spi)

				/* Insert wildcard policy rules for traffic skipping back through host */
				ipsecIPv4Wildcard := &net.IPNet{IP: net.ParseIP(wildcardIPv4), Mask: net.IPv4Mask(0, 0, 0, 0)}
				if err = ipsec.IpSecReplacePolicyFwd(ipsecIPv4Wildcard, ipsecRemote, ipsecIPv4Wildcard, ipsecRemote); err != nil {
					log.WithError(err).Warning("egress unable to replace policy fwd:")
				}
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
				spi, err = ipsec.UpsertIPsecEndpoint(ipsecLocal, ipsecIPv6Wildcard, ipsecLocal, ipsec.IPSecDirIn, false, tunnelEnabled())
				upsertIPsecLog(err, "local IPv6", ipsecLocal, ipsecIPv6Wildcard, spi)
			}
		} else {
			if ciliumInternalIPv6 := newNode.GetCiliumInternalIP(true); ciliumInternalIPv6 != nil {
				ipsecLocal := &net.IPNet{IP: n.nodeAddressing.IPv6().Router(), Mask: net.CIDRMask(0, 0)}
				ipsecRemote := &net.IPNet{IP: ciliumInternalIPv6, Mask: newNode.IPv6AllocCIDR.Mask}
				n.replaceNodeIPSecOutRoute(new6Net)
				spi, err := ipsec.UpsertIPsecEndpoint(ipsecLocal, ipsecRemote, ipsecLocal, ipsec.IPSecDirOut, false, tunnelEnabled())
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
		oldIP4Cidr, oldIP6Cidr                   *cidr.CIDR
		oldAllIP4AllocCidrs, oldAllIP6AllocCidrs []*cidr.CIDR
		newAllIP4AllocCidrs                      = newNode.GetIPv4AllocCIDRs()
		newAllIP6AllocCidrs                      = newNode.GetIPv6AllocCIDRs()
		oldIP4, oldIP6                           net.IP
		newIP4                                   = newNode.GetNodeIP(false)
		newIP6                                   = newNode.GetNodeIP(true)
		oldKey, newKey                           uint8
		isLocalNode                              = false
	)

	if oldNode != nil {
		oldIP4Cidr = oldNode.IPv4AllocCIDR
		oldIP6Cidr = oldNode.IPv6AllocCIDR
		oldAllIP4AllocCidrs = oldNode.GetIPv4AllocCIDRs()
		oldAllIP6AllocCidrs = oldNode.GetIPv6AllocCIDRs()
		oldIP4 = oldNode.GetNodeIP(false)
		oldIP6 = oldNode.GetNodeIP(true)
		oldKey = oldNode.EncryptionKey
	}

	if n.nodeConfig.EnableIPSec && !n.subnetEncryption() && !n.nodeConfig.EncryptNode {
		n.enableIPsec(newNode)
		newKey = newNode.EncryptionKey
	}

	if n.enableNeighDiscovery && !newNode.IsLocal() {
		// Running insertNeighbor in a separate goroutine relies on the following
		// assumptions:
		// 1. newNode is accessed only by reads.
		// 2. It is safe to invoke insertNeighbor for the same node.
		go n.insertNeighbor(context.Background(), newNode, false)
	}

	if n.nodeConfig.EnableIPSec && n.nodeConfig.EncryptNode && !n.subnetEncryption() {
		n.encryptNode(newNode)
	}

	if newNode.IsLocal() {
		isLocalNode = true
		if n.nodeConfig.EnableLocalNodeRoute {
			n.updateOrRemoveNodeRoutes(oldAllIP4AllocCidrs, newAllIP4AllocCidrs, isLocalNode)
			n.updateOrRemoveNodeRoutes(oldAllIP6AllocCidrs, newAllIP6AllocCidrs, isLocalNode)
		}
		if n.subnetEncryption() {
			n.enableSubnetIPsec(n.nodeConfig.IPv4PodSubnets, n.nodeConfig.IPv6PodSubnets)
		}
		if firstAddition && n.nodeConfig.EnableIPSec {
			metrics.Register(n.ipsecMetricCollector)
		}
		return nil
	}

	if option.Config.EnableWireguard && newNode.WireguardPubKey != "" {
		if err := n.wgAgent.UpdatePeer(newNode.Name, newNode.WireguardPubKey, newIP4, newIP6); err != nil {
			log.WithError(err).
				WithField(logfields.NodeName, newNode.Name).
				Warning("Failed to update wireguard configuration for peer")
		}
	}

	if n.nodeConfig.EnableAutoDirectRouting {
		n.updateDirectRoutes(oldAllIP4AllocCidrs, newAllIP4AllocCidrs, oldIP4, newIP4, firstAddition, n.nodeConfig.EnableIPv4)
		n.updateDirectRoutes(oldAllIP6AllocCidrs, newAllIP6AllocCidrs, oldIP6, newIP6, firstAddition, n.nodeConfig.EnableIPv6)
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
			n.updateOrRemoveNodeRoutes(oldAllIP4AllocCidrs, newAllIP4AllocCidrs, isLocalNode)
			n.updateOrRemoveNodeRoutes(oldAllIP6AllocCidrs, newAllIP6AllocCidrs, isLocalNode)
		}

		return nil
	} else if firstAddition {
		for _, ipv4AllocCIDR := range newAllIP4AllocCidrs {
			if rt, _ := n.lookupNodeRoute(ipv4AllocCIDR, isLocalNode); rt != nil {
				n.deleteNodeRoute(ipv4AllocCIDR, isLocalNode)
			}
		}
		for _, ipv6AllocCIDR := range newAllIP6AllocCidrs {
			if rt, _ := n.lookupNodeRoute(ipv6AllocCIDR, isLocalNode); rt != nil {
				n.deleteNodeRoute(ipv6AllocCIDR, isLocalNode)
			}
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
		if n.nodeConfig.EnableIPSec {
			metrics.Unregister(n.ipsecMetricCollector)
		}
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
		go n.deleteNeighbor(oldNode)
	}

	if n.nodeConfig.EnableIPSec {
		if oldNode.IsLocal() || !n.subnetEncryption() {
			n.deleteIPsec(oldNode)
		}
	}

	if option.Config.EnableWireguard {
		if err := n.wgAgent.DeletePeer(oldNode.Name); err != nil {
			return err
		}
	}

	return nil
}

func (n *linuxNodeHandler) updateOrRemoveClusterRoute(addressing types.NodeAddressingFamily, addressFamilyEnabled bool) {
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

	if err := route.DeleteRouteTable(linux_defaults.RouteTableIPSec, netlink.FAMILY_V4); err != nil {
		log.WithError(err).Warn("Deletion of IPSec routes failed")
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
		device = option.Config.EncryptInterface[0]
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
	var mtu int

	if dflt {
		mtu = n.nodeConfig.MtuConfig.GetRouteMTU()
	} else {
		tbl = linux_defaults.RouteTableIPSec
		mtu = n.nodeConfig.MtuConfig.GetRoutePostEncryptMTU()
	}

	// The default routing table accounts for encryption overhead for encrypt-node traffic
	return route.Route{
		Device: n.datapathConfig.HostDevice,
		Prefix: *ip,
		Table:  tbl,
		Proto:  route.EncryptRouteProtocol,
		MTU:    mtu,
	}
}

// replaceNodeIPSecOutRoute replace the out IPSec route in the host routing
// table with the new route. If no route exists the route is installed on the
// host. The caller must ensure that the CIDR passed in must be non-nil.
func (n *linuxNodeHandler) replaceNodeIPSecOutRoute(ip *net.IPNet) {
	if ip.IP.To4() != nil {
		if !n.nodeConfig.EnableIPv4 {
			return
		}
	} else {
		if !n.nodeConfig.EnableIPv6 {
			return
		}
	}

	if err := route.Upsert(n.createNodeIPSecOutRoute(ip)); err != nil {
		log.WithError(err).WithField(logfields.CIDR, ip).Error("Unable to replace the IPSec route OUT the host routing table")
	}
}

// replaceNodeExternalIPSecOutRoute replace the out IPSec route in the host
// routing table with the new route. If no route exists the route is installed
// on the host. The caller must ensure that the CIDR passed in must be non-nil.
func (n *linuxNodeHandler) replaceNodeExternalIPSecOutRoute(ip *net.IPNet) {
	if ip.IP.To4() != nil {
		if !n.nodeConfig.EnableIPv4 {
			return
		}
	} else {
		if !n.nodeConfig.EnableIPv6 {
			return
		}
	}

	if err := route.Upsert(n.createNodeExternalIPSecOutRoute(ip, true)); err != nil {
		log.WithError(err).WithField(logfields.CIDR, ip).Error("Unable to replace the IPSec route OUT the default routing table")
	}
	if err := route.Upsert(n.createNodeExternalIPSecOutRoute(ip, false)); err != nil {
		log.WithError(err).WithField(logfields.CIDR, ip).Error("Unable to replace the IPSec route OUT the host routing table")
	}
}

// The caller must ensure that the CIDR passed in must be non-nil.
func (n *linuxNodeHandler) deleteNodeIPSecOutRoute(ip *net.IPNet) {
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
		log.WithError(err).WithField(logfields.CIDR, ip).Error("Unable to delete the IPsec route OUT from the host routing table")
	}
}

// The caller must ensure that the CIDR passed in must be non-nil.
func (n *linuxNodeHandler) deleteNodeExternalIPSecOutRoute(ip *net.IPNet) {
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
		log.WithError(err).WithField(logfields.CIDR, ip).Error("Unable to delete the IPsec route External OUT from the ipsec routing table")
	}

	if err := route.Delete(n.createNodeExternalIPSecOutRoute(ip, false)); err != nil {
		log.WithError(err).WithField(logfields.CIDR, ip).Error("Unable to delete the IPsec route External OUT from the host routing table")
	}
}

// replaceNodeIPSecoInRoute replace the in IPSec routes in the host routing
// table with the new route. If no route exists the route is installed on the
// host. The caller must ensure that the CIDR passed in must be non-nil.
func (n *linuxNodeHandler) replaceNodeIPSecInRoute(ip *net.IPNet) {
	if ip.IP.To4() != nil {
		if !n.nodeConfig.EnableIPv4 {
			return
		}
	} else {
		if !n.nodeConfig.EnableIPv6 {
			return
		}
	}

	if err := route.Upsert(n.createNodeIPSecInRoute(ip)); err != nil {
		log.WithError(err).WithField(logfields.CIDR, ip).Error("Unable to replace the IPSec route IN the host routing table")
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

	if n.nodeConfig.EnableIPv4 || n.nodeConfig.EnableIPv6 {
		ifaceName := ""
		switch {
		case !option.Config.EnableL2NeighDiscovery:
			n.enableNeighDiscovery = false
		case option.Config.DirectRoutingDeviceRequired():
			if option.Config.DirectRoutingDevice == "" {
				return fmt.Errorf("direct routing device is required, but not defined")
			}

			mac, err := link.GetHardwareAddr(option.Config.DirectRoutingDevice)
			if err != nil {
				return err
			}
			ifaceName = option.Config.DirectRoutingDevice
			n.enableNeighDiscovery = mac != nil // No need to arping for L2-less devices
		case n.nodeConfig.EnableIPSec &&
			option.Config.Tunnel == option.TunnelDisabled &&
			len(option.Config.EncryptInterface) != 0:
			// When FIB lookup is not supported we need to pick an
			// interface so pick first interface in the list. On
			// kernels with FIB lookup helpers we do a lookup from
			// the datapath side and ignore this value.
			ifaceName = option.Config.EncryptInterface[0]
			n.enableNeighDiscovery = true
		}

		if n.enableNeighDiscovery {
			link, err := netlink.LinkByName(ifaceName)
			if err != nil {
				return fmt.Errorf("cannot find link by name %s for neighbor discovery: %w",
					ifaceName, err)
			}

			// Store neighDiscoveryLink so that we can remove the ARP
			// PERM entries when cilium-agent starts with neigh discovery
			// disabled next time.
			err = storeNeighLink(option.Config.StateDir, ifaceName)
			if err != nil {
				log.WithError(err).Warning("Unable to store neighbor discovery iface." +
					" Removing PERM neighbor entries upon cilium-agent init when neighbor" +
					" discovery is disabled will not work.")
			}

			// neighDiscoveryLink can be accessed by a concurrent insertNeighbor
			// goroutine.
			n.neighLock.Lock()
			n.neighDiscoveryLink = link
			n.neighLock.Unlock()
		}
	}

	n.updateOrRemoveNodeRoutes(prevConfig.AuxiliaryPrefixes, newConfig.AuxiliaryPrefixes, true)

	if newConfig.EnableIPSec {
		// For the ENI ipam mode on EKS, this will be the interface that
		// the router (cilium_host) IP is associated to.
		if (option.Config.IPAM == ipamOption.IPAMENI || option.Config.IPAM == ipamOption.IPAMAzure) &&
			len(option.Config.IPv4PodSubnets) == 0 {
			if info := node.GetRouterInfo(); info != nil {
				var ipv4PodSubnets []*net.IPNet
				for _, c := range info.GetIPv4CIDRs() {
					cidr := c // create a copy to be able to take a reference
					ipv4PodSubnets = append(ipv4PodSubnets, &cidr)
				}
				n.nodeConfig.IPv4PodSubnets = ipv4PodSubnets
			}
		}

		if err := n.replaceHostRules(); err != nil {
			log.WithError(err).Warning("Cannot replace Host rules")
		}
		metrics.Register(n.ipsecMetricCollector)
	} else {
		err := n.removeEncryptRules()
		if err != nil {
			log.WithError(err).Warning("Cannot cleanup previous encryption rule state.")
		}
		ipsec.DeleteXfrm()
		metrics.Unregister(n.ipsecMetricCollector)
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

	refreshComplete := make(chan struct{})
	go n.refreshNeighbor(ctx, &nodeToRefresh, refreshComplete)
	select {
	case <-ctx.Done():
	case <-refreshComplete:
	}
}

func (n *linuxNodeHandler) NodeCleanNeighborsLink(l netlink.Link, migrateOnly bool) bool {
	successClean := true

	neighList, err := netlink.NeighListExecute(netlink.Ndmsg{
		Index: uint32(l.Attrs().Index),
	})
	if err != nil {
		log.WithError(err).WithFields(logrus.Fields{
			logfields.Device:    l.Attrs().Name,
			logfields.LinkIndex: l.Attrs().Index,
		}).Error("Unable to list PERM neighbor entries for removal of network device")
		return false
	}

	if migrateOnly {
		// neighLastPingByNextHop holds both v4 and v6 neighbors and given
		// we try to find stale neighbors, we need to check their presence
		// again it.
		n.neighLock.Lock()
		defer n.neighLock.Unlock()
	}

	var neighSucceeded, neighErrored int
	var which string
	for _, neigh := range neighList {
		var err error
		// If this is a non-static neighbor entry, it will be GC'ed by
		// the kernel eventually. Older Cilium versions might have left-
		// overs installed as NUD_PERMANENT.
		if neigh.State&netlink.NUD_PERMANENT == 0 &&
			neigh.Flags&netlink.NTF_EXT_LEARNED == 0 {
			continue
		}
		migrateEntry := false
		if migrateOnly {
			nextHop := neigh.IP.String()
			if _, found := n.neighLastPingByNextHop[nextHop]; found {
				migrateEntry = true
			}
		}
		if migrateEntry {
			// We only care to migrate NUD_PERMANENT over to dynamic
			// state entries with NTF_EXT_LEARNED.
			if neigh.State&netlink.NUD_PERMANENT == 0 {
				continue
			}

			which = "migrate"
			if option.Config.ARPPingKernelManaged {
				neigh.State = netlink.NUD_REACHABLE
				neigh.Flags = netlink.NTF_EXT_LEARNED
				neigh.FlagsExt = netlink.NTF_EXT_MANAGED
			} else {
				neigh.State = netlink.NUD_REACHABLE
				neigh.Flags = netlink.NTF_EXT_LEARNED
				if err := netlink.NeighSet(&neigh); err != nil {
					log.WithError(err).WithFields(logrus.Fields{
						logfields.Device:    l.Attrs().Name,
						logfields.LinkIndex: l.Attrs().Index,
						"neighbor":          fmt.Sprintf("%+v", neigh),
					}).Info("Unable to replace new next hop")
					neighErrored++
					successClean = false
					continue
				}
				// Quirk for older kernels above. We cannot directly transition
				// from NUD_PERMANENT to dynamic NUD_* with NTF_EXT_LEARNED|NTF_USE
				// without having the following kernel fixes:
				//   e4400bbf5b15 ("net, neigh: Fix NTF_EXT_LEARNED in combination with NTF_USE")
				//   3dc20f4762c6 ("net, neigh: Enable state migration between NUD_PERMANENT and NTF_USE")
				// Thus, migrate state temporarily to NUD_REACHABLE first, and then
				// do the ping via NTF_USE.
				neigh.State = netlink.NUD_REACHABLE
				neigh.Flags = netlink.NTF_EXT_LEARNED | netlink.NTF_USE
			}
			err = netlink.NeighSet(&neigh)
		} else {
			which = "remove"
			err = netlink.NeighDel(&neigh)
		}
		if err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				logfields.Device:    l.Attrs().Name,
				logfields.LinkIndex: l.Attrs().Index,
				"neighbor":          fmt.Sprintf("%+v", neigh),
			}).Errorf("Unable to %s non-GC'ed neighbor entry of network device. "+
				"Consider removing this entry manually with 'ip neigh del %s dev %s'",
				which, neigh.IP.String(), l.Attrs().Name)
			neighErrored++
			successClean = false
		} else {
			neighSucceeded++
		}
	}
	if neighSucceeded != 0 {
		log.WithFields(logrus.Fields{
			logfields.Count: neighSucceeded,
		}).Infof("Successfully %sd non-GC'ed neighbor entries previously installed by cilium-agent", which)
	}
	if neighErrored != 0 {
		log.WithFields(logrus.Fields{
			logfields.Count: neighErrored,
		}).Warningf("Unable to %s non-GC'ed neighbor entries previously installed by cilium-agent", which)
	}
	return successClean
}

// NodeCleanNeighbors cleans all neighbor entries of previously used neighbor
// discovery link interfaces. If migrateOnly is true, then NodeCleanNeighbors
// cleans old entries by trying to convert PERMANENT to dynamic, externally
// learned ones. If set to false, then it removes all PERMANENT or externally
// learned ones, e.g. when the agent got restarted and changed the state from
// `n.enableNeighDiscovery = true` to `n.enableNeighDiscovery = false`.
//
// Also, NodeCleanNeighbors is called after kubeapi server resync, so we have
// the full picture of all nodes. If there are any externally learned neighbors
// not in neighLastPingByNextHop, then we delete them as they could be stale
// neighbors from a previous agent run where in the meantime the given node was
// deleted (and the new agent instance did not see the delete event during the
// down/up cycle).
func (n *linuxNodeHandler) NodeCleanNeighbors(migrateOnly bool) {
	linkName, err := loadNeighLink(option.Config.StateDir)
	if err != nil {
		log.WithError(err).Error("Unable to load neighbor discovery iface name" +
			" for removing PERM neighbor entries")
		return
	}
	if len(linkName) == 0 {
		return
	}

	// Delete the file after cleaning up neighbor list if we were able to clean
	// up all neighbors.
	successClean := true
	defer func() {
		if successClean {
			os.Remove(filepath.Join(option.Config.StateDir, neighFileName))
		}
	}()

	l, err := netlink.LinkByName(linkName)
	if err != nil {
		// If the link is not found we don't need to keep retrying cleaning
		// up the neihbor entries so we can keep successClean=true
		if _, ok := err.(netlink.LinkNotFoundError); !ok {
			log.WithError(err).WithFields(logrus.Fields{
				logfields.Device: linkName,
			}).Error("Unable to remove PERM neighbor entries of network device")
			successClean = false
		}
		return
	}

	successClean = n.NodeCleanNeighborsLink(l, migrateOnly)
}

func storeNeighLink(dir string, name string) error {
	configFileName := filepath.Join(dir, neighFileName)
	f, err := os.Create(configFileName)
	if err != nil {
		return fmt.Errorf("unable to create '%s': %w", configFileName, err)
	}
	defer f.Close()
	nl := NeighLink{Name: name}
	err = json.NewEncoder(f).Encode(nl)
	if err != nil {
		return fmt.Errorf("unable to encode '%+v': %w", nl, err)
	}
	return nil
}

func loadNeighLink(dir string) (string, error) {
	configFileName := filepath.Join(dir, neighFileName)
	f, err := os.Open(configFileName)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("unable to open '%s': %w", configFileName, err)
	}
	defer f.Close()
	var nl NeighLink

	err = json.NewDecoder(f).Decode(&nl)
	if err != nil {
		return "", fmt.Errorf("unable to decode '%s': %w", configFileName, err)
	}
	return nl.Name, nil
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
