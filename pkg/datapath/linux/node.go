// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"go.uber.org/multierr"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/cidr"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/counter"
	"github.com/cilium/cilium/pkg/datapath/link"
	"github.com/cilium/cilium/pkg/datapath/linux/ipsec"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/errs"
	"github.com/cilium/cilium/pkg/idpool"
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

	neighFileName = "neigh-link.json"
)

// NeighLink contains the details of a NeighLink
type NeighLink struct {
	Name string `json:"link-name"`
}

type errNeighUpdateFailure struct {
	ts   time.Time
	node string
	err  error
}

func (e errNeighUpdateFailure) Error() string {
	return fmt.Sprintf("node %q failed neigh update: %s", e.node, e.err)
}

func (h *linuxNodeHandler) reportNeighFailure(node string, err error) {
	h.neighFailures = append(h.neighFailures, errNeighUpdateFailure{
		ts:   time.Now(),
		node: node,
		err:  err,
	})
	// Ensure we don't grow the slice indefinitely.
	if h.neighFailures != nil && len(h.neighFailures) > 100 {
		h.neighFailures = h.neighFailures[1:]
	}
}

type linuxNodeHandler struct {
	mutex                lock.Mutex
	isInitialized        bool
	nodeConfig           datapath.LocalNodeConfiguration
	nodeAddressing       datapath.NodeAddressing
	datapathConfig       DatapathConfiguration
	nodes                map[nodeTypes.Identity]*nodeTypes.Node
	enableNeighDiscovery bool
	neighLock            lock.Mutex // protects neigh* fields below
	neighFailures        []errNeighUpdateFailure
	neighDiscoveryLinks  []netlink.Link
	neighNextHopByNode4  map[nodeTypes.Identity]map[string]string // val = (key=link, value=string(net.IP))
	neighNextHopByNode6  map[nodeTypes.Identity]map[string]string // val = (key=link, value=string(net.IP))
	// All three mappings below hold both IPv4 and IPv6 entries.
	neighNextHopRefCount   counter.StringCounter
	neighByNextHop         map[string]*netlink.Neigh // key = string(net.IP)
	neighLastPingByNextHop map[string]time.Time      // key = string(net.IP)
	wgAgent                datapath.WireguardAgent

	// Pool of available IDs for nodes.
	nodeIDs idpool.IDPool
	// Node-scoped unique IDs for the nodes.
	nodeIDsByIPs map[string]uint16
	// reverse map of the above
	nodeIPsByIDs map[uint16]string

	ipsecMetricCollector prometheus.Collector
	ipsecMetricOnce      sync.Once
}

func (h *linuxNodeHandler) Name() string {
	return "node-host-linux-datapath"
}

var (
	_ datapath.NodeHandler   = (*linuxNodeHandler)(nil)
	_ datapath.NodeIDHandler = (*linuxNodeHandler)(nil)
	_ datapath.NodeNeighbors = (*linuxNodeHandler)(nil)
)

// NewNodeHandler returns a new node handler to handle node events and
// implement the implications in the Linux datapath
func NewNodeHandler(datapathConfig DatapathConfiguration, nodeAddressing datapath.NodeAddressing, wgAgent datapath.WireguardAgent) *linuxNodeHandler {
	return &linuxNodeHandler{
		nodeAddressing:         nodeAddressing,
		datapathConfig:         datapathConfig,
		nodes:                  map[nodeTypes.Identity]*nodeTypes.Node{},
		neighNextHopByNode4:    map[nodeTypes.Identity]map[string]string{},
		neighNextHopByNode6:    map[nodeTypes.Identity]map[string]string{},
		neighNextHopRefCount:   counter.StringCounter{},
		neighByNextHop:         map[string]*netlink.Neigh{},
		neighLastPingByNextHop: map[string]time.Time{},
		wgAgent:                wgAgent,
		nodeIDs:                idpool.NewIDPool(minNodeID, maxNodeID),
		nodeIDsByIPs:           map[string]uint16{},
		nodeIPsByIDs:           map[uint16]string{},
		ipsecMetricCollector:   ipsec.NewXFRMCollector(),
	}
}

// updateTunnelMapping is called when a node update is received while running
// with encapsulation mode enabled. The CIDR and IP of both the old and new
// node are provided as context. The caller expects the tunnel mapping in the
// datapath to be updated.
func updateTunnelMapping(oldCIDR, newCIDR cmtypes.PrefixCluster, oldIP, newIP net.IP,
	firstAddition, encapEnabled bool, oldEncryptKey, newEncryptKey uint8, nodeID uint16) error {
	var acc error
	if !encapEnabled {
		// When the protocol family is disabled, the initial node addition will
		// trigger a deletion to clean up leftover entries. The deletion happens
		// in quiet mode as we don't know whether it exists or not
		if newCIDR.IsValid() && firstAddition {
			return deleteTunnelMapping(newCIDR, true)
		}

		return nil
	}

	if cidrNodeMappingUpdateRequired(oldCIDR, newCIDR, oldIP, newIP, oldEncryptKey, newEncryptKey) {
		log.WithFields(logrus.Fields{
			logfields.IPAddr: newIP,
			"allocCIDR":      newCIDR,
		}).Debug("Updating tunnel map entry")

		if err := tunnel.TunnelMap().SetTunnelEndpoint(newEncryptKey, nodeID, newCIDR.AddrCluster(), newIP); err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				"allocCIDR": newCIDR,
			}).Error("bpf: Unable to update in tunnel endpoint map")
			err = multierr.Append(acc, fmt.Errorf("unable to update in tunnel endpoint map: %w", err))
		}
	}

	// Determine whether an old tunnel mapping must be cleaned up. The
	// below switch lists all conditions in which case the oldCIDR must be
	// removed from the tunnel mapping
	switch {
	// CIDR no longer announced
	case !newCIDR.IsValid() && oldCIDR.IsValid():
		fallthrough
	// Node allocation CIDR has changed
	case oldCIDR.IsValid() && newCIDR.IsValid() && !oldCIDR.Equal(newCIDR):
		if err := deleteTunnelMapping(oldCIDR, false); err != nil {
			err = multierr.Append(acc, fmt.Errorf("unable to delete old tunnel mapping: %w", err))
		}
	}
	return acc
}

// cidrNodeMappingUpdateRequired returns true if the change from an old node
// CIDR and node IP to a new node CIDR and node IP requires to insert/update
// the new node CIDR.
func cidrNodeMappingUpdateRequired(oldCIDR, newCIDR cmtypes.PrefixCluster, oldIP, newIP net.IP, oldKey, newKey uint8) bool {
	// No CIDR provided
	if !newCIDR.IsValid() {
		return false
	}
	// Newly announced CIDR
	if !oldCIDR.IsValid() {
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

func deleteTunnelMapping(oldCIDR cmtypes.PrefixCluster, quietMode bool) error {
	if !oldCIDR.IsValid() {
		return nil
	}

	log.WithFields(logrus.Fields{
		"allocPrefixCluster": oldCIDR.String(),
		"quietMode":          quietMode,
	}).Debug("Deleting tunnel map entry")

	addrCluster := oldCIDR.AddrCluster()

	if !quietMode {
		if err := tunnel.TunnelMap().DeleteTunnelEndpoint(addrCluster); err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				"allocPrefixCluster": oldCIDR.String(),
			}).Error("Unable to delete in tunnel endpoint map")
			return err
		}
	} else {
		_ = tunnel.TunnelMap().SilentDeleteTunnelEndpoint(addrCluster)
	}
	return nil
}

func createDirectRouteSpec(CIDR *cidr.CIDR, nodeIP net.IP) (routeSpec *netlink.Route, err error) {
	var routes []netlink.Route

	routeSpec = &netlink.Route{
		Dst:      CIDR.IPNet,
		Gw:       nodeIP,
		Protocol: linux_defaults.RTProto,
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
			return n.deleteAllDirectRoutes(newCIDRs, newIP)
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
	return n.deleteAllDirectRoutes(removedCIDRs, oldIP)
}

func (n *linuxNodeHandler) deleteAllDirectRoutes(CIDRs []*cidr.CIDR, nodeIP net.IP) error {
	var acc error
	for _, cidr := range CIDRs {
		if err := n.deleteDirectRoute(cidr, nodeIP); err != nil {
			acc = multierr.Append(acc, fmt.Errorf("delete route for %q: %w", cidr.String(), err))
		}
	}
	return acc
}

func (n *linuxNodeHandler) deleteDirectRoute(CIDR *cidr.CIDR, nodeIP net.IP) error {
	if CIDR == nil {
		return nil
	}

	family := netlink.FAMILY_V4
	if CIDR.IP.To4() == nil {
		family = netlink.FAMILY_V6
	}

	filter := &netlink.Route{
		Dst:      CIDR.IPNet,
		Gw:       nodeIP,
		Protocol: linux_defaults.RTProto,
	}

	routes, err := netlink.RouteListFiltered(family, filter, netlink.RT_FILTER_DST|netlink.RT_FILTER_GW)
	if err != nil {
		log.WithError(err).Error("Unable to list direct routes")
		return err
	}

	var acc error
	for _, rt := range routes {
		if err := netlink.RouteDel(&rt); err != nil {
			log.WithError(err).Warningf("Unable to delete direct node route %s", rt.String())
			acc = multierr.Append(acc, fmt.Errorf("delete direct node route (link_index=%d)", rt.LinkIndex))
		}
	}
	return acc
}

// createNodeRouteSpec creates a route spec that points the specified prefix to the host
// device via the router IP. The route is configured with a computed MTU for non-local
// nodes (i.e isLocalNode is set to false).
//
// Example:
// 10.10.0.0/24 via 10.10.0.1 dev cilium_host src 10.10.0.1
// f00d::a0a:0:0:0/112 via f00d::a0a:0:0:1 dev cilium_host src fd04::11 metric 1024 pref medium
func (n *linuxNodeHandler) createNodeRouteSpec(prefix *cidr.CIDR, isLocalNode bool) (route.Route, error) {
	var (
		local   net.IP
		nexthop *net.IP
		mtu     int
	)
	if prefix.IP.To4() != nil {
		if n.nodeAddressing.IPv4() == nil {
			return route.Route{}, fmt.Errorf("IPv4 addressing unavailable")
		}

		if n.nodeAddressing.IPv4().Router() == nil {
			return route.Route{}, fmt.Errorf("IPv4 router address unavailable")
		}

		local = n.nodeAddressing.IPv4().Router()
		nexthop = &local
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

		// For ipv6, kernel will reject "ip r a $cidr via $ipv6_cilium_host dev cilium_host"
		// with "Error: Gateway can not be a local address". Instead, we have to remove "via"
		// as "ip r a $cidr dev cilium_host" to make it work.
		nexthop = nil
		local = n.nodeAddressing.IPv6().Router()
	}

	if !isLocalNode {
		mtu = n.nodeConfig.MtuConfig.GetRouteMTU()
	}

	// The default routing table accounts for encryption overhead for encrypt-node traffic
	return route.Route{
		Nexthop:  nexthop,
		Local:    local,
		Device:   n.datapathConfig.HostDevice,
		Prefix:   *prefix.IPNet,
		MTU:      mtu,
		Priority: option.Config.RouteMetric,
		Proto:    linux_defaults.RTProto,
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

func (n *linuxNodeHandler) updateOrRemoveNodeRoutes(old, new []*cidr.CIDR, isLocalNode bool) error {
	var acc error
	addedAuxRoutes, removedAuxRoutes := cidr.DiffCIDRLists(old, new)
	for _, prefix := range addedAuxRoutes {
		if prefix != nil {
			errs.Into(&acc, n.updateNodeRoute(prefix, n.familyEnabled(prefix), isLocalNode))
		}
	}
	for _, prefix := range removedAuxRoutes {
		if rt, _ := n.lookupNodeRoute(prefix, isLocalNode); rt != nil {
			errs.Into(&acc, n.deleteNodeRoute(prefix, isLocalNode))
		}
	}
	return acc
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

func upsertIPsecLog(err error, spec string, loc, rem *net.IPNet, spi uint8, accs ...*error) {
	if err != nil {
		for _, acc := range accs {
			errs.Into(acc,
				fmt.Errorf("%s: IPSec enable failed (local_ip=%s, rem=%s, spi=%d) %w",
					spec,
					loc.String(),
					rem.String(),
					spi, err))
		}
	}

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

func (n *linuxNodeHandler) registerIpsecMetricOnce() {
	n.ipsecMetricOnce.Do(func() {
		metrics.Register(n.ipsecMetricCollector)
	})
}

func (n *linuxNodeHandler) enableSubnetIPsec(v4CIDR, v6CIDR []*net.IPNet) error {
	var acc error

	errs.Into(&acc, n.replaceHostRules())

	for _, cidr := range v4CIDR {
		if !option.Config.EnableEndpointRoutes {
			errs.Into(&acc, n.replaceNodeIPSecInRoute(cidr))
		}
		errs.Into(&acc, n.replaceNodeIPSecOutRoute(cidr))
		if n.nodeConfig.EncryptNode {
			errs.Into(&acc, n.replaceNodeExternalIPSecOutRoute(cidr))
		}
	}

	for _, cidr := range v6CIDR {
		errs.Into(&acc, n.replaceNodeIPSecInRoute(cidr))
		errs.Into(&acc, n.replaceNodeIPSecOutRoute(cidr))
		if n.nodeConfig.EncryptNode {
			errs.Into(&acc, n.replaceNodeExternalIPSecOutRoute(cidr))
		}
	}
	return acc
}

// encryptNode handles setting the IPsec state for node encryption (subnet
// encryption = disabled).
func (n *linuxNodeHandler) encryptNode(newNode *nodeTypes.Node) error {
	var spi uint8
	var err, acc error

	if n.nodeConfig.EnableIPv4 {
		internalIPv4 := n.nodeAddressing.IPv4().PrimaryExternal()
		exactMask := net.IPv4Mask(255, 255, 255, 255)
		ipsecLocal := &net.IPNet{IP: internalIPv4, Mask: exactMask}
		if newNode.IsLocal() {
			wildcardIP := net.ParseIP(wildcardIPv4)
			ipsecIPv4Wildcard := &net.IPNet{IP: wildcardIP, Mask: net.IPv4Mask(0, 0, 0, 0)}
			errs.Into(&acc, n.replaceNodeIPSecInRoute(ipsecLocal))
			spi, err = ipsec.UpsertIPsecEndpoint(ipsecLocal, ipsecIPv4Wildcard, internalIPv4, wildcardIP, 0, ipsec.IPSecDirIn, false)
			upsertIPsecLog(err, "EncryptNode local IPv4", ipsecLocal, ipsecIPv4Wildcard, spi, &acc)
		} else {
			if remoteIPv4 := newNode.GetNodeIP(false); remoteIPv4 != nil {
				ipsecRemote := &net.IPNet{IP: remoteIPv4, Mask: exactMask}
				errs.Into(&acc, n.replaceNodeExternalIPSecOutRoute(ipsecRemote))
				spi, err = ipsec.UpsertIPsecEndpoint(ipsecLocal, ipsecRemote, internalIPv4, remoteIPv4, 0, ipsec.IPSecDirOutNode, false)
				upsertIPsecLog(err, "EncryptNode IPv4", ipsecLocal, ipsecRemote, spi, &acc)
			}
			remoteIPv4 := newNode.GetCiliumInternalIP(false)
			if remoteIPv4 != nil {
				mask := newNode.IPv4AllocCIDR.Mask
				ipsecRemoteRoute := &net.IPNet{IP: remoteIPv4.Mask(mask), Mask: mask}
				ipsecRemote := &net.IPNet{IP: remoteIPv4, Mask: mask}
				ipsecWildcard := &net.IPNet{IP: net.ParseIP(wildcardIPv4), Mask: net.IPv4Mask(0, 0, 0, 0)}

				errs.Into(&acc, n.replaceNodeExternalIPSecOutRoute(ipsecRemoteRoute))
				if remoteIPv4T := newNode.GetNodeIP(false); remoteIPv4T != nil {
					err = ipsec.UpsertIPsecEndpointPolicy(ipsecWildcard, ipsecRemote, internalIPv4, remoteIPv4T, 0, ipsec.IPSecDirOutNode)
				}
				upsertIPsecLog(err, "EncryptNode Cilium IPv4", ipsecWildcard, ipsecRemote, spi, &acc)
			}
		}
	}

	if n.nodeConfig.EnableIPv6 {
		internalIPv6 := n.nodeAddressing.IPv6().PrimaryExternal()
		exactMask := net.CIDRMask(128, 128)
		ipsecLocal := &net.IPNet{IP: internalIPv6, Mask: exactMask}
		if newNode.IsLocal() {
			wildcardIP := net.ParseIP(wildcardIPv6)
			ipsecIPv6Wildcard := &net.IPNet{IP: wildcardIP, Mask: net.CIDRMask(0, 0)}
			errs.Into(&acc, n.replaceNodeIPSecInRoute(ipsecLocal))
			spi, err = ipsec.UpsertIPsecEndpoint(ipsecLocal, ipsecIPv6Wildcard, internalIPv6, wildcardIP, 0, ipsec.IPSecDirIn, false)
			upsertIPsecLog(err, "EncryptNode local IPv6", ipsecLocal, ipsecIPv6Wildcard, spi, &acc)
		} else {
			if remoteIPv6 := newNode.GetNodeIP(true); remoteIPv6 != nil {
				ipsecRemote := &net.IPNet{IP: remoteIPv6, Mask: exactMask}
				errs.Into(&acc, n.replaceNodeExternalIPSecOutRoute(ipsecRemote))
				spi, err = ipsec.UpsertIPsecEndpoint(ipsecLocal, ipsecRemote, internalIPv6, remoteIPv6, 0, ipsec.IPSecDirOut, false)
				upsertIPsecLog(err, "EncryptNode IPv6", ipsecLocal, ipsecRemote, spi, &acc)
			}
			remoteIPv6 := newNode.GetCiliumInternalIP(true)
			if remoteIPv6 != nil {
				mask := newNode.IPv6AllocCIDR.Mask
				ipsecRemoteRoute := &net.IPNet{IP: remoteIPv6.Mask(mask), Mask: mask}
				ipsecRemote := &net.IPNet{IP: remoteIPv6, Mask: mask}
				ipsecWildcard := &net.IPNet{IP: net.ParseIP(wildcardIPv6), Mask: net.CIDRMask(0, 0)}

				errs.Into(&acc, n.replaceNodeExternalIPSecOutRoute(ipsecRemoteRoute))
				if remoteIPv6T := newNode.GetNodeIP(true); remoteIPv6T != nil {
					err = ipsec.UpsertIPsecEndpointPolicy(ipsecWildcard, ipsecRemote, internalIPv6, remoteIPv6T, 0, ipsec.IPSecDirOutNode)
				}
				upsertIPsecLog(err, "EncryptNode Cilium IPv6", ipsecWildcard, ipsecRemote, spi, &acc)
			}
		}
	}
	return acc
}

func getNextHopIP(nodeIP net.IP, link netlink.Link) (nextHopIP net.IP, err error) {
	// Figure out whether nodeIP is directly reachable (i.e. in the same L2)
	routes, err := netlink.RouteGetWithOptions(nodeIP, &netlink.RouteGetOptions{Oif: link.Attrs().Name})
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

func (n *linuxNodeHandler) insertNeighborCommon(scopedLog *logrus.Entry, ctx context.Context, nextHop NextHop, link netlink.Link, refresh bool) error {
	var acc error
	if refresh {
		if lastPing, found := n.neighLastPingByNextHop[nextHop.Name]; found &&
			time.Since(lastPing) < option.Config.ARPPingRefreshPeriod {
			// Last ping was issued less than option.Config.ARPPingRefreshPeriod
			// ago, so skip it (e.g. to avoid ddos'ing the same GW if nodes are
			// L3 connected)
			return nil
		}
	}

	// Don't proceed if the refresh controller cancelled the context
	select {
	case <-ctx.Done():
		return nil
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
		return fmt.Errorf("unable to refresh next hop: %w", err)
	}
	n.neighByNextHop[nextHop.Name] = &neigh
	return acc
}

func (n *linuxNodeHandler) insertNeighbor4(ctx context.Context, newNode *nodeTypes.Node, link netlink.Link, refresh bool) (err error) {
	newNodeIP := newNode.GetNodeIP(false)
	nextHopIPv4 := make(net.IP, len(newNodeIP))
	copy(nextHopIPv4, newNodeIP)

	scopedLog := log.WithFields(logrus.Fields{
		logfields.LogSubsys: "node-neigh-debug",
		logfields.Interface: link.Attrs().Name,
		logfields.IPAddr:    newNodeIP,
	})

	nextHopIPv4, err = getNextHopIP(nextHopIPv4, link)
	if err != nil {
		scopedLog.WithError(err).Info("Unable to determine next hop address")
		return fmt.Errorf("unable to determine next hop address: %w", err)
	}
	nextHopStr := nextHopIPv4.String()
	scopedLog = scopedLog.WithField(logfields.NextHop, nextHopIPv4)

	n.neighLock.Lock()
	defer n.neighLock.Unlock()

	nextHopByLink, found := n.neighNextHopByNode4[newNode.Identity()]
	if !found {
		nextHopByLink = make(map[string]string)
		n.neighNextHopByNode4[newNode.Identity()] = nextHopByLink
	}

	nextHopIsNew := false
	if existingNextHopStr, found := nextHopByLink[link.Attrs().Name]; found {
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
					if errs.Into(&err, netlink.NeighDel(neigh)) {
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

	n.neighNextHopByNode4[newNode.Identity()][link.Attrs().Name] = nextHopStr
	nh := NextHop{
		Name:  nextHopStr,
		IP:    nextHopIPv4,
		IsNew: nextHopIsNew,
	}

	errs.Into(&err, n.insertNeighborCommon(scopedLog, ctx, nh, link, refresh))
	return
}

func (n *linuxNodeHandler) insertNeighbor6(ctx context.Context, newNode *nodeTypes.Node, link netlink.Link, refresh bool) (err error) {
	newNodeIP := newNode.GetNodeIP(true)
	nextHopIPv6 := make(net.IP, len(newNodeIP))
	copy(nextHopIPv6, newNodeIP)

	scopedLog := log.WithFields(logrus.Fields{
		logfields.LogSubsys: "node-neigh-debug",
		logfields.Interface: link.Attrs().Name,
		logfields.IPAddr:    newNodeIP,
	})

	nextHopIPv6, err = getNextHopIP(nextHopIPv6, link)
	if err != nil {
		scopedLog.WithError(err).Info("Unable to determine next hop address")
		return fmt.Errorf("unable to determine next hop address: %w", err)
	}
	nextHopStr := nextHopIPv6.String()
	scopedLog = scopedLog.WithField(logfields.NextHop, nextHopIPv6)

	n.neighLock.Lock()
	defer n.neighLock.Unlock()

	nextHopByLink, found := n.neighNextHopByNode6[newNode.Identity()]
	if !found {
		nextHopByLink = make(map[string]string)
		n.neighNextHopByNode6[newNode.Identity()] = nextHopByLink
	}

	nextHopIsNew := false
	if existingNextHopStr, found := nextHopByLink[link.Attrs().Name]; found {
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
					if errs.Into(&err, netlink.NeighDel(neigh)) {
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

	n.neighNextHopByNode6[newNode.Identity()][link.Attrs().Name] = nextHopStr
	nh := NextHop{
		Name:  nextHopStr,
		IP:    nextHopIPv6,
		IsNew: nextHopIsNew,
	}
	errs.Into(&err, n.insertNeighborCommon(scopedLog, ctx, nh, link, refresh))
	return
}

// insertNeighbor inserts a non-GC'able neighbor entry for a nexthop to the given
// "newNode" (ip route get newNodeIP.GetNodeIP()). The L2 addr of the nexthop is
// determined by the Linux kernel's neighboring subsystem. The related iface for
// the neighbor is specified by n.neighDiscoveryLink.
//
// The given "refresh" param denotes whether the method is called by a controller
// which tries to update neighbor entries previously inserted by insertNeighbor().
// In this case the kernel refreshes the entry via NTF_USE.
func (n *linuxNodeHandler) insertNeighbor(ctx context.Context, newNode *nodeTypes.Node, refresh bool) error {
	var acc error
	var links []netlink.Link

	n.neighLock.Lock()
	if n.neighDiscoveryLinks == nil || len(n.neighDiscoveryLinks) == 0 {
		n.neighLock.Unlock()
		// Nothing to do - the discovery link was not set yet
		return nil
	}
	links = n.neighDiscoveryLinks
	n.neighLock.Unlock()

	if newNode.GetNodeIP(false).To4() != nil {
		for _, l := range links {
			errs.Into(&acc, n.insertNeighbor4(ctx, newNode, l, refresh))
		}
	}
	if newNode.GetNodeIP(true).To16() != nil {
		for _, l := range links {
			errs.Into(&acc, n.insertNeighbor6(ctx, newNode, l, refresh))
		}
	}
	return acc
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
	nextHopByLink, found := n.neighNextHopByNode4[oldNode.Identity()]
	if !found {
		return
	}
	defer func() { delete(n.neighNextHopByNode4, oldNode.Identity()) }()
	for _, nextHopStr := range nextHopByLink {
		n.deleteNeighborCommon(nextHopStr)
	}
}

func (n *linuxNodeHandler) deleteNeighbor6(oldNode *nodeTypes.Node) {
	n.neighLock.Lock()
	defer n.neighLock.Unlock()
	nextHopByLink, found := n.neighNextHopByNode6[oldNode.Identity()]
	if !found {
		return
	}
	defer func() { delete(n.neighNextHopByNode6, oldNode.Identity()) }()
	for _, nextHopStr := range nextHopByLink {
		n.deleteNeighborCommon(nextHopStr)
	}
}

func (n *linuxNodeHandler) deleteNeighbor(oldNode *nodeTypes.Node) {
	n.deleteNeighbor4(oldNode)
	n.deleteNeighbor6(oldNode)
}

// enableIPSec performs necessary host datapath configuration procedures to
// enable IPsec for the given node.
//
// TODO: In subsequent commit, look at procedural calls that may be "asymptotic",
//
//	thus if their state is already settled?
func (n *linuxNodeHandler) enableIPsec(newNode *nodeTypes.Node) error {
	var spi uint8
	var acc error

	if newNode.IsLocal() {
		errs.Into(&acc, n.replaceHostRules())
	}

	// In endpoint routes mode we use the stack to route packets after
	// the packet is decrypted so set skb->mark to zero from XFRM stack
	// to avoid confusion in netfilters and conntrack that may be using
	// the mark fields. This uses XFRM_OUTPUT_MARK added in 4.14 kernels.
	zeroMark := option.Config.EnableEndpointRoutes

	if n.nodeConfig.EnableIPv4 && newNode.IPv4AllocCIDR != nil {
		new4Net := newNode.IPv4AllocCIDR.IPNet
		wildcardIP := net.ParseIP(wildcardIPv4)
		wildcardCIDR := &net.IPNet{IP: wildcardIP, Mask: net.IPv4Mask(0, 0, 0, 0)}

		// Set default drop policy for IPv4, regardless if node is local.
		err := ipsec.IPsecDefaultDropPolicy(false)
		upsertIPsecLog(err, "default-drop IPv4", wildcardCIDR, wildcardCIDR, spi, &acc)

		if newNode.IsLocal() {
			errs.Into(&acc, n.replaceNodeIPSecInRoute(new4Net))

			if localIP := newNode.GetCiliumInternalIP(false); localIP != nil {
				if n.subnetEncryption() {
					for _, cidr := range n.nodeConfig.IPv4PodSubnets {
						/* Insert wildcard policy rules for traffic skipping back through host */
						if err = ipsec.IpSecReplacePolicyFwd(cidr, localIP); err != nil {
							log.WithError(err).Warning("egress unable to replace policy fwd:")
							errs.Into(&acc, fmt.Errorf("unable to replace policy fwd: %w", err))
						}

						spi, err := ipsec.UpsertIPsecEndpoint(wildcardCIDR, cidr, localIP, wildcardIP, 0, ipsec.IPSecDirIn, zeroMark)
						upsertIPsecLog(err, "in IPv4", wildcardCIDR, cidr, spi, &acc)
					}
				} else {
					localCIDR := n.nodeAddressing.IPv4().AllocationCIDR().IPNet
					spi, err = ipsec.UpsertIPsecEndpoint(localCIDR, wildcardCIDR, localIP, wildcardIP, 0, ipsec.IPSecDirIn, false)
					upsertIPsecLog(err, "in IPv4", localCIDR, wildcardCIDR, spi, &acc)
				}
			}
		} else {
			if remoteIP := newNode.GetCiliumInternalIP(false); remoteIP != nil {
				localIP := n.nodeAddressing.IPv4().Router()
				remoteNodeID := n.allocateIDForNode(newNode)

				if n.subnetEncryption() {
					for _, cidr := range n.nodeConfig.IPv4PodSubnets {
						// @tom here---->
						spi, err = ipsec.UpsertIPsecEndpoint(wildcardCIDR, cidr, localIP, remoteIP, remoteNodeID, ipsec.IPSecDirOut, zeroMark)
						fmt.Println("[tom-debug] 111->", err)
						upsertIPsecLog(err, "out IPv4", wildcardCIDR, cidr, spi, &acc)
					}
				} else {
					localCIDR := n.nodeAddressing.IPv4().AllocationCIDR().IPNet
					remoteCIDR := newNode.IPv4AllocCIDR.IPNet
					errs.Into(&acc, n.replaceNodeIPSecOutRoute(new4Net))
					spi, err = ipsec.UpsertIPsecEndpoint(localCIDR, remoteCIDR, localIP, remoteIP, remoteNodeID, ipsec.IPSecDirOut, false)
					fmt.Println("[tom-debug] 222->", err)
					// So this is for non local endpoints
					upsertIPsecLog(err, "out IPv4", localCIDR, remoteCIDR, spi, &acc)

					/* Insert wildcard policy rules for traffic skipping back through host */
					if err = ipsec.IpSecReplacePolicyFwd(remoteCIDR, remoteIP); err != nil {
						log.WithError(err).Warning("egress unable to replace policy fwd")
						errs.Into(&acc, fmt.Errorf("unable to replace policy fwd: %w", err))
					}
				}
			}
		}
	}

	if n.nodeConfig.EnableIPv6 && newNode.IPv6AllocCIDR != nil {
		new6Net := newNode.IPv6AllocCIDR.IPNet
		wildcardIP := net.ParseIP(wildcardIPv6)
		wildcardCIDR := &net.IPNet{IP: wildcardIP, Mask: net.CIDRMask(0, 128)}

		err := ipsec.IPsecDefaultDropPolicy(true)
		upsertIPsecLog(err, "default-drop IPv6", wildcardCIDR, wildcardCIDR, spi, &acc)

		if newNode.IsLocal() {
			errs.Into(&err, n.replaceNodeIPSecInRoute(new6Net))

			if localIP := newNode.GetCiliumInternalIP(true); localIP != nil {
				if n.subnetEncryption() {
					for _, cidr := range n.nodeConfig.IPv6PodSubnets {
						spi, err := ipsec.UpsertIPsecEndpoint(wildcardCIDR, cidr, localIP, wildcardIP, 0, ipsec.IPSecDirIn, zeroMark)
						upsertIPsecLog(err, "in IPv6", wildcardCIDR, cidr, spi, &acc)
					}
				} else {
					localCIDR := n.nodeAddressing.IPv6().AllocationCIDR().IPNet
					spi, err = ipsec.UpsertIPsecEndpoint(localCIDR, wildcardCIDR, localIP, wildcardIP, 0, ipsec.IPSecDirIn, false)
					upsertIPsecLog(err, "in IPv6", localCIDR, wildcardCIDR, spi, &acc)
				}
			}
		} else {
			if remoteIP := newNode.GetCiliumInternalIP(true); remoteIP != nil {
				localIP := n.nodeAddressing.IPv6().Router()
				remoteNodeID := n.allocateIDForNode(newNode)

				if n.subnetEncryption() {
					for _, cidr := range n.nodeConfig.IPv6PodSubnets {
						spi, err = ipsec.UpsertIPsecEndpoint(wildcardCIDR, cidr, localIP, remoteIP, remoteNodeID, ipsec.IPSecDirOut, zeroMark)
						upsertIPsecLog(err, "out IPv6", wildcardCIDR, cidr, spi, &acc)
					}
				} else {
					localCIDR := n.nodeAddressing.IPv6().AllocationCIDR().IPNet
					remoteCIDR := newNode.IPv6AllocCIDR.IPNet
					errs.Into(&acc, n.replaceNodeIPSecOutRoute(new6Net))
					spi, err := ipsec.UpsertIPsecEndpoint(localCIDR, remoteCIDR, localIP, remoteIP, remoteNodeID, ipsec.IPSecDirOut, false)
					upsertIPsecLog(err, "out IPv6", localCIDR, remoteCIDR, spi, &acc)
				}
			}
		}
	}
	return acc
}

func (n *linuxNodeHandler) subnetEncryption() bool {
	return len(n.nodeConfig.IPv4PodSubnets) > 0 || len(n.nodeConfig.IPv6PodSubnets) > 0
}

// Must be called with linuxNodeHandler.mutex held.
func (n *linuxNodeHandler) nodeUpdate(oldNode, newNode *nodeTypes.Node, firstAddition bool) error {
	// Question: Is this the approach we want to take, its a bit ugly in cases like this where there
	// is a lot of places for errors to be tacked on.
	//
	// Perhaps we want another multierr?
	// This is the high level reconciliation function for this node handler implementation,
	// upon return, aggregate all errors and return them to the caller.
	//
	// Outline of procedure:
	// 1. Do ipsec reconciliation.
	// 2. Spawn off async neighbor reconciliation.
	//
	// TODO: Look into that palantir thingy.
	// defer func() {
	// 	acc = n.aggregateErrs()
	// }()
	//
	//
	// TODO:
	// * There may be some complicated interplay/overlap with setting routes
	//		via the ipsec/encryptNode/subnetIPSec functions.
	//		You'll need to see if there is any considerations there, if so that may be deferred in doc.

	var acc error

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

	// If the nodeConfig enables IPSec and the node is not encrypted, enable IPSec.
	//
	// This should be idempoent, so we can call it on every node update and errors
	// generally should indicate possible degraded host state issues.
	if n.nodeConfig.EnableIPSec && !n.nodeConfig.EncryptNode {
		errs.Into(&acc, n.enableIPsec(newNode))
		newKey = newNode.EncryptionKey
	}

	// So this inserts l2 neighbors from non-local node events.
	// That is, if a node is added, we insert it as a neighbor locally.
	//
	// TODO: Ask about what happens if this fails?
	//
	// So this seems pretty critical, how do we handle this?
	if n.enableNeighDiscovery && !newNode.IsLocal() {
		// Running insertNeighbor in a separate goroutine relies on the following
		// assumptions:
		// 1. newNode is accessed only by reads.
		// 2. It is safe to invoke insertNeighbor for the same node.

		// insertCh := make(chan []error)
		// TODO: There is a goroutine that runs a background process that invokes this periodically,
		// 	do we need to do this here?
		//
		// The final param, "refresh" denotes whether this is a new neighbor or a refresh of an existing
		// one.
		// If it's a refresh, then it uses NTF_USE to refresh the neighbor entry.
		go func() {
			err := n.insertNeighbor(context.Background(), newNode, false)
			if err != nil {
				newName := newNode.Fullname()
				n.neighLock.Lock()
				// TODO: Collect on these, also need to ensure they don't grow too big.
				n.reportNeighFailure(newName, err)
				n.neighLock.Unlock()
			}
		}()
	}

	if n.nodeConfig.EnableIPSec && n.nodeConfig.EncryptNode && !n.subnetEncryption() {
		if err := n.encryptNode(newNode); err != nil {
			acc = multierr.Append(acc, fmt.Errorf("encrypting node %q: %w", newNode, err))
		}
	}

	if newNode.IsLocal() {
		isLocalNode = true
		if n.nodeConfig.EnableLocalNodeRoute {
			if err := n.updateOrRemoveNodeRoutes(oldAllIP4AllocCidrs, newAllIP4AllocCidrs, isLocalNode); err != nil {
				acc = multierr.Append(acc, fmt.Errorf("sync node ipv4 routes: %w", err))
			}
			if err := n.updateOrRemoveNodeRoutes(oldAllIP6AllocCidrs, newAllIP6AllocCidrs, isLocalNode); err != nil {
				acc = multierr.Append(acc, fmt.Errorf("sync node ipv6 routes: %w", err))
			}
		}
		if n.subnetEncryption() {
			if err := n.enableSubnetIPsec(n.nodeConfig.IPv4PodSubnets, n.nodeConfig.IPv6PodSubnets); err != nil {
				acc = multierr.Append(acc, fmt.Errorf("enabling subnet encryption: %w", err))
			}
		}
		if firstAddition && n.nodeConfig.EnableIPSec {
			n.registerIpsecMetricOnce()
		}
		return nil
	}

	if option.Config.EnableWireguard && newNode.WireguardPubKey != "" {
		if err := n.wgAgent.UpdatePeer(newNode.Fullname(), newNode.WireguardPubKey, newIP4, newIP6); err != nil {
			log.WithError(err).
				WithField(logfields.NodeName, newNode.Fullname()).
				Warning("Failed to update wireguard configuration for peer")
			acc = multierr.Append(acc, fmt.Errorf("enable WireGuard: configuration for peer: %w", err))
		}
	}

	if n.nodeConfig.EnableAutoDirectRouting {
		if err := n.updateDirectRoutes(oldAllIP4AllocCidrs, newAllIP4AllocCidrs, oldIP4, newIP4, firstAddition, n.nodeConfig.EnableIPv4); err != nil {
			errs.Into(&acc, fmt.Errorf("enabling auto direct routing (ipv4): %w", err))
		}
		if err := n.updateDirectRoutes(oldAllIP6AllocCidrs, newAllIP6AllocCidrs, oldIP6, newIP6, firstAddition, n.nodeConfig.EnableIPv6); err != nil {
			errs.Into(&acc, fmt.Errorf("enabling auto direct routing (ipv6): %w", err))
		}
		return acc
	}

	if n.nodeConfig.EnableEncapsulation {
		// An uninitialized PrefixCluster has empty netip.Prefix and 0 ClusterID.
		// We use this empty PrefixCluster instead of nil here.
		var (
			oldPrefixCluster4 cmtypes.PrefixCluster
			oldPrefixCluster6 cmtypes.PrefixCluster
			newPrefixCluster4 cmtypes.PrefixCluster
			newPrefixCluster6 cmtypes.PrefixCluster
		)

		if oldNode != nil {
			oldPrefixCluster4 = cmtypes.PrefixClusterFromCIDR(oldIP4Cidr, 0)
			oldPrefixCluster6 = cmtypes.PrefixClusterFromCIDR(oldIP6Cidr, 0)
		}

		if newNode != nil {
			newPrefixCluster4 = cmtypes.PrefixClusterFromCIDR(newNode.IPv4AllocCIDR, 0)
			newPrefixCluster6 = cmtypes.PrefixClusterFromCIDR(newNode.IPv6AllocCIDR, 0)
		}

		nodeID := n.allocateIDForNode(newNode)

		// Update the tunnel mapping of the node. In case the
		// node has changed its CIDR range, a new entry in the
		// map is created and the old entry is removed.
		errs.Into(&acc, updateTunnelMapping(oldPrefixCluster4, newPrefixCluster4, oldIP4, newIP4, firstAddition, n.nodeConfig.EnableIPv4, oldKey, newKey, nodeID))
		// Not a typo, the IPv4 host IP is used to build the IPv6 overlay
		errs.Into(&acc, updateTunnelMapping(oldPrefixCluster6, newPrefixCluster6, oldIP4, newIP4, firstAddition, n.nodeConfig.EnableIPv6, oldKey, newKey, nodeID))

		if !n.nodeConfig.UseSingleClusterRoute {
			errs.Into(&acc, n.updateOrRemoveNodeRoutes(oldAllIP4AllocCidrs, newAllIP4AllocCidrs, isLocalNode))
			errs.Into(&acc, n.updateOrRemoveNodeRoutes(oldAllIP6AllocCidrs, newAllIP6AllocCidrs, isLocalNode))
		}

		return acc
	} else if firstAddition {
		for _, ipv4AllocCIDR := range newAllIP4AllocCidrs {
			if rt, _ := n.lookupNodeRoute(ipv4AllocCIDR, isLocalNode); rt != nil {
				if err := n.deleteNodeRoute(ipv4AllocCIDR, isLocalNode); err != nil {
					acc = multierr.Append(acc, err)
				}
			}
		}
		for _, ipv6AllocCIDR := range newAllIP6AllocCidrs {
			if rt, _ := n.lookupNodeRoute(ipv6AllocCIDR, isLocalNode); rt != nil {
				if err := n.deleteNodeRoute(ipv6AllocCIDR, isLocalNode); err != nil {
					acc = multierr.Append(acc, err)
				}
			}
		}
	}

	return acc
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
		oldPrefix4 := cmtypes.PrefixClusterFromCIDR(oldNode.IPv4AllocCIDR, oldNode.ClusterID)
		oldPrefix6 := cmtypes.PrefixClusterFromCIDR(oldNode.IPv6AllocCIDR, oldNode.ClusterID)
		deleteTunnelMapping(oldPrefix4, false)
		deleteTunnelMapping(oldPrefix6, false)

		if !n.nodeConfig.UseSingleClusterRoute {
			n.deleteNodeRoute(oldNode.IPv4AllocCIDR, false)
			n.deleteNodeRoute(oldNode.IPv6AllocCIDR, false)
		}
	}

	if n.enableNeighDiscovery {
		go n.deleteNeighbor(oldNode)
	}

	if n.nodeConfig.EnableIPSec {
		n.deleteIPsec(oldNode)
	}

	if option.Config.EnableWireguard {
		if err := n.wgAgent.DeletePeer(oldNode.Fullname()); err != nil {
			return err
		}
	}

	n.deallocateIDForNode(oldNode)

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

// replaceHostRules attempts to emplace ipsec encrypt/decrypt routes.
func (n *linuxNodeHandler) replaceHostRules() error {
	// Add a new IP route rule to ipsec table.
	rule := route.Rule{
		Priority: 1,
		Mask:     linux_defaults.RouteMarkMask,
		Table:    linux_defaults.RouteTableIPSec,
		Protocol: linux_defaults.RTProto,
	}

	if n.nodeConfig.EnableIPv4 {
		if !option.Config.EnableEndpointRoutes {
			rule.Mark = linux_defaults.RouteMarkDecrypt
			if err := route.ReplaceRule(rule); err != nil {
				log.WithError(err).Error("Replace IPv4 route decrypt rule failed")
				return fmt.Errorf("failed to replace ipv4 route decrypt rule: %w", err)
			}
		}
		rule.Mark = linux_defaults.RouteMarkEncrypt
		if err := route.ReplaceRule(rule); err != nil {
			log.WithError(err).Error("Replace IPv4 route encrypt rule failed")
			return fmt.Errorf("failed to replace ipv4 route encrypt rule: %w", err)
		}
	}

	if n.nodeConfig.EnableIPv6 {
		rule.Mark = linux_defaults.RouteMarkDecrypt
		if err := route.ReplaceRuleIPv6(rule); err != nil {
			log.WithError(err).Error("Replace IPv6 route decrypt rule failed")
			return fmt.Errorf("failed to replace ipv6 route decrypt rule: %w", err)
		}
		rule.Mark = linux_defaults.RouteMarkEncrypt
		if err := route.ReplaceRuleIPv6(rule); err != nil {
			log.WithError(err).Error("Replace IPv6 route encrypt rule failed")
			return fmt.Errorf("failed to replace ipv6 route encrypt rule: %w", err)
		}
	}

	return nil
}

func (n *linuxNodeHandler) removeEncryptRules() error {
	rule := route.Rule{
		Priority: 1,
		Mask:     linux_defaults.RouteMarkMask,
		Table:    linux_defaults.RouteTableIPSec,
		Protocol: linux_defaults.RTProto,
	}

	rule.Mark = linux_defaults.RouteMarkDecrypt
	if err := route.DeleteRule(netlink.FAMILY_V4, rule); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("Delete previous IPv4 decrypt rule failed: %s", err)
		}
	}

	rule.Mark = linux_defaults.RouteMarkEncrypt
	if err := route.DeleteRule(netlink.FAMILY_V4, rule); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("Delete previousa IPv4 encrypt rule failed: %s", err)
		}
	}

	if err := route.DeleteRouteTable(linux_defaults.RouteTableIPSec, netlink.FAMILY_V4); err != nil {
		log.WithError(err).Warn("Deletion of IPSec routes failed")
	}

	rule.Mark = linux_defaults.RouteMarkDecrypt
	if err := route.DeleteRule(netlink.FAMILY_V6, rule); err != nil {
		if !os.IsNotExist(err) && !errors.Is(err, unix.EAFNOSUPPORT) {
			return fmt.Errorf("Delete previous IPv6 decrypt rule failed: %s", err)
		}
	}

	rule.Mark = linux_defaults.RouteMarkEncrypt
	if err := route.DeleteRule(netlink.FAMILY_V6, rule); err != nil {
		if !os.IsNotExist(err) && !errors.Is(err, unix.EAFNOSUPPORT) {
			return fmt.Errorf("Delete previous IPv6 encrypt rule failed: %s", err)
		}
	}
	return nil
}

func (n *linuxNodeHandler) createNodeIPSecInRoute(ip *net.IPNet) route.Route {
	var device string

	if !option.Config.TunnelingEnabled() {
		device = option.Config.EncryptInterface[0]
	} else {
		device = option.Config.TunnelDevice()
	}
	return route.Route{
		Nexthop: nil,
		Device:  device,
		Prefix:  *ip,
		Table:   linux_defaults.RouteTableIPSec,
		Proto:   linux_defaults.RTProto,
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
		Proto:   linux_defaults.RTProto,
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

// returns if passed IP type is enabled (ip4/ip6), as well as what
// ip version it is.
func (n *linuxNodeHandler) checkIP(ip *net.IPNet) (string, bool) {
	if ip.IP.To4() != nil {
		return "ipv4", n.nodeConfig.EnableIPv4
	} else {
		return "ipv6", n.nodeConfig.EnableIPv6
	}
}

// replaceNodeIPSecOutRoute replace the out IPSec route in the host routing
// table with the new route. If no route exists the route is installed on the
// host. The caller must ensure that the CIDR passed in must be non-nil.
func (n *linuxNodeHandler) replaceNodeIPSecOutRoute(ip *net.IPNet) error {
	ipv, enabled := n.checkIP(ip)
	if !enabled {
		return nil
	}

	if err := route.Upsert(n.createNodeIPSecOutRoute(ip)); err != nil {
		log.WithError(err).WithField(logfields.CIDR, ip).Error("Unable to replace the IPSec route OUT the host routing table")
		return fmt.Errorf("unable to replace the IPSec route OUT the host routing table (%s): %w", ipv, err)
	}
	return nil
}

// replaceNodeExternalIPSecOutRoute replace the out IPSec route in the host
// routing table with the new route. If no route exists the route is installed
// on the host. The caller must ensure that the CIDR passed in must be non-nil.
func (n *linuxNodeHandler) replaceNodeExternalIPSecOutRoute(ip *net.IPNet) error {
	var acc error
	ipv, enabled := n.checkIP(ip)
	if !enabled {
		return nil
	}

	if err := route.Upsert(n.createNodeExternalIPSecOutRoute(ip, true)); err != nil {
		log.WithError(err).WithField(logfields.CIDR, ip).Error("Unable to replace the IPSec route OUT the default routing table")
		acc = multierr.Append(acc, fmt.Errorf("Unable to replace IPSec route OUT on default routing table (%s): %w", ipv, err))
	}
	if err := route.Upsert(n.createNodeExternalIPSecOutRoute(ip, false)); err != nil {
		log.WithError(err).WithField(logfields.CIDR, ip).Error("Unable to replace the IPSec route OUT the host routing table")
		acc = multierr.Append(acc, fmt.Errorf("Unable to replace IPSec route OUT on host routing table (%s): %w", ipv, err))
	}
	return acc
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
func (n *linuxNodeHandler) replaceNodeIPSecInRoute(ip *net.IPNet) error {
	ipv, enabled := n.checkIP(ip)
	if !enabled {
		return nil
	}

	if err := route.Upsert(n.createNodeIPSecInRoute(ip)); err != nil {
		log.WithError(err).WithField(logfields.CIDR, ip).Error("Unable to replace the IPSec route IN the host routing table")
		return fmt.Errorf("unable to replace the IPSec route IN the host routing table (%s): %w", ipv, err)
	}
	return nil
}

func (n *linuxNodeHandler) deleteIPsec(oldNode *nodeTypes.Node) {
	if n.nodeConfig.EnableIPv4 && oldNode.IPv4AllocCIDR != nil {
		ciliumInternalIPv4 := oldNode.GetCiliumInternalIP(false)
		old4RouteNet := &net.IPNet{IP: oldNode.IPv4AllocCIDR.IP, Mask: oldNode.IPv4AllocCIDR.Mask}
		n.deleteNodeIPSecOutRoute(old4RouteNet)
		ipsec.DeleteIPsecEndpoint(ciliumInternalIPv4)
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
		old6RouteNet := &net.IPNet{IP: oldNode.IPv6AllocCIDR.IP, Mask: oldNode.IPv6AllocCIDR.Mask}
		n.deleteNodeIPSecOutRoute(old6RouteNet)
		ipsec.DeleteIPsecEndpoint(ciliumInternalIPv6)
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
		var ifaceNames []string
		switch {
		case !option.Config.EnableL2NeighDiscovery:
			n.enableNeighDiscovery = false
		case option.Config.DirectRoutingDeviceRequired():
			if option.Config.DirectRoutingDevice == "" {
				return fmt.Errorf("direct routing device is required, but not defined")
			}

			var targetDevices []string
			targetDevices = append(targetDevices, option.Config.DirectRoutingDevice)
			targetDevices = append(targetDevices, option.Config.GetDevices()...)

			var err error
			ifaceNames, err = filterL2Devices(targetDevices)
			if err != nil {
				return err
			}
			n.enableNeighDiscovery = len(ifaceNames) != 0 // No need to arping for L2-less devices
		case n.nodeConfig.EnableIPSec && !option.Config.TunnelingEnabled() &&
			len(option.Config.EncryptInterface) != 0:
			// When FIB lookup is not supported we need to pick an
			// interface so pick first interface in the list. On
			// kernels with FIB lookup helpers we do a lookup from
			// the datapath side and ignore this value.
			ifaceNames = append(ifaceNames, option.Config.EncryptInterface[0])
		}

		if n.enableNeighDiscovery {
			var neighDiscoveryLinks []netlink.Link
			for _, ifaceName := range ifaceNames {
				l, err := netlink.LinkByName(ifaceName)
				if err != nil {
					return fmt.Errorf("cannot find link by name %s for neighbor discovery: %w",
						ifaceName, err)
				}
				neighDiscoveryLinks = append(neighDiscoveryLinks, l)
			}

			// Store neighDiscoveryLink so that we can remove the ARP
			// PERM entries when cilium-agent starts with neigh discovery
			// disabled next time.
			err := storeNeighLink(option.Config.StateDir, ifaceNames)
			if err != nil {
				log.WithError(err).Warning("Unable to store neighbor discovery iface." +
					" Removing PERM neighbor entries upon cilium-agent init when neighbor" +
					" discovery is disabled will not work.")
			}

			// neighDiscoveryLink can be accessed by a concurrent insertNeighbor
			// goroutine.
			n.neighLock.Lock()
			n.neighDiscoveryLinks = neighDiscoveryLinks
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
		n.registerIpsecMetricOnce()
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

func filterL2Devices(devices []string) ([]string, error) {
	// Eliminate duplicates
	deviceSets := make(map[string]struct{})
	for _, d := range devices {
		deviceSets[d] = struct{}{}
	}

	var l2devices []string
	for k := range deviceSets {
		mac, err := link.GetHardwareAddr(k)
		if err != nil {
			return nil, err
		}
		if mac != nil {
			l2devices = append(l2devices, k)
		}
	}
	return l2devices, nil
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
	linkNames, err := loadNeighLink(option.Config.StateDir)
	if err != nil {
		log.WithError(err).Error("Unable to load neighbor discovery iface name" +
			" for removing PERM neighbor entries")
		return
	}
	if len(linkNames) == 0 {
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

	for _, linkName := range linkNames {
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
			continue
		}

		successClean = n.NodeCleanNeighborsLink(l, migrateOnly)
	}
}

func storeNeighLink(dir string, names []string) error {
	configFileName := filepath.Join(dir, neighFileName)
	f, err := os.Create(configFileName)
	if err != nil {
		return fmt.Errorf("unable to create '%s': %w", configFileName, err)
	}
	defer f.Close()

	var nls []NeighLink
	for _, name := range names {
		nls = append(nls, NeighLink{Name: name})
	}
	err = json.NewEncoder(f).Encode(nls)
	if err != nil {
		return fmt.Errorf("unable to encode '%+v': %w", nls, err)
	}
	return nil
}

func loadNeighLink(dir string) ([]string, error) {
	configFileName := filepath.Join(dir, neighFileName)
	f, err := os.Open(configFileName)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("unable to open '%s': %w", configFileName, err)
	}
	defer f.Close()

	// Ensure backward compatibility
	var nl NeighLink
	if err = json.NewDecoder(f).Decode(&nl); err == nil {
		if len(nl.Name) > 0 {
			return []string{nl.Name}, nil
		}
	}

	var nls []NeighLink
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	if err := json.NewDecoder(f).Decode(&nls); err != nil {
		return nil, fmt.Errorf("unable to decode '%s': %w", configFileName, err)
	}
	var names []string
	for _, nl := range nls {
		names = append(names, nl.Name)
	}
	return names, nil
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

func deleteOldLocalRule(family int, rule route.Rule) error {
	var familyStr string

	// sanity check, nothing to do if the rule is the same
	if linux_defaults.RTProto == unix.RTPROT_UNSPEC {
		return nil
	}

	if family == netlink.FAMILY_V4 {
		familyStr = "IPv4"
	} else {
		familyStr = "IPv6"
	}

	localRules, err := route.ListRules(family, &rule)
	if err != nil {
		return fmt.Errorf("could not list local %s rules: %w", familyStr, err)
	}

	// we need to check for the old rule and make sure it's before the new one
	oldPos := -1
	found := false
	for pos, rule := range localRules {
		// mark the first unspec rule that matches
		if oldPos == -1 && rule.Protocol == unix.RTPROT_UNSPEC {
			oldPos = pos
		}

		if rule.Protocol == linux_defaults.RTProto {
			// mark it as found only if it's before the new one
			if oldPos != -1 {
				found = true
			}
			break
		}
	}

	if found == true {
		err := route.DeleteRule(family, rule)
		if err != nil {
			return fmt.Errorf("could not delete old %s local rule: %w", familyStr, err)
		}
		log.WithFields(logrus.Fields{"family": familyStr}).Info("Deleting old local lookup rule")
	}

	return nil
}

// NodeEnsureLocalIPRule checks if Cilium local lookup rule (usually 100)
// was installed and has proper protocol
func NodeEnsureLocalIPRule() error {
	// we have the Cilium local lookup rule only if the proxy rule is present
	if !option.Config.InstallIptRules || !option.Config.EnableL7Proxy {
		return nil
	}

	localRule := route.Rule{Priority: linux_defaults.RulePriorityLocalLookup, Table: unix.RT_TABLE_LOCAL, Mark: -1, Mask: -1, Protocol: linux_defaults.RTProto}
	oldRule := localRule
	oldRule.Protocol = unix.RTPROT_UNSPEC

	if option.Config.EnableIPv4 {
		err := route.ReplaceRule(localRule)
		if err != nil {
			return fmt.Errorf("could not replace IPv4 local rule: %w", err)
		}

		err = deleteOldLocalRule(netlink.FAMILY_V4, oldRule)
		if err != nil {
			return err
		}
	}

	if option.Config.EnableIPv6 {
		err := route.ReplaceRuleIPv6(localRule)
		if err != nil {
			return fmt.Errorf("could not replace IPv6 local rule: %w", err)
		}

		err = deleteOldLocalRule(netlink.FAMILY_V6, oldRule)
		if err != nil {
			return err
		}
	}

	return nil
}
