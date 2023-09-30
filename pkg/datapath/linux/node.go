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
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/cidr"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/counter"
	"github.com/cilium/cilium/pkg/datapath/link"
	"github.com/cilium/cilium/pkg/datapath/linux/ipsec"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/idpool"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/nodemap"
	"github.com/cilium/cilium/pkg/maps/tunnel"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/types"
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

type linuxNodeHandler struct {
	mutex                lock.RWMutex
	isInitialized        bool
	nodeConfig           datapath.LocalNodeConfiguration
	nodeAddressing       datapath.NodeAddressing
	datapathConfig       DatapathConfiguration
	nodes                map[nodeTypes.Identity]*nodeTypes.Node
	enableNeighDiscovery bool
	neighLock            lock.Mutex // protects neigh* fields below
	neighDiscoveryLinks  []netlink.Link
	neighNextHopByNode4  map[nodeTypes.Identity]map[string]string // val = (key=link, value=string(net.IP))
	neighNextHopByNode6  map[nodeTypes.Identity]map[string]string // val = (key=link, value=string(net.IP))
	// All three mappings below hold both IPv4 and IPv6 entries.
	neighNextHopRefCount   counter.StringCounter
	neighByNextHop         map[string]*netlink.Neigh // key = string(net.IP)
	neighLastPingByNextHop map[string]time.Time      // key = string(net.IP)

	nodeMap nodemap.Map
	// Pool of available IDs for nodes.
	nodeIDs idpool.IDPool
	// Node-scoped unique IDs for the nodes.
	nodeIDsByIPs map[string]uint16
	// reverse map of the above
	nodeIPsByIDs map[uint16]string

	ipsecMetricCollector prometheus.Collector
	ipsecMetricOnce      sync.Once

	prefixClusterMutatorFn func(node *types.Node) []cmtypes.PrefixClusterOpts
}

var (
	_ datapath.NodeHandler   = (*linuxNodeHandler)(nil)
	_ datapath.NodeIDHandler = (*linuxNodeHandler)(nil)
	_ datapath.NodeNeighbors = (*linuxNodeHandler)(nil)
)

// NewNodeHandler returns a new node handler to handle node events and
// implement the implications in the Linux datapath
func NewNodeHandler(datapathConfig DatapathConfiguration, nodeAddressing datapath.NodeAddressing, nodeMap nodemap.Map) *linuxNodeHandler {
	return &linuxNodeHandler{
		nodeAddressing:         nodeAddressing,
		datapathConfig:         datapathConfig,
		nodes:                  map[nodeTypes.Identity]*nodeTypes.Node{},
		neighNextHopByNode4:    map[nodeTypes.Identity]map[string]string{},
		neighNextHopByNode6:    map[nodeTypes.Identity]map[string]string{},
		neighNextHopRefCount:   counter.StringCounter{},
		neighByNextHop:         map[string]*netlink.Neigh{},
		neighLastPingByNextHop: map[string]time.Time{},
		nodeMap:                nodeMap,
		nodeIDs:                idpool.NewIDPool(minNodeID, maxNodeID),
		nodeIDsByIPs:           map[string]uint16{},
		nodeIPsByIDs:           map[uint16]string{},
		ipsecMetricCollector:   ipsec.NewXFRMCollector(),
		prefixClusterMutatorFn: func(node *nodeTypes.Node) []cmtypes.PrefixClusterOpts { return nil },
	}
}

func (l *linuxNodeHandler) Name() string {
	return "linux-node-datapath"
}

// updateTunnelMapping is called when a node update is received while running
// with encapsulation mode enabled. The CIDR and IP of both the old and new
// node are provided as context. The caller expects the tunnel mapping in the
// datapath to be updated.
func updateTunnelMapping(oldCIDR, newCIDR cmtypes.PrefixCluster, oldIP, newIP net.IP,
	firstAddition, encapEnabled bool, oldEncryptKey, newEncryptKey uint8) error {
	var errs error
	if !encapEnabled {
		// When the protocol family is disabled, the initial node addition will
		// trigger a deletion to clean up leftover entries. The deletion happens
		// in quiet mode as we don't know whether it exists or not
		if newCIDR.IsValid() && firstAddition {
			if err := deleteTunnelMapping(newCIDR, true); err != nil {
				errs = errors.Join(errs,
					fmt.Errorf("failed to delete tunnel mapping %q: %w", newCIDR, err))
			}
		}

		return errs
	}

	if cidrNodeMappingUpdateRequired(oldCIDR, newCIDR, oldIP, newIP, oldEncryptKey, newEncryptKey) {
		log.WithFields(logrus.Fields{
			logfields.IPAddr: newIP,
			"allocCIDR":      newCIDR,
		}).Debug("Updating tunnel map entry")

		if err := tunnel.TunnelMap().SetTunnelEndpoint(newEncryptKey, newCIDR.AddrCluster(), newIP); err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				"allocCIDR": newCIDR,
			}).Error("bpf: Unable to update in tunnel endpoint map")
			errs = errors.Join(errs,
				fmt.Errorf("failed to update tunnel endpoint map (prefix: %s, nodeIP: %s): %w", newCIDR.AddrCluster(), newIP, err))
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
			errs = errors.Join(errs,
				fmt.Errorf("failed to delete tunnel mapping (oldCIDR: %s, newIP: %s): %w", oldCIDR, newIP, err))
		}
	}
	return errs
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
			return fmt.Errorf("failed to delete tunnel endpoint map: %w", err)
		}
	} else {
		return tunnel.TunnelMap().SilentDeleteTunnelEndpoint(addrCluster)
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
		err = fmt.Errorf("unable to lookup route for node %s: %w", nodeIP, err)
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
			// In the current implementation, this often fails because updates are tried for both ip families
			// regardless if the Node has either ip types.
			// At the time of this change we are only interested in bubbling up errors without affecting execution flow.
			// Thus we are ignoring the error here for now.
			//
			// TODO(Tom): In the future we will want to avoid attempting to do the update if we know it will fail.
			if newIP == nil && errors.Is(err, unix.ERANGE) {
				return nil
			}
			return err
		}
	}
	if err := n.deleteAllDirectRoutes(removedCIDRs, oldIP); err != nil {
		return fmt.Errorf("failed to delete all direct routes: %w", err)
	}

	return nil
}

func (n *linuxNodeHandler) deleteAllDirectRoutes(CIDRs []*cidr.CIDR, nodeIP net.IP) error {
	var errs error
	for _, cidr := range CIDRs {
		if err := n.deleteDirectRoute(cidr, nodeIP); err != nil {
			errs = errors.Join(errs, err)
		}
	}
	return errs
}

func (n *linuxNodeHandler) deleteDirectRoute(CIDR *cidr.CIDR, nodeIP net.IP) error {
	if CIDR == nil {
		return nil
	}

	family := netlink.FAMILY_V4
	familyStr := "ip4"
	if CIDR.IP.To4() == nil {
		family = netlink.FAMILY_V6
		familyStr = "ip6"
	}

	filter := &netlink.Route{
		Dst:      CIDR.IPNet,
		Gw:       nodeIP,
		Protocol: linux_defaults.RTProto,
	}

	routes, err := netlink.RouteListFiltered(family, filter, netlink.RT_FILTER_DST|netlink.RT_FILTER_GW)
	if err != nil {
		log.WithError(err).Error("Unable to list direct routes")
		return fmt.Errorf("failed to list direct routes %s: %w", familyStr, err)
	}

	var errs error
	for _, rt := range routes {
		if err := netlink.RouteDel(&rt); err != nil {
			log.WithError(err).Warningf("Unable to delete direct node route %s", rt.String())
			errs = errors.Join(errs, fmt.Errorf("failed to delete direct route %q: %w", rt.String(), err))
		}
	}
	return errs
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
			return route.Route{}, fmt.Errorf("external IPv6 address unavailable")
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
	var errs error
	addedAuxRoutes, removedAuxRoutes := cidr.DiffCIDRLists(old, new)
	for _, prefix := range addedAuxRoutes {
		if prefix != nil {
			if err := n.updateNodeRoute(prefix, n.familyEnabled(prefix), isLocalNode); err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to add aux route %q: %w", prefix, err))
			}
		}
	}
	for _, prefix := range removedAuxRoutes {
		if rt, _ := n.lookupNodeRoute(prefix, isLocalNode); rt != nil {
			if err := n.deleteNodeRoute(prefix, isLocalNode); err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to remove aux route %q: %w", prefix, err))
			}
		}
	}
	return errs
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

func upsertIPsecLog(err error, spec string, loc, rem *net.IPNet, spi uint8) error {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.Reason: spec,
		"local-ip":       loc,
		"remote-ip":      rem,
		"spi":            spi,
	})
	if err != nil {
		scopedLog.WithError(err).Error("IPsec enable failed")
		return fmt.Errorf("failed to enable ipsec with %s using local IP %s, rem %s, spi %d: %w",
			spec,
			loc.String(),
			rem.String(),
			spi, err)
	} else {
		scopedLog.Debug("IPsec enable succeeded")
	}
	return nil
}

func (n *linuxNodeHandler) registerIpsecMetricOnce() {
	n.ipsecMetricOnce.Do(func() {
		if err := metrics.Register(n.ipsecMetricCollector); err != nil {
			log.WithError(err).Error("IPSec metrics registration failed. No metrics will be reported!")
		}
	})
}

func (n *linuxNodeHandler) enableSubnetIPsec(v4CIDR, v6CIDR []*net.IPNet) error {
	errs := n.replaceHostRules()
	for _, cidr := range v4CIDR {
		if !option.Config.EnableEndpointRoutes {
			if err := n.replaceNodeIPSecInRoute(cidr); err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to replace ipsec IN (%q): %w", cidr.IP, err))
			}
		}
		if err := n.replaceNodeIPSecOutRoute(cidr); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to replace ipsec OUT (%q): %w", cidr.IP, err))
		}
		if n.nodeConfig.EncryptNode {
			if err := n.replaceNodeExternalIPSecOutRoute(cidr); err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to replace external ipsec OUT (%q): %w", cidr.IP, err))
			}
		}
	}

	for _, cidr := range v6CIDR {
		if err := n.replaceNodeIPSecInRoute(cidr); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to replace ipsec IN (%q): %w", cidr.IP, err))
		}

		if err := n.replaceNodeIPSecOutRoute(cidr); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to replace ipsec OUT (%q): %w", cidr.IP, err))
		}
		if n.nodeConfig.EncryptNode {
			if err := n.replaceNodeExternalIPSecOutRoute(cidr); err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to replace external ipsec OUT (%q): %w", cidr.IP, err))
			}
		}
	}
	return errs
}

// encryptNode handles setting the IPsec state for node encryption (subnet
// encryption = disabled).
func (n *linuxNodeHandler) encryptNode(newNode *nodeTypes.Node) error {
	var errs error
	var spi uint8
	var err error

	if n.nodeConfig.EnableIPv4 {
		internalIPv4 := n.nodeAddressing.IPv4().PrimaryExternal()
		exactMask := net.IPv4Mask(255, 255, 255, 255)
		ipsecLocal := &net.IPNet{IP: internalIPv4, Mask: exactMask}
		if newNode.IsLocal() {
			wildcardIP := net.ParseIP(wildcardIPv4)
			ipsecIPv4Wildcard := &net.IPNet{IP: wildcardIP, Mask: net.IPv4Mask(0, 0, 0, 0)}
			errs = errors.Join(errs, n.replaceNodeIPSecInRoute(ipsecLocal))
			spi, err = ipsec.UpsertIPsecEndpoint(ipsecLocal, ipsecIPv4Wildcard, internalIPv4, wildcardIP, 0, ipsec.IPSecDirIn, false)
			errs = errors.Join(errs, upsertIPsecLog(err, "EncryptNode local IPv4", ipsecLocal, ipsecIPv4Wildcard, spi))
		} else {
			if remoteIPv4 := newNode.GetNodeIP(false); remoteIPv4 != nil {
				ipsecRemote := &net.IPNet{IP: remoteIPv4, Mask: exactMask}
				errs = errors.Join(errs, n.replaceNodeExternalIPSecOutRoute(ipsecRemote))
				spi, err = ipsec.UpsertIPsecEndpoint(ipsecLocal, ipsecRemote, internalIPv4, remoteIPv4, 0, ipsec.IPSecDirOutNode, false)
				errs = errors.Join(errs, upsertIPsecLog(err, "EncryptNode IPv4", ipsecLocal, ipsecRemote, spi))
			}
			remoteIPv4 := newNode.GetCiliumInternalIP(false)
			if remoteIPv4 != nil {
				mask := newNode.IPv4AllocCIDR.Mask
				ipsecRemoteRoute := &net.IPNet{IP: remoteIPv4.Mask(mask), Mask: mask}
				ipsecRemote := &net.IPNet{IP: remoteIPv4, Mask: mask}
				ipsecWildcard := &net.IPNet{IP: net.ParseIP(wildcardIPv4), Mask: net.IPv4Mask(0, 0, 0, 0)}

				errs = errors.Join(errs, n.replaceNodeExternalIPSecOutRoute(ipsecRemoteRoute))
				if remoteIPv4T := newNode.GetNodeIP(false); remoteIPv4T != nil {
					err = ipsec.UpsertIPsecEndpointPolicy(ipsecWildcard, ipsecRemote, internalIPv4, remoteIPv4T, 0, ipsec.IPSecDirOutNode)
				}
				errs = errors.Join(errs, upsertIPsecLog(err, "EncryptNode Cilium IPv4", ipsecWildcard, ipsecRemote, spi))
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
			errs = errors.Join(errs, n.replaceNodeIPSecInRoute(ipsecLocal))
			spi, err = ipsec.UpsertIPsecEndpoint(ipsecLocal, ipsecIPv6Wildcard, internalIPv6, wildcardIP, 0, ipsec.IPSecDirIn, false)
			errs = errors.Join(errs, upsertIPsecLog(err, "EncryptNode local IPv6", ipsecLocal, ipsecIPv6Wildcard, spi))
		} else {
			if remoteIPv6 := newNode.GetNodeIP(true); remoteIPv6 != nil {
				ipsecRemote := &net.IPNet{IP: remoteIPv6, Mask: exactMask}
				errs = errors.Join(errs, n.replaceNodeExternalIPSecOutRoute(ipsecRemote))
				spi, err = ipsec.UpsertIPsecEndpoint(ipsecLocal, ipsecRemote, internalIPv6, remoteIPv6, 0, ipsec.IPSecDirOut, false)
				errs = errors.Join(errs, upsertIPsecLog(err, "EncryptNode IPv6", ipsecLocal, ipsecRemote, spi))
			}
			remoteIPv6 := newNode.GetCiliumInternalIP(true)
			if remoteIPv6 != nil {
				mask := newNode.IPv6AllocCIDR.Mask
				ipsecRemoteRoute := &net.IPNet{IP: remoteIPv6.Mask(mask), Mask: mask}
				ipsecRemote := &net.IPNet{IP: remoteIPv6, Mask: mask}
				ipsecWildcard := &net.IPNet{IP: net.ParseIP(wildcardIPv6), Mask: net.CIDRMask(0, 0)}

				errs = errors.Join(n.replaceNodeExternalIPSecOutRoute(ipsecRemoteRoute))
				if remoteIPv6T := newNode.GetNodeIP(true); remoteIPv6T != nil {
					err = ipsec.UpsertIPsecEndpointPolicy(ipsecWildcard, ipsecRemote, internalIPv6, remoteIPv6T, 0, ipsec.IPSecDirOutNode)
				}
				errs = errors.Join(errs, upsertIPsecLog(err, "EncryptNode Cilium IPv6", ipsecWildcard, ipsecRemote, spi))
			}
		}
	}
	return errs
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

func (n *linuxNodeHandler) insertNeighborCommon(scopedLog *logrus.Entry, ctx context.Context, nextHop NextHop, link netlink.Link, refresh bool) {
	if refresh {
		if lastPing, found := n.neighLastPingByNextHop[nextHop.Name]; found &&
			time.Since(lastPing) < option.Config.ARPPingRefreshPeriod {
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

	nextHopIPv4, err := getNextHopIP(nextHopIPv4, link)
	if err != nil {
		scopedLog.WithError(err).Info("Unable to determine next hop address")
		return
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

	n.neighNextHopByNode4[newNode.Identity()][link.Attrs().Name] = nextHopStr
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

	nextHopIPv6, err := getNextHopIP(nextHopIPv6, link)
	if err != nil {
		scopedLog.WithError(err).Info("Unable to determine next hop address")
		return
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

	n.neighNextHopByNode6[newNode.Identity()][link.Attrs().Name] = nextHopStr
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
	var links []netlink.Link

	n.neighLock.Lock()
	if n.neighDiscoveryLinks == nil || len(n.neighDiscoveryLinks) == 0 {
		n.neighLock.Unlock()
		// Nothing to do - the discovery link was not set yet
		return
	}
	links = n.neighDiscoveryLinks
	n.neighLock.Unlock()

	if newNode.GetNodeIP(false).To4() != nil {
		for _, l := range links {
			n.insertNeighbor4(ctx, newNode, l, refresh)
		}
	}
	if newNode.GetNodeIP(true).To16() != nil {
		for _, l := range links {
			n.insertNeighbor6(ctx, newNode, l, refresh)
		}
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

func getLinkLocalIP(family int) (net.IP, error) {
	iface := getDefaultEncryptionInterface()
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return nil, err
	}
	addr, err := netlink.AddrList(link, family)
	if err != nil {
		return nil, err
	}
	return addr[0].IPNet.IP, nil
}

func getV4LinkLocalIP() (net.IP, error) {
	return getLinkLocalIP(netlink.FAMILY_V4)
}

func getV6LinkLocalIP() (net.IP, error) {
	return getLinkLocalIP(netlink.FAMILY_V6)
}

func (n *linuxNodeHandler) enableIPsec(newNode *nodeTypes.Node, nodeID uint16) error {
	var errs error
	if newNode.IsLocal() {
		if err := n.replaceHostRules(); err != nil {
			errs = fmt.Errorf("failed to replace host rules: %w", err)
		}
	}

	// In endpoint routes mode we use the stack to route packets after
	// the packet is decrypted so set skb->mark to zero from XFRM stack
	// to avoid confusion in netfilters and conntrack that may be using
	// the mark fields. This uses XFRM_OUTPUT_MARK added in 4.14 kernels.
	zeroMark := option.Config.EnableEndpointRoutes

	return errors.Join(
		errs,
		n.enableIPsecIPv4(newNode, nodeID, zeroMark),
		n.enableIPsecIPv6(newNode, nodeID, zeroMark),
	)
}

func (n *linuxNodeHandler) enableIPsecIPv4(newNode *nodeTypes.Node, nodeID uint16, zeroMark bool) error {
	var spi uint8
	var errs error

	if !n.nodeConfig.EnableIPv4 || (newNode.IPv4AllocCIDR == nil && !n.subnetEncryption()) {
		return nil
	}

	wildcardIP := net.ParseIP(wildcardIPv4)
	wildcardCIDR := &net.IPNet{IP: wildcardIP, Mask: net.IPv4Mask(0, 0, 0, 0)}

	err := ipsec.IPsecDefaultDropPolicy(false)
	errs = errors.Join(errs, upsertIPsecLog(err, "default-drop IPv4", wildcardCIDR, wildcardCIDR, spi))

	if newNode.IsLocal() {
		localIP := newNode.GetCiliumInternalIP(false)
		if localIP == nil {
			return errs
		}

		if n.subnetEncryption() {
			// FIXME: Remove the following four lines in Cilium v1.16
			if localCIDR := n.nodeAddressing.IPv4().AllocationCIDR(); localCIDR != nil {
				// This removes a bogus route that Cilium installed prior to v1.15
				_ = route.Delete(n.createNodeIPSecInRoute(localCIDR.IPNet))
			}

			localNodeInternalIP, err := getV4LinkLocalIP()
			if err != nil {
				log.WithError(err).Error("Failed to get local IPv4 for IPsec configuration")
				errs = errors.Join(errs, fmt.Errorf("failed to get local ipv4 for ipsec link: %w", err))
			}

			for _, cidr := range n.nodeConfig.IPv4PodSubnets {
				/* Insert wildcard policy rules for traffic skipping back through host */
				if err = ipsec.IpSecReplacePolicyFwd(cidr, localIP); err != nil {
					log.WithError(err).Warning("egress unable to replace policy fwd:")
				}

				spi, err := ipsec.UpsertIPsecEndpoint(wildcardCIDR, cidr, localIP, wildcardIP, 0, ipsec.IPSecDirIn, zeroMark)
				errs = errors.Join(errs, upsertIPsecLog(err, "in CiliumInternalIPv4", wildcardCIDR, cidr, spi))

				spi, err = ipsec.UpsertIPsecEndpoint(wildcardCIDR, cidr, localNodeInternalIP, wildcardIP, 0, ipsec.IPSecDirIn, zeroMark)
				errs = errors.Join(errs, upsertIPsecLog(err, "in NodeInternalIPv4", wildcardCIDR, cidr, spi))
			}
		} else {
			/* Insert wildcard policy rules for traffic skipping back through host */
			if err = ipsec.IpSecReplacePolicyFwd(wildcardCIDR, localIP); err != nil {
				log.WithError(err).Warning("egress unable to replace policy fwd:")
			}

			localCIDR := n.nodeAddressing.IPv4().AllocationCIDR().IPNet
			errs = errors.Join(errs, n.replaceNodeIPSecInRoute(localCIDR))
			spi, err = ipsec.UpsertIPsecEndpoint(localCIDR, wildcardCIDR, localIP, wildcardIP, 0, ipsec.IPSecDirIn, false)
			errs = errors.Join(errs, upsertIPsecLog(err, "in IPv4", localCIDR, wildcardCIDR, spi))
		}
	} else {
		remoteIP := newNode.GetCiliumInternalIP(false)
		if remoteIP == nil {
			return errs
		}

		localIP := n.nodeAddressing.IPv4().Router()

		if n.subnetEncryption() {
			// Check if we should use the NodeInternalIPs instead of the
			// CiliumInternalIPs for the IPsec encapsulation.
			if !option.Config.UseCiliumInternalIPForIPsec {
				localIP, err = getV4LinkLocalIP()
				if err != nil {
					log.WithError(err).Error("Failed to get local IPv4 for IPsec configuration")
				}
				remoteIP = newNode.GetNodeIP(false)
			}

			for _, cidr := range n.nodeConfig.IPv4PodSubnets {
				spi, err = ipsec.UpsertIPsecEndpoint(wildcardCIDR, cidr, localIP, remoteIP, nodeID, ipsec.IPSecDirOut, zeroMark)
				errs = errors.Join(errs, upsertIPsecLog(err, "out IPv4", wildcardCIDR, cidr, spi))
			}
		} else {
			remoteCIDR := newNode.IPv4AllocCIDR.IPNet
			n.replaceNodeIPSecOutRoute(remoteCIDR)
			spi, err = ipsec.UpsertIPsecEndpoint(wildcardCIDR, remoteCIDR, localIP, remoteIP, nodeID, ipsec.IPSecDirOut, false)
			errs = errors.Join(errs, upsertIPsecLog(err, "out IPv4", wildcardCIDR, remoteCIDR, spi))
		}
	}
	return errs
}

func (n *linuxNodeHandler) enableIPsecIPv6(newNode *nodeTypes.Node, nodeID uint16, zeroMark bool) error {
	var errs error
	var spi uint8

	if !n.nodeConfig.EnableIPv6 || (newNode.IPv6AllocCIDR == nil && !n.subnetEncryption()) {
		return nil
	}

	wildcardIP := net.ParseIP(wildcardIPv6)
	wildcardCIDR := &net.IPNet{IP: wildcardIP, Mask: net.CIDRMask(0, 128)}

	err := ipsec.IPsecDefaultDropPolicy(true)
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to create default drop policy IPv6: %w", err))
	}
	errs = errors.Join(errs, upsertIPsecLog(err, "default-drop IPv6", wildcardCIDR, wildcardCIDR, spi))

	if newNode.IsLocal() {
		localIP := newNode.GetCiliumInternalIP(true)
		if localIP == nil {
			return errs
		}

		if n.subnetEncryption() {
			// FIXME: Remove the following four lines in Cilium v1.16
			if localCIDR := n.nodeAddressing.IPv6().AllocationCIDR(); localCIDR != nil {
				// This removes a bogus route that Cilium installed prior to v1.15
				_ = route.Delete(n.createNodeIPSecInRoute(localCIDR.IPNet))
			}

			localNodeInternalIP, err := getV6LinkLocalIP()
			if err != nil {
				log.WithError(err).Error("Failed to get local IPv6 for IPsec configuration")
				errs = errors.Join(errs, fmt.Errorf("failed to get local ipv6 for ipsec link: %w", err))
			}

			for _, cidr := range n.nodeConfig.IPv6PodSubnets {
				spi, err := ipsec.UpsertIPsecEndpoint(wildcardCIDR, cidr, localIP, wildcardIP, 0, ipsec.IPSecDirIn, zeroMark)
				errs = errors.Join(errs, upsertIPsecLog(err, "in CiliumInternalIPv6", wildcardCIDR, cidr, spi))

				spi, err = ipsec.UpsertIPsecEndpoint(wildcardCIDR, cidr, localNodeInternalIP, wildcardIP, 0, ipsec.IPSecDirIn, zeroMark)
				errs = errors.Join(errs, upsertIPsecLog(err, "in NodeInternalIPv6", wildcardCIDR, cidr, spi))
			}
		} else {
			localCIDR := n.nodeAddressing.IPv6().AllocationCIDR().IPNet
			errs = errors.Join(errs, n.replaceNodeIPSecInRoute(localCIDR))
			spi, err = ipsec.UpsertIPsecEndpoint(localCIDR, wildcardCIDR, localIP, wildcardIP, 0, ipsec.IPSecDirIn, false)
			errs = errors.Join(errs, upsertIPsecLog(err, "in IPv6", localCIDR, wildcardCIDR, spi))
		}
	} else {
		remoteIP := newNode.GetCiliumInternalIP(true)
		if remoteIP == nil {
			return errs
		}

		localIP := n.nodeAddressing.IPv6().Router()

		if n.subnetEncryption() {
			// Check if we should use the NodeInternalIPs instead of the
			// CiliumInternalIPs for the IPsec encapsulation.
			if !option.Config.UseCiliumInternalIPForIPsec {
				localIP, err = getV6LinkLocalIP()
				if err != nil {
					log.WithError(err).Error("Failed to get local IPv6 for IPsec configuration")
					errs = errors.Join(errs, fmt.Errorf("failed to get local ipv6 for ipsec link: %w", err))
				}
				remoteIP = newNode.GetNodeIP(true)
			}

			for _, cidr := range n.nodeConfig.IPv6PodSubnets {
				spi, err = ipsec.UpsertIPsecEndpoint(wildcardCIDR, cidr, localIP, remoteIP, nodeID, ipsec.IPSecDirOut, zeroMark)
				errs = errors.Join(errs, upsertIPsecLog(err, "out IPv6", wildcardCIDR, cidr, spi))
			}
		} else {
			remoteCIDR := newNode.IPv6AllocCIDR.IPNet
			n.replaceNodeIPSecOutRoute(remoteCIDR)
			spi, err := ipsec.UpsertIPsecEndpoint(wildcardCIDR, remoteCIDR, localIP, remoteIP, nodeID, ipsec.IPSecDirOut, false)
			errs = errors.Join(errs, upsertIPsecLog(err, "out IPv6", wildcardCIDR, remoteCIDR, spi))
		}
	}
	return errs
}

func (n *linuxNodeHandler) subnetEncryption() bool {
	return len(n.nodeConfig.IPv4PodSubnets) > 0 || len(n.nodeConfig.IPv6PodSubnets) > 0
}

// Must be called with linuxNodeHandler.mutex held.
func (n *linuxNodeHandler) nodeUpdate(oldNode, newNode *nodeTypes.Node, firstAddition bool) error {
	var (
		// Don't stop executing the function if we get an error. Instead we
		// log and aggregate errors in accumulator.
		errs error

		oldAllIP4AllocCidrs, oldAllIP6AllocCidrs []*cidr.CIDR
		newAllIP4AllocCidrs                      = newNode.GetIPv4AllocCIDRs()
		newAllIP6AllocCidrs                      = newNode.GetIPv6AllocCIDRs()
		oldIP4, oldIP6                           net.IP
		newIP4                                   = newNode.GetNodeIP(false)
		newIP6                                   = newNode.GetNodeIP(true)
		oldKey, newKey                           uint8
		isLocalNode                              = false
	)
	remoteNodeID, err := n.allocateIDForNode(newNode)
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to allocate ID for node %s: %w", newNode.Name, err))
	}

	if oldNode != nil {
		oldAllIP4AllocCidrs = oldNode.GetIPv4AllocCIDRs()
		oldAllIP6AllocCidrs = oldNode.GetIPv6AllocCIDRs()
		oldIP4 = oldNode.GetNodeIP(false)
		oldIP6 = oldNode.GetNodeIP(true)
		oldKey = oldNode.EncryptionKey

		n.diffAndUnmapNodeIPs(oldNode.IPAddresses, newNode.IPAddresses)
	}

	if n.nodeConfig.EnableIPSec && !n.nodeConfig.EncryptNode {
		errs = errors.Join(errs, n.enableIPsec(newNode, remoteNodeID))
		newKey = newNode.EncryptionKey
	}

	if n.enableNeighDiscovery && !newNode.IsLocal() {
		// Running insertNeighbor in a separate goroutine relies on the following
		// assumptions:
		// 1. newNode is accessed only by reads.
		// 2. It is safe to invoke insertNeighbor for the same node.
		//
		// Because neighbor inserts is not synced, we do not currently
		// collect/ bubble up errors.
		// Instead we just rely on logging errors as they come up in the
		// neighbor update procedure.
		//
		// In v1.15, we will have the neighbor sync component report its own
		// health via stored errors.
		go n.insertNeighbor(context.Background(), newNode, false)
	}

	if n.nodeConfig.EnableIPSec && n.nodeConfig.EncryptNode && !n.subnetEncryption() {
		if err := n.encryptNode(newNode); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to enable node encryption: %w", err))
		}
	}

	// Local node update
	if newNode.IsLocal() {
		isLocalNode = true
		if n.nodeConfig.EnableLocalNodeRoute {
			if err := n.updateOrRemoveNodeRoutes(oldAllIP4AllocCidrs, newAllIP4AllocCidrs, isLocalNode); err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to enable local node route: update ipv4 routes: %w", err))
			}
			if err := n.updateOrRemoveNodeRoutes(oldAllIP6AllocCidrs, newAllIP6AllocCidrs, isLocalNode); err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to enable local node route: update ipv6 routes: %w", err))
			}
		}
		if n.subnetEncryption() {
			// Enables subnet IPSec by upserting node host routing table IPSec routing
			if err := n.enableSubnetIPsec(n.nodeConfig.IPv4PodSubnets, n.nodeConfig.IPv6PodSubnets); err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to enable subnet encryption: %w", err))
			}
		}
		if firstAddition && n.nodeConfig.EnableIPSec {
			n.registerIpsecMetricOnce()
		}
		return errs
	}

	if n.nodeConfig.EnableAutoDirectRouting {
		if err := n.updateDirectRoutes(oldAllIP4AllocCidrs, newAllIP4AllocCidrs, oldIP4, newIP4, firstAddition, n.nodeConfig.EnableIPv4); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to enable direct routes for ipv4: %w", err))
		}
		if err := n.updateDirectRoutes(oldAllIP6AllocCidrs, newAllIP6AllocCidrs, oldIP6, newIP6, firstAddition, n.nodeConfig.EnableIPv6); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to enable direct routes for ipv6: %w", err))
		}
		return errs
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
			oldPrefixCluster4 = cmtypes.PrefixClusterFromCIDR(oldNode.IPv4AllocCIDR, n.prefixClusterMutatorFn(oldNode)...)
			oldPrefixCluster6 = cmtypes.PrefixClusterFromCIDR(oldNode.IPv6AllocCIDR, n.prefixClusterMutatorFn(oldNode)...)
		}

		if newNode != nil {
			newPrefixCluster4 = cmtypes.PrefixClusterFromCIDR(newNode.IPv4AllocCIDR, n.prefixClusterMutatorFn(newNode)...)
			newPrefixCluster6 = cmtypes.PrefixClusterFromCIDR(newNode.IPv6AllocCIDR, n.prefixClusterMutatorFn(newNode)...)
		}

		// Update the tunnel mapping of the node. In case the
		// node has changed its CIDR range, a new entry in the
		// map is created and the old entry is removed.
		errs = errors.Join(errs, updateTunnelMapping(oldPrefixCluster4, newPrefixCluster4, oldIP4, newIP4, firstAddition, n.nodeConfig.EnableIPv4, oldKey, newKey))
		// Not a typo, the IPv4 host IP is used to build the IPv6 overlay
		errs = errors.Join(errs, updateTunnelMapping(oldPrefixCluster6, newPrefixCluster6, oldIP4, newIP4, firstAddition, n.nodeConfig.EnableIPv6, oldKey, newKey))

		if !n.nodeConfig.UseSingleClusterRoute {
			if err := n.updateOrRemoveNodeRoutes(oldAllIP4AllocCidrs, newAllIP4AllocCidrs, isLocalNode); err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to enable encapsulation: single cluster routes: ipv4: %w", err))
			}
			if err := n.updateOrRemoveNodeRoutes(oldAllIP6AllocCidrs, newAllIP6AllocCidrs, isLocalNode); err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to enable encapsulation: single cluster routes: ipv6: %w", err))
			}
		}

		return errs
	} else if firstAddition {
		for _, ipv4AllocCIDR := range newAllIP4AllocCidrs {
			if rt, _ := n.lookupNodeRoute(ipv4AllocCIDR, isLocalNode); rt != nil {
				if err := n.deleteNodeRoute(ipv4AllocCIDR, isLocalNode); err != nil {
					errs = errors.Join(errs, fmt.Errorf("failed to apply initial sync (no encapsulation): delete ipv4 route: %w", err))
				}
			}
		}
		for _, ipv6AllocCIDR := range newAllIP6AllocCidrs {
			if rt, _ := n.lookupNodeRoute(ipv6AllocCIDR, isLocalNode); rt != nil {
				if err := n.deleteNodeRoute(ipv6AllocCIDR, isLocalNode); err != nil {
					errs = errors.Join(errs, fmt.Errorf("failed to apply initial sync (no encapsulation): delete ipv6 route: %w", err))
				}
			}
		}
	}

	return errs
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

	var errs error
	if n.nodeConfig.EnableAutoDirectRouting {
		if err := n.deleteDirectRoute(oldNode.IPv4AllocCIDR, oldIP4); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to remove old direct routing: deleting old routes %w", err))
		}
		if err := n.deleteDirectRoute(oldNode.IPv6AllocCIDR, oldIP6); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to remove old direct routing: deleting old routes %w", err))
		}
	}

	if n.nodeConfig.EnableEncapsulation {
		oldPrefix4 := cmtypes.PrefixClusterFromCIDR(oldNode.IPv4AllocCIDR, n.prefixClusterMutatorFn(oldNode)...)
		oldPrefix6 := cmtypes.PrefixClusterFromCIDR(oldNode.IPv6AllocCIDR, n.prefixClusterMutatorFn(oldNode)...)
		if err := deleteTunnelMapping(oldPrefix4, false); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to remove old encapsulation config: deleting tunnel mapping for ipv4: %w", err))
		}
		if err := deleteTunnelMapping(oldPrefix6, false); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to remove old encapsulation config: deleting tunnel mapping for ipv6: %w", err))
		}

		if !n.nodeConfig.UseSingleClusterRoute {
			if err := n.deleteNodeRoute(oldNode.IPv4AllocCIDR, false); err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to remove old encapsulation config: deleting old single cluster node route for ipv4: %w", err))
			}
			if err := n.deleteNodeRoute(oldNode.IPv6AllocCIDR, false); err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to remove old encapsulation config: deleting old single cluster node route for ipv6: %w", err))
			}
		}
	}

	if n.enableNeighDiscovery {
		go n.deleteNeighbor(oldNode)
	}

	if n.nodeConfig.EnableIPSec {
		if err := n.deleteIPsec(oldNode); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to delete old ipsec config: %w", err))
		}
	}

	if err := n.deallocateIDForNode(oldNode); err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to deallocate old node ID: %w", err))
	}

	return errs
}

func (n *linuxNodeHandler) updateOrRemoveClusterRoute(addressing datapath.NodeAddressingFamily, addressFamilyEnabled bool) error {
	allocCIDR := addressing.AllocationCIDR()
	if addressFamilyEnabled {
		return n.updateNodeRoute(allocCIDR, addressFamilyEnabled, false)
	}
	if rt, _ := n.lookupNodeRoute(allocCIDR, false); rt != nil {
		return n.deleteNodeRoute(allocCIDR, false)
	}

	return nil
}

func (n *linuxNodeHandler) replaceHostRules() error {
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
		Protocol: linux_defaults.RTProto,
	}

	rule.Mark = linux_defaults.RouteMarkDecrypt
	if err := route.DeleteRule(netlink.FAMILY_V4, rule); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("delete previous IPv4 decrypt rule failed: %w", err)
		}
	}

	rule.Mark = linux_defaults.RouteMarkEncrypt
	if err := route.DeleteRule(netlink.FAMILY_V4, rule); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("delete previousa IPv4 encrypt rule failed: %w", err)
		}
	}

	if err := route.DeleteRouteTable(linux_defaults.RouteTableIPSec, netlink.FAMILY_V4); err != nil {
		log.WithError(err).Warn("Deletion of IPSec routes failed")
	}

	rule.Mark = linux_defaults.RouteMarkDecrypt
	if err := route.DeleteRule(netlink.FAMILY_V6, rule); err != nil {
		if !os.IsNotExist(err) && !errors.Is(err, unix.EAFNOSUPPORT) {
			return fmt.Errorf("delete previous IPv6 decrypt rule failed: %w", err)
		}
	}

	rule.Mark = linux_defaults.RouteMarkEncrypt
	if err := route.DeleteRule(netlink.FAMILY_V6, rule); err != nil {
		if !os.IsNotExist(err) && !errors.Is(err, unix.EAFNOSUPPORT) {
			return fmt.Errorf("delete previous IPv6 encrypt rule failed: %w", err)
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

// replaceNodeIPSecOutRoute replace the out IPSec route in the host routing
// table with the new route. If no route exists the route is installed on the
// host. The caller must ensure that the CIDR passed in must be non-nil.
func (n *linuxNodeHandler) replaceNodeIPSecOutRoute(ip *net.IPNet) error {
	if ip.IP.To4() != nil {
		if !n.nodeConfig.EnableIPv4 {
			return nil
		}
	} else {
		if !n.nodeConfig.EnableIPv6 {
			return nil
		}
	}

	if err := route.Upsert(n.createNodeIPSecOutRoute(ip)); err != nil {
		log.WithError(err).WithField(logfields.CIDR, ip).Error("Unable to replace the IPSec route OUT the host routing table")
		return err
	}
	return nil
}

// replaceNodeExternalIPSecOutRoute replace the out IPSec route in the host
// routing table with the new route. If no route exists the route is installed
// on the host. The caller must ensure that the CIDR passed in must be non-nil.
func (n *linuxNodeHandler) replaceNodeExternalIPSecOutRoute(ip *net.IPNet) error {
	var errs error
	if ip.IP.To4() != nil {
		if !n.nodeConfig.EnableIPv4 {
			return nil
		}
	} else {
		if !n.nodeConfig.EnableIPv6 {
			return nil
		}
	}

	if err := route.Upsert(n.createNodeExternalIPSecOutRoute(ip, true)); err != nil {
		log.WithError(err).WithField(logfields.CIDR, ip).Error("Unable to replace the IPSec route OUT the default routing table")
		errs = errors.Join(errs, fmt.Errorf("failed to replace external ipsec routes: ipsec default route OUT: %w", err))
	}
	if err := route.Upsert(n.createNodeExternalIPSecOutRoute(ip, false)); err != nil {
		log.WithError(err).WithField(logfields.CIDR, ip).Error("Unable to replace the IPSec route OUT the host routing table")
		errs = errors.Join(errs, fmt.Errorf("failed to replace external ipsec routes: replace ipsec host route OUT: %w", err))
	}
	return errs
}

// The caller must ensure that the CIDR passed in must be non-nil.
func (n *linuxNodeHandler) deleteNodeIPSecOutRoute(ip *net.IPNet) error {
	if ip.IP.To4() != nil {
		if !n.nodeConfig.EnableIPv4 {
			return nil
		}
	} else {
		if !n.nodeConfig.EnableIPv6 {
			return nil
		}
	}

	if err := route.Delete(n.createNodeIPSecOutRoute(ip)); err != nil {
		log.WithError(err).WithField(logfields.CIDR, ip).Error("Unable to delete the IPsec route OUT from the host routing table")
		return fmt.Errorf("failed to delete ipsec host route out: %w", err)
	}
	return nil
}

// The caller must ensure that the CIDR passed in must be non-nil.
func (n *linuxNodeHandler) deleteNodeExternalIPSecOutRoute(ip *net.IPNet) error {
	var errs error
	if ip.IP.To4() != nil {
		if !n.nodeConfig.EnableIPv4 {
			return nil
		}
	} else {
		if !n.nodeConfig.EnableIPv6 {
			return nil
		}
	}

	if err := route.Delete(n.createNodeExternalIPSecOutRoute(ip, true)); err != nil {
		log.WithError(err).WithField(logfields.CIDR, ip).Error("Unable to delete the IPsec route External OUT from the ipsec routing table")
		errs = errors.Join(errs, fmt.Errorf("failed to delete ipsec route out: %w", err))
	}

	if err := route.Delete(n.createNodeExternalIPSecOutRoute(ip, false)); err != nil {
		log.WithError(err).WithField(logfields.CIDR, ip).Error("Unable to delete the IPsec route External OUT from the host routing table")
		errs = errors.Join(errs, fmt.Errorf("failed to delete ipsec host route out: %w", err))
	}
	return errs
}

// replaceNodeIPSecoInRoute replace the in IPSec routes in the host routing
// table with the new route. If no route exists the route is installed on the
// host. The caller must ensure that the CIDR passed in must be non-nil.
func (n *linuxNodeHandler) replaceNodeIPSecInRoute(ip *net.IPNet) error {
	if ip.IP.To4() != nil {
		if !n.nodeConfig.EnableIPv4 {
			return nil
		}
	} else {
		if !n.nodeConfig.EnableIPv6 {
			return nil
		}
	}

	if err := route.Upsert(n.createNodeIPSecInRoute(ip)); err != nil {
		log.WithError(err).WithField(logfields.CIDR, ip).Error("Unable to replace the IPSec route IN the host routing table")
		return fmt.Errorf("failed to replace ipsec host route IN: %w", err)
	}
	return nil
}

func (n *linuxNodeHandler) deleteIPsec(oldNode *nodeTypes.Node) error {
	var errs error
	scopedLog := log.WithField(logfields.NodeName, oldNode.Name)
	scopedLog.Debugf("Removing IPsec configuration for node")

	nodeID := n.getNodeIDForNode(oldNode)
	if nodeID == 0 {
		scopedLog.Warning("No node ID found for node.")
	} else {
		errs = errors.Join(errs, ipsec.DeleteIPsecEndpoint(nodeID))
	}

	if n.nodeConfig.EnableIPv4 && oldNode.IPv4AllocCIDR != nil {
		old4RouteNet := &net.IPNet{IP: oldNode.IPv4AllocCIDR.IP, Mask: oldNode.IPv4AllocCIDR.Mask}
		// This is only needed in IPAM modes where we install one route per
		// remote pod CIDR.
		if !n.subnetEncryption() {
			errs = errors.Join(errs, n.deleteNodeIPSecOutRoute(old4RouteNet))
		}
		if n.nodeConfig.EncryptNode {
			if remoteIPv4 := oldNode.GetNodeIP(false); remoteIPv4 != nil {
				exactMask := net.IPv4Mask(255, 255, 255, 255)
				ipsecRemote := &net.IPNet{IP: remoteIPv4, Mask: exactMask}
				errs = errors.Join(errs, n.deleteNodeExternalIPSecOutRoute(ipsecRemote))
			}
		}
	}

	if n.nodeConfig.EnableIPv6 && oldNode.IPv6AllocCIDR != nil {
		old6RouteNet := &net.IPNet{IP: oldNode.IPv6AllocCIDR.IP, Mask: oldNode.IPv6AllocCIDR.Mask}
		// See IPv4 case above.
		if !n.subnetEncryption() {
			n.deleteNodeIPSecOutRoute(old6RouteNet)
		}
		if n.nodeConfig.EncryptNode {
			if remoteIPv6 := oldNode.GetNodeIP(true); remoteIPv6 != nil {
				exactMask := net.CIDRMask(128, 128)
				ipsecRemote := &net.IPNet{IP: remoteIPv6, Mask: exactMask}
				errs = errors.Join(errs, n.deleteNodeExternalIPSecOutRoute(ipsecRemote))
			}
		}
	}
	return errs
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

	if err := n.updateOrRemoveNodeRoutes(prevConfig.AuxiliaryPrefixes, newConfig.AuxiliaryPrefixes, true); err != nil {
		return fmt.Errorf("failed to update or remove node routes: %w", err)
	}

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
		if err := ipsec.DeleteXfrm(); err != nil {
			return fmt.Errorf("failed to delete xfrm policies on node configuration changed: %w", err)
		}
	}

	var errs error
	if newConfig.UseSingleClusterRoute {
		if err := n.updateOrRemoveClusterRoute(n.nodeAddressing.IPv4(), newConfig.EnableIPv4); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to update or remove IPv4 cluster route: %w", err))
		}
		if err := n.updateOrRemoveClusterRoute(n.nodeAddressing.IPv6(), newConfig.EnableIPv6); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to update or remove IPv6 cluster route: %w", err))
		}
	} else if prevConfig.UseSingleClusterRoute {
		// single cluster route has been disabled, remove route
		if err := n.deleteNodeRoute(n.nodeAddressing.IPv4().AllocationCIDR(), false); err != nil {
			errs = errors.Join(errs, err)
		}
		if err := n.deleteNodeRoute(n.nodeAddressing.IPv6().AllocationCIDR(), false); err != nil {
			errs = errors.Join(errs, err)
		}
	}

	if !n.isInitialized {
		n.isInitialized = true
		if !n.nodeConfig.UseSingleClusterRoute {
			for _, unlinkedNode := range n.nodes {
				if err := n.nodeUpdate(nil, unlinkedNode, true); err != nil {
					errs = errors.Join(errs, err)
				}
			}
		}
	}

	return errs
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

// AllNodeValidateImplementation is called to validate the implementation of the
// node in the datapath for all existing nodes
func (n *linuxNodeHandler) AllNodeValidateImplementation() {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	var errs error
	for _, updateNode := range n.nodes {
		if err := n.nodeUpdate(nil, updateNode, false); err != nil {
			errs = errors.Join(errs, err)
		}
	}
	if errs != nil {
		log.WithError(errs).Warn("Node update failed during datapath node validation")
	}
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

// NodeEnsureLocalRoutingRule moves the kernel's default '0: from all lookup
// local' ip rule up to priority 100 to create space for Cilium to install rules
// with a lower pref (meaning a higher priority).
//
// Cilium's 'new' rule is always installed before removing the default one with
// pref 0 to avoid breaking local packet delivery.
func NodeEnsureLocalRoutingRule() error {
	// Equivalent of 'ip rule add from all lookup local pref 100 proto 2'.
	r := route.Rule{
		Table:    unix.RT_TABLE_LOCAL,
		Priority: linux_defaults.RulePriorityLocalLookup,
		Protocol: linux_defaults.RTProto,
		Mark:     -1,
		Mask:     -1,
	}

	if option.Config.EnableIPv4 {
		if err := route.ReplaceRule(r); err != nil {
			return fmt.Errorf("replace local ipv4 rule: %w", err)
		}

		if err := deleteDefaultLocalRule(netlink.FAMILY_V4); err != nil {
			return fmt.Errorf("remove default local ipv4 rule: %w", err)
		}
	}

	if option.Config.EnableIPv6 {
		if err := route.ReplaceRuleIPv6(r); err != nil {
			return fmt.Errorf("replace local ipv6 rule: %w", err)
		}

		if err := deleteDefaultLocalRule(netlink.FAMILY_V6); err != nil {
			return fmt.Errorf("remove default local ipv6 rule: %w", err)
		}
	}

	return nil
}

// deleteDefaultLocalRule removes a rule with pref 0 pointing to routing table
// 255 (local). Returns nil if the rule is not present.
func deleteDefaultLocalRule(family int) error {
	rule := route.Rule{
		Table:    unix.RT_TABLE_LOCAL,
		Priority: 0,
	}

	err := route.DeleteRule(family, rule)
	if errors.Is(err, syscall.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("delete default local rule: %w", err)
	}

	return nil
}

func (n *linuxNodeHandler) SetPrefixClusterMutatorFn(mutator func(*nodeTypes.Node) []cmtypes.PrefixClusterOpts) {
	n.prefixClusterMutatorFn = mutator
}
