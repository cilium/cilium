// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/cidr"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/counter"
	"github.com/cilium/cilium/pkg/datapath/link"
	"github.com/cilium/cilium/pkg/datapath/linux/ipsec"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	dpTunnel "github.com/cilium/cilium/pkg/datapath/tunnel"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/idpool"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/nodemap"
	"github.com/cilium/cilium/pkg/maps/tunnel"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/manager"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
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
	log *slog.Logger

	mutex                lock.RWMutex
	isInitialized        bool
	nodeConfig           datapath.LocalNodeConfiguration
	datapathConfig       DatapathConfiguration
	nodes                map[nodeTypes.Identity]*nodeTypes.Node
	enableNeighDiscovery bool
	neighLock            lock.Mutex // protects neigh* fields below
	neighDiscoveryLinks  []netlink.Link
	neighNextHopByNode4  map[nodeTypes.Identity]map[string]string // val = (key=link, value=string(net.IP))
	neighNextHopByNode6  map[nodeTypes.Identity]map[string]string // val = (key=link, value=string(net.IP))
	ipsecUpdateNeeded    map[nodeTypes.Identity]bool
	// All three mappings below hold both IPv4 and IPv6 entries.
	neighNextHopRefCount   counter.Counter[string]
	neighByNextHop         map[string]*netlink.Neigh // key = string(net.IP)
	neighLastPingByNextHop map[string]time.Time      // key = string(net.IP)

	nodeMap nodemap.MapV2
	// Pool of available IDs for nodes.
	nodeIDs *idpool.IDPool
	// Node-scoped unique IDs for the nodes.
	nodeIDsByIPs map[string]uint16
	// reverse map of the above
	nodeIPsByIDs map[uint16]sets.Set[string]

	ipsecMetricCollector prometheus.Collector
	ipsecMetricOnce      sync.Once

	prefixClusterMutatorFn func(node *nodeTypes.Node) []cmtypes.PrefixClusterOpts
	enableEncapsulation    func(node *nodeTypes.Node) bool
	nodeNeighborQueue      datapath.NodeNeighborEnqueuer
}

var (
	_ datapath.NodeHandler   = (*linuxNodeHandler)(nil)
	_ datapath.NodeIDHandler = (*linuxNodeHandler)(nil)
	_ datapath.NodeNeighbors = (*linuxNodeHandler)(nil)
)

// NewNodeHandler returns a new node handler to handle node events and
// implement the implications in the Linux datapath
func NewNodeHandler(
	log *slog.Logger,
	tunnelConfig dpTunnel.Config,
	nodeMap nodemap.MapV2,
	nodeManager manager.NodeManager,
) (datapath.NodeHandler, datapath.NodeIDHandler, datapath.NodeNeighbors) {
	datapathConfig := DatapathConfiguration{
		HostDevice:   defaults.HostDevice,
		TunnelDevice: tunnelConfig.DeviceName(),
	}

	handler := newNodeHandler(log, datapathConfig, nodeMap, nodeManager)
	return handler, handler, handler
}

// newNodeHandler returns a new node handler to handle node events and
// implement the implications in the Linux datapath
func newNodeHandler(
	log *slog.Logger,
	datapathConfig DatapathConfiguration,
	nodeMap nodemap.MapV2,
	nbq datapath.NodeNeighborEnqueuer,
) *linuxNodeHandler {
	return &linuxNodeHandler{
		log:                    log,
		datapathConfig:         datapathConfig,
		nodeConfig:             datapath.LocalNodeConfiguration{},
		nodes:                  map[nodeTypes.Identity]*nodeTypes.Node{},
		neighNextHopByNode4:    map[nodeTypes.Identity]map[string]string{},
		neighNextHopByNode6:    map[nodeTypes.Identity]map[string]string{},
		neighNextHopRefCount:   counter.Counter[string]{},
		neighByNextHop:         map[string]*netlink.Neigh{},
		neighLastPingByNextHop: map[string]time.Time{},
		nodeMap:                nodeMap,
		nodeIDs:                idpool.NewIDPool(minNodeID, maxNodeID),
		nodeIDsByIPs:           map[string]uint16{},
		nodeIPsByIDs:           map[uint16]sets.Set[string]{},
		ipsecMetricCollector:   ipsec.NewXFRMCollector(),
		prefixClusterMutatorFn: func(node *nodeTypes.Node) []cmtypes.PrefixClusterOpts { return nil },
		nodeNeighborQueue:      nbq,
		ipsecUpdateNeeded:      map[nodeTypes.Identity]bool{},
	}
}

func (l *linuxNodeHandler) Name() string {
	return "linux-node-datapath"
}

// updateTunnelMapping is called when a node update is received while running
// with encapsulation mode enabled. The CIDR and IP of both the old and new
// node are provided as context. The caller expects the tunnel mapping in the
// datapath to be updated.
func updateTunnelMapping(log *slog.Logger, oldCIDR, newCIDR cmtypes.PrefixCluster, oldIP, newIP net.IP,
	firstAddition, encapEnabled bool, oldEncryptKey, newEncryptKey uint8) error {
	var errs error
	if !encapEnabled {
		// When the protocol family is disabled, the initial node addition will
		// trigger a deletion to clean up leftover entries. The deletion happens
		// in quiet mode as we don't know whether it exists or not
		if newCIDR.IsValid() && firstAddition {
			if err := deleteTunnelMapping(log, newCIDR, true); err != nil {
				errs = errors.Join(errs,
					fmt.Errorf("failed to delete tunnel mapping %q: %w", newCIDR, err))
			}
		}

		return errs
	}

	if cidrNodeMappingUpdateRequired(oldCIDR, newCIDR, oldIP, newIP, oldEncryptKey, newEncryptKey) {
		log.Debug("Updating tunnel map entry",
			logfields.IPAddr, newIP,
			"allocCIDR", newCIDR,
		)

		if err := tunnel.TunnelMap().SetTunnelEndpoint(newEncryptKey, newCIDR.AddrCluster(), newIP); err != nil {
			log.Error("bpf: Unable to update in tunnel endpoint map",
				logfields.Error, err,
				"allocCIDR", newCIDR,
			)
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
		if err := deleteTunnelMapping(log, oldCIDR, false); err != nil {
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

func deleteTunnelMapping(log *slog.Logger, oldCIDR cmtypes.PrefixCluster, quietMode bool) error {
	if !oldCIDR.IsValid() {
		return nil
	}

	log.Debug("Deleting tunnel map entry",
		"allocPrefixCluster", oldCIDR.String(),
		"quietMode", quietMode,
	)

	addrCluster := oldCIDR.AddrCluster()

	if !quietMode {
		if err := tunnel.TunnelMap().DeleteTunnelEndpoint(addrCluster); err != nil {
			log.Error("Unable to delete in tunnel endpoint map",
				logfields.Error, err,
				"allocPrefixCluster", oldCIDR.String(),
			)
			return fmt.Errorf("failed to delete tunnel endpoint map: %w", err)
		}
	} else {
		return tunnel.TunnelMap().SilentDeleteTunnelEndpoint(addrCluster)
	}
	return nil
}

func createDirectRouteSpec(log *slog.Logger, CIDR *cidr.CIDR, nodeIP net.IP, skipUnreachable bool) (routeSpec *netlink.Route, addRoute bool, err error) {
	var routes []netlink.Route
	addRoute = true

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
		if skipUnreachable {
			log.Warn("route to destination contains gateway, skipping route as not directly reachable",
				"nodeIP", nodeIP,
				"gateway", routes[0].Gw.String())
			addRoute = false
		} else {
			err = fmt.Errorf("route to destination %s contains gateway %s, must be directly reachable. Add `direct-node-routes-skip-unreachable` to skip unreachable routes",
				nodeIP, routes[0].Gw.String())
		}
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
			err = fmt.Errorf("unable to find local route for destination %s: %w", nodeIP, err)
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

func installDirectRoute(log *slog.Logger, CIDR *cidr.CIDR, nodeIP net.IP, skipUnreachable bool) (routeSpec *netlink.Route, err error) {
	routeSpec, addRoute, err := createDirectRouteSpec(log, CIDR, nodeIP, skipUnreachable)
	if err != nil {
		return
	}

	if addRoute {
		err = netlink.RouteReplace(routeSpec)
	}
	return
}

func (n *linuxNodeHandler) updateDirectRoutes(oldCIDRs, newCIDRs []*cidr.CIDR, oldIP, newIP net.IP, firstAddition, directRouteEnabled bool, directRouteSkipUnreachable bool) error {

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

	n.log.Debug("Updating direct route",
		"newIP", newIP,
		"oldIP", oldIP,
		"addedCIDRs", addedCIDRs,
		"removedCIDRs", removedCIDRs,
	)

	for _, cidr := range addedCIDRs {
		if routeSpec, err := installDirectRoute(n.log, cidr, newIP, directRouteSkipUnreachable); err != nil {
			n.log.Warn("Unable to install direct node route", "route", routeSpec.String(), logfields.Error, err)
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
		n.log.Error("Unable to list direct routes", logfields.Error, err)
		return fmt.Errorf("failed to list direct routes %s: %w", familyStr, err)
	}

	var errs error
	for _, rt := range routes {
		if err := netlink.RouteDel(&rt); err != nil {
			n.log.Warn("Unable to delete direct node route", "cidr", rt.String(), logfields.Error, err)
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
		if n.nodeConfig.CiliumInternalIPv4 == nil {
			return route.Route{}, fmt.Errorf("IPv4 router address unavailable")
		}

		local = n.nodeConfig.CiliumInternalIPv4
		nexthop = &local
	} else {
		if n.nodeConfig.CiliumInternalIPv6 == nil {
			return route.Route{}, fmt.Errorf("IPv6 router address unavailable")
		}

		if n.nodeConfig.NodeIPv6 == nil {
			return route.Route{}, fmt.Errorf("external IPv6 address unavailable")
		}

		// For ipv6, kernel will reject "ip r a $cidr via $ipv6_cilium_host dev cilium_host"
		// with "Error: Gateway can not be a local address". Instead, we have to remove "via"
		// as "ip r a $cidr dev cilium_host" to make it work.
		nexthop = nil
		local = n.nodeConfig.CiliumInternalIPv6
	}

	if !isLocalNode {
		mtu = n.nodeConfig.RouteMTU
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
		n.log.Warn("Unable to update route",
			append(nodeRoute.LogAttrs(), logfields.Error, err)...)
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
		n.log.Warn("Unable to delete route",
			append(nodeRoute.LogAttrs(), logfields.Error, err)...)
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

func getNextHopIP(nodeIP net.IP, link netlink.Link) (nextHopIP net.IP, err error) {
	// Figure out whether nodeIP is directly reachable (i.e. in the same L2)
	routes, err := netlink.RouteGetWithOptions(nodeIP, &netlink.RouteGetOptions{Oif: link.Attrs().Name, FIBMatch: true})
	if err != nil && !errors.Is(err, unix.EHOSTUNREACH) && !errors.Is(err, unix.ENETUNREACH) {
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

		// Select a gw for the specified link if there are multi paths to the nodeIP
		// For example, the nextHop to the nodeIP 9.9.9.9 from eth0 is 10.0.1.2,
		// from eth1 is 10.0.2.2 as shown bellow.
		//
		// 9.9.9.9 proto bird metric 32
		//        nexthop via 10.0.1.2 dev eth0 weight 1
		//        nexthop via 10.0.2.2 dev eth1 weight 1
		//
		// NOTE: We currently don't handle multiple next hops, so only one next hop
		// per device can be used.
		if route.MultiPath != nil {
			for _, mp := range route.MultiPath {
				if mp.LinkIndex == link.Attrs().Index {
					copy(nextHopIP, mp.Gw.To16())
					break
				}
			}
		}
	}
	return nextHopIP, nil
}

type NextHop struct {
	Name  string
	IP    net.IP
	IsNew bool
}

func (n *linuxNodeHandler) insertNeighborCommon(ctx context.Context, nextHop NextHop, link netlink.Link, refresh bool) error {
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

	var errs error
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
			// EINVAL is expected (see above)
			errs = errors.Join(errs, fmt.Errorf("next hop insert failed for %+v: %w", neighInit, err))
		}
	}
	if err := netlink.NeighSet(&neigh); err != nil {
		return errors.Join(errs, fmt.Errorf("next hop refresh failed for %+v: %w", neigh, err))
	}
	n.neighByNextHop[nextHop.Name] = &neigh

	return errs
}

func (n *linuxNodeHandler) insertNeighbor4(ctx context.Context, newNode *nodeTypes.Node, link netlink.Link, refresh bool) error {
	newNodeIP := newNode.GetNodeIP(false)
	nextHopIPv4 := make(net.IP, len(newNodeIP))
	copy(nextHopIPv4, newNodeIP)

	nextHopIPv4, err := getNextHopIP(nextHopIPv4, link)
	if err != nil {
		return fmt.Errorf("unable to determine next hop IPv4 address for %s (%s): %w", link.Attrs().Name, newNodeIP, err)
	}
	nextHopStr := nextHopIPv4.String()
	scopedLog := n.log.With(
		logfields.LogSubsys, "node-neigh-debug",
		logfields.Interface, link.Attrs().Name,
		logfields.IPAddr, newNodeIP,
		logfields.NextHop, nextHopIPv4)

	n.neighLock.Lock()
	defer n.neighLock.Unlock()

	nextHopByLink, found := n.neighNextHopByNode4[newNode.Identity()]
	if !found {
		nextHopByLink = make(map[string]string)
		n.neighNextHopByNode4[newNode.Identity()] = nextHopByLink
	}

	nextHopIsNew := false
	var errs error
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
						errs = errors.Join(errs, fmt.Errorf("unable to remove next hop for IP %s (%d): %w", neigh.IP, neigh.LinkIndex, err))
						scopedLog.Info("Unable to remove next hop",
							logfields.NextHop, neigh.IP,
							logfields.LinkIndex, neigh.LinkIndex,
						)
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

	if err := errors.Join(errs, n.insertNeighborCommon(ctx, nh, link, refresh)); err != nil {
		return fmt.Errorf("insert node neighbor IPv4 for %s(%s) failed : %w", link.Attrs().Name, newNodeIP, err)
	}

	return errs
}

func (n *linuxNodeHandler) insertNeighbor6(ctx context.Context, newNode *nodeTypes.Node, link netlink.Link, refresh bool) error {
	newNodeIP := newNode.GetNodeIP(true)
	nextHopIPv6 := make(net.IP, len(newNodeIP))
	copy(nextHopIPv6, newNodeIP)

	nextHopIPv6, err := getNextHopIP(nextHopIPv6, link)
	if err != nil {
		return fmt.Errorf("unable to determine next hop IPv6 address for %s (%s): %w", link.Attrs().Name, newNodeIP, err)
	}
	nextHopStr := nextHopIPv6.String()
	scopedLog := n.log.With(
		logfields.LogSubsys, "node-neigh-debug",
		logfields.Interface, link.Attrs().Name,
		logfields.IPAddr, newNodeIP,
		logfields.NextHop, nextHopIPv6)

	n.neighLock.Lock()
	defer n.neighLock.Unlock()

	nextHopByLink, found := n.neighNextHopByNode6[newNode.Identity()]
	if !found {
		nextHopByLink = make(map[string]string)
		n.neighNextHopByNode6[newNode.Identity()] = nextHopByLink
	}

	nextHopIsNew := false
	var errs error
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
						errs = errors.Join(errs, fmt.Errorf("unable to remove next hop for IP %s (%d): %w", neigh.IP, neigh.LinkIndex, err))
						scopedLog.Info("Unable to remove next hop",
							logfields.NextHop, neigh.IP,
							logfields.LinkIndex, neigh.LinkIndex,
						)
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

	if err := errors.Join(errs, n.insertNeighborCommon(ctx, nh, link, refresh)); err != nil {
		scopedLog.Debug("insert node neighbor IPv6 failed", logfields.Error, err)
		return err
	}

	return errs
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
	var links []netlink.Link

	n.neighLock.Lock()
	if n.neighDiscoveryLinks == nil || len(n.neighDiscoveryLinks) == 0 {
		n.neighLock.Unlock()
		// Nothing to do - the discovery link was not set yet
		return nil
	}
	links = n.neighDiscoveryLinks
	n.neighLock.Unlock()

	var errs error
	if newNode.GetNodeIP(false).To4() != nil {
		for _, l := range links {
			errs = errors.Join(errs, n.insertNeighbor4(ctx, newNode, l, refresh))
		}
	}
	if newNode.GetNodeIP(true).To16() != nil {
		for _, l := range links {
			errs = errors.Join(errs, n.insertNeighbor6(ctx, newNode, l, refresh))
		}
	}

	return errs
}

func (n *linuxNodeHandler) InsertMiscNeighbor(newNode *nodeTypes.Node) {
	n.nodeNeighborQueue.Enqueue(newNode, false)
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
				n.log.Info("Unable to remove next hop",
					logfields.LogSubsys, "node-neigh-debug",
					logfields.NextHop, neigh.IP,
					logfields.LinkIndex, neigh.LinkIndex,
					logfields.Error, err,
				)
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

func (n *linuxNodeHandler) DeleteMiscNeighbor(oldNode *nodeTypes.Node) {
	n.deleteNeighbor(oldNode)
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
	nodeID, err := n.allocateIDForNode(oldNode, newNode)
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

	if n.nodeConfig.EnableIPSec {
		errs = errors.Join(errs, n.enableIPsec(oldNode, newNode, nodeID))
		newKey = newNode.EncryptionKey
	}

	if n.enableNeighDiscovery && !newNode.IsLocal() {
		// If neighbor discovery is enabled, enqueue the request so we can monitor/report call health.
		n.nodeNeighborQueue.Enqueue(newNode, false)
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

	if n.nodeConfig.EnableAutoDirectRouting && !n.enableEncapsulation(newNode) {
		if err := n.updateDirectRoutes(oldAllIP4AllocCidrs, newAllIP4AllocCidrs, oldIP4, newIP4, firstAddition, n.nodeConfig.EnableIPv4, n.nodeConfig.DirectRoutingSkipUnreachable); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to enable direct routes for ipv4: %w", err))
		}
		if err := n.updateDirectRoutes(oldAllIP6AllocCidrs, newAllIP6AllocCidrs, oldIP6, newIP6, firstAddition, n.nodeConfig.EnableIPv6, n.nodeConfig.DirectRoutingSkipUnreachable); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to enable direct routes for ipv6: %w", err))
		}
		return errs
	}

	if n.enableEncapsulation(newNode) {
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
		errs = errors.Join(errs, updateTunnelMapping(n.log, oldPrefixCluster4, newPrefixCluster4, oldIP4, newIP4, firstAddition, n.nodeConfig.EnableIPv4, oldKey, newKey))
		// Not a typo, the IPv4 host IP is used to build the IPv6 overlay
		errs = errors.Join(errs, updateTunnelMapping(n.log, oldPrefixCluster6, newPrefixCluster6, oldIP4, newIP4, firstAddition, n.nodeConfig.EnableIPv6, oldKey, newKey))

		if err := n.updateOrRemoveNodeRoutes(oldAllIP4AllocCidrs, newAllIP4AllocCidrs, isLocalNode); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to enable encapsulation: single cluster routes: ipv4: %w", err))
		}
		if err := n.updateOrRemoveNodeRoutes(oldAllIP6AllocCidrs, newAllIP6AllocCidrs, isLocalNode); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to enable encapsulation: single cluster routes: ipv6: %w", err))
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
	if oldCachedNode, nodeExists := n.nodes[nodeIdentity]; nodeExists || oldNode.Source == source.Restored {
		delete(n.nodes, nodeIdentity)

		if oldNode.Source == source.Restored {
			oldCachedNode = &oldNode
		}

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
	if n.nodeConfig.EnableAutoDirectRouting && !n.enableEncapsulation(oldNode) {
		if err := n.deleteDirectRoute(oldNode.IPv4AllocCIDR, oldIP4); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to remove old direct routing: deleting old routes: %w", err))
		}
		if err := n.deleteDirectRoute(oldNode.IPv6AllocCIDR, oldIP6); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to remove old direct routing: deleting old routes: %w", err))
		}
	}

	if n.enableEncapsulation(oldNode) {
		oldPrefix4 := cmtypes.PrefixClusterFromCIDR(oldNode.IPv4AllocCIDR, n.prefixClusterMutatorFn(oldNode)...)
		oldPrefix6 := cmtypes.PrefixClusterFromCIDR(oldNode.IPv6AllocCIDR, n.prefixClusterMutatorFn(oldNode)...)
		if err := deleteTunnelMapping(n.log, oldPrefix4, false); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to remove old encapsulation config: deleting tunnel mapping for ipv4: %w", err))
		}
		if err := deleteTunnelMapping(n.log, oldPrefix6, false); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to remove old encapsulation config: deleting tunnel mapping for ipv6: %w", err))
		}

		if err := n.deleteNodeRoute(oldNode.IPv4AllocCIDR, false); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to remove old encapsulation config: deleting old single cluster node route for ipv4: %w", err))
		}
		if err := n.deleteNodeRoute(oldNode.IPv6AllocCIDR, false); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to remove old encapsulation config: deleting old single cluster node route for ipv6: %w", err))
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
				n.log.Error("Replace IPv4 route decrypt rule failed", logfields.Error, err)
				return err
			}
		}
		rule.Mark = linux_defaults.RouteMarkEncrypt
		if err := route.ReplaceRule(rule); err != nil {
			n.log.Error("Replace IPv4 route encrypt rule failed", logfields.Error, err)
			return err
		}
	}

	if n.nodeConfig.EnableIPv6 {
		rule.Mark = linux_defaults.RouteMarkDecrypt
		if err := route.ReplaceRuleIPv6(rule); err != nil {
			n.log.Error("Replace IPv6 route decrypt rule failed", logfields.Error, err)
			return err
		}
		rule.Mark = linux_defaults.RouteMarkEncrypt
		if err := route.ReplaceRuleIPv6(rule); err != nil {
			n.log.Error("Replace IPv6 route ecrypt rule failed", logfields.Error, err)
			return err
		}
	}

	return nil
}

// NodeConfigurationChanged is called when the LocalNodeConfiguration has changed
func (n *linuxNodeHandler) NodeConfigurationChanged(newConfig datapath.LocalNodeConfiguration) error {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	prevConfig := n.nodeConfig
	n.nodeConfig = newConfig

	if n.enableEncapsulation == nil {
		n.enableEncapsulation = func(*nodeTypes.Node) bool { return n.nodeConfig.EnableEncapsulation }
	}

	if n.nodeConfig.EnableIPv4 || n.nodeConfig.EnableIPv6 {
		var ifaceNames []string
		switch {
		case !option.Config.EnableL2NeighDiscovery:
			n.enableNeighDiscovery = false
		case option.Config.DirectRoutingDeviceRequired():
			if newConfig.DirectRoutingDevice == nil {
				return fmt.Errorf("direct routing device is required, but not defined")
			}

			drd := newConfig.DirectRoutingDevice
			devices := n.nodeConfig.DeviceNames()

			targetDevices := make([]string, 0, len(devices)+1)
			targetDevices = append(targetDevices, drd.Name)
			targetDevices = append(targetDevices, devices...)

			var err error
			ifaceNames, err = filterL2Devices(targetDevices)
			if err != nil {
				return err
			}
			n.enableNeighDiscovery = len(ifaceNames) != 0 // No need to arping for L2-less devices
		}

		if n.enableNeighDiscovery {
			neighDiscoveryLinks := make([]netlink.Link, 0, len(ifaceNames))
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
				n.log.Warn("Unable to store neighbor discovery iface."+
					" Removing PERM neighbor entries upon cilium-agent init when neighbor"+
					" discovery is disabled will not work.",
					logfields.Error, err,
				)
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
				ipv4CIDRs := info.GetIPv4CIDRs()
				ipv4PodSubnets := make([]*net.IPNet, 0, len(ipv4CIDRs))
				for _, c := range ipv4CIDRs {
					ipv4PodSubnets = append(ipv4PodSubnets, &c)
				}
				n.nodeConfig.IPv4PodSubnets = ipv4PodSubnets
			}
		}

		if err := n.replaceHostRules(); err != nil {
			n.log.Warn("Cannot replace Host rules", logfields.Error, err)
		}
		n.registerIpsecMetricOnce()
	} else {
		if err := n.removeEncryptRules(); err != nil {
			n.log.Warn("Cannot cleanup previous encryption rule state.", logfields.Error, err)
		}
		if err := ipsec.DeleteXFRM(n.log, ipsec.AllReqID); err != nil {
			return fmt.Errorf("failed to delete xfrm policies on node configuration changed: %w", err)
		}
	}

	if !newConfig.EnableIPSecEncryptedOverlay {
		if err := ipsec.DeleteXFRM(n.log, ipsec.EncryptedOverlayReqID); err != nil {
			return fmt.Errorf("failed to delete encrypt overlay xfrm policies on node configuration change: %w", err)
		}
	}

	var errs error
	if !n.isInitialized {
		n.isInitialized = true

		for _, unlinkedNode := range n.nodes {
			if err := n.nodeUpdate(nil, unlinkedNode, true); err != nil {
				errs = errors.Join(errs, err)
			}
		}
	}

	return errs
}

func filterL2Devices(devices []string) ([]string, error) {
	// Eliminate duplicates
	deviceSets := make(map[string]struct{}, len(devices))
	for _, d := range devices {
		deviceSets[d] = struct{}{}
	}

	l2devices := make([]string, 0, len(deviceSets))
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

	if !n.isInitialized {
		return nil
	}

	return n.nodeUpdate(nil, &nodeToValidate, false)
}

// AllNodeValidateImplementation is called to validate the implementation of the
// node in the datapath for all existing nodes
func (n *linuxNodeHandler) AllNodeValidateImplementation() {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	if !n.isInitialized {
		return
	}

	var errs error
	for _, updateNode := range n.nodes {
		if err := n.nodeUpdate(nil, updateNode, false); err != nil {
			errs = errors.Join(errs, err)
		}
	}
	if errs != nil {
		n.log.Warn("Node update failed during datapath node validation", logfields.Error, errs)
	}
}

// NodeNeighDiscoveryEnabled returns whether node neighbor discovery is enabled
func (n *linuxNodeHandler) NodeNeighDiscoveryEnabled() bool {
	return n.enableNeighDiscovery
}

// NodeNeighborRefresh is called to refresh node neighbor table.
// This is currently triggered by controller neighbor-table-refresh
// When refresh is set, insertNeighbor will perform a timestamp check on
// the last ping and potentially skip the refresh to prevent ddos on the gateway.
func (n *linuxNodeHandler) NodeNeighborRefresh(ctx context.Context, nodeToRefresh nodeTypes.Node, refresh bool) error {
	n.mutex.Lock()
	if !n.isInitialized {
		n.mutex.Unlock()
		// Wait until the node is initialized. When it's not, insertNeighbor()
		// is not invoked, so there is nothing to refresh.
		return nil
	}
	n.mutex.Unlock()
	return n.insertNeighbor(ctx, &nodeToRefresh, refresh)
}

func (n *linuxNodeHandler) NodeCleanNeighborsLink(l netlink.Link, migrateOnly bool) bool {
	successClean := true

	neighList, err := netlink.NeighListExecute(netlink.Ndmsg{
		Index: uint32(l.Attrs().Index),
	})
	if err != nil {
		n.log.Error("Unable to list PERM neighbor entries for removal of network device",
			logfields.Error, err,
			logfields.Device, l.Attrs().Name,
			logfields.LinkIndex, l.Attrs().Index,
		)
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
					n.log.Info("Unable to replace new next hop",
						logfields.Error, err,
						logfields.Device, l.Attrs().Name,
						logfields.LinkIndex, l.Attrs().Index,
						"neighbor", fmt.Sprintf("%+v", neigh),
					)
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
			n.log.Error("Unable to "+which+" non-GC'ed neighbor entry of network device. "+
				"Consider removing this entry manually with 'ip neigh del "+neigh.IP.String()+" dev "+l.Attrs().Name+"'",
				logfields.Error, err,
				logfields.Device, l.Attrs().Name,
				logfields.LinkIndex, l.Attrs().Index,
				"neighbor", fmt.Sprintf("%+v", neigh),
			)

			neighErrored++
			successClean = false
		} else {
			neighSucceeded++
		}
	}
	if neighSucceeded != 0 {
		n.log.Info("Successfully "+which+"d non-GC'ed neighbor entries previously installed by cilium-agent",
			logfields.Count, neighSucceeded,
		)
	}
	if neighErrored != 0 {
		n.log.Warn("Unable to "+which+" non-GC'ed neighbor entries previously installed by cilium-agent",
			logfields.Count, neighErrored,
		)
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
		n.log.Error("Unable to load neighbor discovery iface name for removing PERM neighbor entries",
			logfields.Error, err,
		)
		return
	}
	if len(linkNames) == 0 {
		return
	}

	// Delete the file after cleaning up neighbor list if we were able to clean
	// up all neighbors.
	successClean := true
	defer func() {
		if successClean && !migrateOnly {
			os.Remove(filepath.Join(option.Config.StateDir, neighFileName))
		}
	}()

	for _, linkName := range linkNames {
		l, err := netlink.LinkByName(linkName)
		if err != nil {
			// If the link is not found we don't need to keep retrying cleaning
			// up the neihbor entries so we can keep successClean=true
			var linkNotFoundError netlink.LinkNotFoundError
			if !errors.As(err, &linkNotFoundError) {
				n.log.Error("Unable to remove PERM neighbor entries of network device",
					logfields.Error, err,
					logfields.Device, linkName,
				)
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

	nls := make([]NeighLink, 0, len(names))
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

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	var nls []NeighLink
	if err := json.NewDecoder(f).Decode(&nls); err != nil {
		return nil, fmt.Errorf("unable to decode '%s': %w", configFileName, err)
	}
	names := make([]string, 0, len(nls))
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

func (n *linuxNodeHandler) OverrideEnableEncapsulation(fn func(*nodeTypes.Node) bool) {
	n.enableEncapsulation = fn
}
