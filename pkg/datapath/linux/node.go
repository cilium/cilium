// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"syscall"

	"github.com/cilium/hive/cell"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/config"
	"github.com/cilium/cilium/pkg/datapath/linux/ipsec"
	fakeipsec "github.com/cilium/cilium/pkg/datapath/linux/ipsec/fake"
	ipsecTypes "github.com/cilium/cilium/pkg/datapath/linux/ipsec/types"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	dpTunnel "github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/idpool"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/nodemap"
	subnetmap "github.com/cilium/cilium/pkg/maps/subnet"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/manager"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
)

const (
	wildcardIPv4 = "0.0.0.0"
	wildcardIPv6 = "0::0"
)

// NeighLink contains the details of a NeighLink
type NeighLink struct {
	Name string `json:"link-name"`
}

type linuxNodeHandler struct {
	log *slog.Logger

	mutex             lock.RWMutex
	isInitialized     bool
	nodeConfig        config.Config
	datapathConfig    DatapathConfiguration
	nodes             map[nodeTypes.Identity]*nodeTypes.Node
	ipsecUpdateNeeded map[nodeTypes.Identity]bool

	localNodeStore *node.LocalNodeStore
	nodeMap        nodemap.MapV2
	// Pool of available IDs for nodes.
	nodeIDs *idpool.IDPool
	// Node-scoped unique IDs for the nodes.
	nodeIDsByIPs map[string]uint16
	// reverse map of the above
	nodeIPsByIDs map[uint16]sets.Set[string]

	ipsecMetricCollector prometheus.Collector
	ipsecMetricOnce      sync.Once
	ipsecAgent           ipsecTypes.Agent

	enableEncapsulation func(node *nodeTypes.Node) bool

	db          *statedb.DB
	subnetTable statedb.Table[subnetmap.SubnetTableEntry]

	kprCfg kpr.KPRConfig

	ipsecCfg ipsecTypes.Config
}

var (
	_ node.Handler         = (*linuxNodeHandler)(nil)
	_ config.ChangeHandler = (*linuxNodeHandler)(nil)
	_ node.IDHandler       = (*linuxNodeHandler)(nil)
)

// NewNodeHandler returns a new node handler to handle node events and
// implement the implications in the Linux datapath
func NewNodeHandler(
	lifecycle cell.Lifecycle,
	log *slog.Logger,
	tunnelConfig dpTunnel.Config,
	nodeMap nodemap.MapV2,
	nodeManager manager.NodeManager,
	nodeConfigNotifier *manager.NodeConfigNotifier,
	kprCfg kpr.KPRConfig,
	ipsecAgent ipsecTypes.Agent,
	localNodeStore *node.LocalNodeStore,
	db *statedb.DB,
	subnetTable statedb.Table[subnetmap.SubnetTableEntry],
) (node.Handler, node.IDHandler) {
	datapathConfig := DatapathConfiguration{
		HostDevice:   defaults.HostDevice,
		TunnelDevice: tunnelConfig.DeviceName(),
	}

	handler := newNodeHandler(log, datapathConfig, nodeMap, kprCfg, ipsecAgent, fakeipsec.Config{}, localNodeStore, db, subnetTable)

	nodeManager.Subscribe(handler)
	nodeConfigNotifier.Subscribe(handler)

	lifecycle.Append(cell.Hook{
		OnStart: func(_ cell.HookContext) error {
			handler.RestoreNodeIDs()
			return nil
		},
	})

	return handler, handler
}

// newNodeHandler returns a new node handler to handle node events and
// implement the implications in the Linux datapath
func newNodeHandler(
	log *slog.Logger,
	datapathConfig DatapathConfiguration,
	nodeMap nodemap.MapV2,
	kprCfg kpr.KPRConfig,
	ipsecAgent ipsecTypes.Agent,
	ipsecCfg ipsecTypes.Config,
	localNodeStore *node.LocalNodeStore,
	db *statedb.DB,
	subnetTable statedb.Table[subnetmap.SubnetTableEntry],
) *linuxNodeHandler {
	return &linuxNodeHandler{
		log:                  log,
		datapathConfig:       datapathConfig,
		nodeConfig:           config.Config{},
		nodes:                map[nodeTypes.Identity]*nodeTypes.Node{},
		localNodeStore:       localNodeStore,
		nodeMap:              nodeMap,
		nodeIDs:              idpool.NewIDPool(minNodeID, maxNodeID),
		nodeIDsByIPs:         map[string]uint16{},
		nodeIPsByIDs:         map[uint16]sets.Set[string]{},
		ipsecMetricCollector: ipsec.NewXFRMCollector(log),
		ipsecUpdateNeeded:    map[nodeTypes.Identity]bool{},
		kprCfg:               kprCfg,
		ipsecAgent:           ipsecAgent,
		ipsecCfg:             ipsecCfg,
		db:                   db,
		subnetTable:          subnetTable,
	}
}

func (l *linuxNodeHandler) Name() string {
	return "linux-node-datapath"
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
			log.Debug("route to destination contains gateway, skipping route as not directly reachable",
				logfields.NodeIP, nodeIP,
				logfields.GatewayIP, routes[0].Gw)
			addRoute = false
		} else {
			err = fmt.Errorf("route to destination %s contains gateway %s, must be directly reachable. Add `direct-routing-skip-unreachable` to skip unreachable routes",
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

		routes, err = safenetlink.RouteListFiltered(family, filter, netlink.RT_FILTER_DST|netlink.RT_FILTER_TABLE)
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
		logfields.NewIP, newIP,
		logfields.OldIP, oldIP,
		logfields.AddedCIDRs, addedCIDRs,
		logfields.RemovedCIDRs, removedCIDRs,
	)

	for _, cidr := range addedCIDRs {
		if routeSpec, err := installDirectRoute(n.log, cidr, newIP, directRouteSkipUnreachable); err != nil {
			n.log.Warn("Unable to install direct node route",
				logfields.Route, routeSpec,
				logfields.Error, err,
			)
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

	routes, err := safenetlink.RouteListFiltered(family, filter, netlink.RT_FILTER_DST|netlink.RT_FILTER_GW)
	if err != nil {
		n.log.Error("Unable to list direct routes", logfields.Error, err)
		return fmt.Errorf("failed to list direct routes %s: %w", familyStr, err)
	}

	var errs error
	for _, rt := range routes {
		if err := netlink.RouteDel(&rt); err != nil {
			n.log.Warn("Unable to delete direct node route",
				logfields.CIDR, rt,
				logfields.Error, err,
			)
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
		if !n.nodeConfig.CiliumInternalIPv4.IsValid() {
			return route.Route{}, fmt.Errorf("IPv4 router address unavailable")
		}

		local = net.IP(n.nodeConfig.CiliumInternalIPv4.AsSlice())
		nexthop = &local
	} else {
		if !n.nodeConfig.CiliumInternalIPv6.IsValid() {
			return route.Route{}, fmt.Errorf("IPv6 router address unavailable")
		}

		if !n.nodeConfig.NodeIPv6.IsValid() {
			return route.Route{}, fmt.Errorf("external IPv6 address unavailable")
		}

		// For ipv6, kernel will reject "ip r a $cidr via $ipv6_cilium_host dev cilium_host"
		// with "Error: Gateway can not be a local address". Instead, we have to remove "via"
		// as "ip r a $cidr dev cilium_host" to make it work.
		nexthop = nil
		local = net.IP(n.nodeConfig.CiliumInternalIPv6.AsSlice())
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
	if err := route.Upsert(n.log, nodeRoute); err != nil {
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

		n.diffAndUnmapNodeIPs(oldNode.IPAddresses, newNode.IPAddresses)
	}

	if n.nodeConfig.EnableIPSec {
		errs = errors.Join(errs, n.enableIPsec(oldNode, newNode, nodeID))
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
			if err := n.enableSubnetIPsec(n.nodeConfig.GetIPv4PodSubnets(), n.nodeConfig.GetIPv6PodSubnets()); err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to enable subnet encryption: %w", err))
			}
		}
		if firstAddition && n.nodeConfig.EnableIPSec {
			n.registerIpsecMetricOnce()
		}
		return errs
	}

	installTunnelRoutes := n.enableEncapsulation(newNode)
	installDirectRoutes := n.nodeConfig.EnableAutoDirectRouting && !installTunnelRoutes

	if installTunnelRoutes {
		if err := n.updateOrRemoveNodeRoutes(oldAllIP4AllocCidrs, newAllIP4AllocCidrs, isLocalNode); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to enable encapsulation: single cluster routes: ipv4: %w", err))
		}
		if err := n.updateOrRemoveNodeRoutes(oldAllIP6AllocCidrs, newAllIP6AllocCidrs, isLocalNode); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to enable encapsulation: single cluster routes: ipv6: %w", err))
		}
	}

	if installDirectRoutes {
		if err := n.updateDirectRoutes(oldAllIP4AllocCidrs, newAllIP4AllocCidrs, oldIP4, newIP4, firstAddition, n.nodeConfig.EnableIPv4, n.nodeConfig.DirectRoutingSkipUnreachable); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to enable direct routes for ipv4: %w", err))
		}
		if err := n.updateDirectRoutes(oldAllIP6AllocCidrs, newAllIP6AllocCidrs, oldIP6, newIP6, firstAddition, n.nodeConfig.EnableIPv6, n.nodeConfig.DirectRoutingSkipUnreachable); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to enable direct routes for ipv6: %w", err))
		}
	}

	if !installTunnelRoutes && firstAddition {
		for _, ipv4AllocCIDR := range newAllIP4AllocCidrs {
			if rt, _ := n.lookupNodeRoute(ipv4AllocCIDR, isLocalNode); rt != nil {
				if err := n.deleteNodeRoute(ipv4AllocCIDR, isLocalNode); err != nil {
					errs = errors.Join(errs, fmt.Errorf("failed to clean up stale tunnel route for ipv4: %w", err))
				}
			}
		}
		for _, ipv6AllocCIDR := range newAllIP6AllocCidrs {
			if rt, _ := n.lookupNodeRoute(ipv6AllocCIDR, isLocalNode); rt != nil {
				if err := n.deleteNodeRoute(ipv6AllocCIDR, isLocalNode); err != nil {
					errs = errors.Join(errs, fmt.Errorf("failed to clean up stale tunnel route for ipv6: %w", err))
				}
			}
		}
	}
	if !installDirectRoutes && firstAddition {
		if err := n.deleteAllDirectRoutes(newAllIP4AllocCidrs, newIP4); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to clean up stale direct route for ipv4: %w", err))
		}
		if err := n.deleteAllDirectRoutes(newAllIP6AllocCidrs, newIP6); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to clean up stale direct route for ipv6: %w", err))
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

	oldAllIP4AllocCidrs := oldNode.GetIPv4AllocCIDRs()
	oldAllIP6AllocCidrs := oldNode.GetIPv6AllocCIDRs()

	var errs error

	deleteTunnelRoutes := n.enableEncapsulation(oldNode)
	deleteDirectRoutes := n.nodeConfig.EnableAutoDirectRouting && !deleteTunnelRoutes

	if deleteDirectRoutes {
		if n.nodeConfig.EnableIPv4 {
			for _, cidr := range oldAllIP4AllocCidrs {
				if err := n.deleteDirectRoute(cidr, oldIP4); err != nil {
					errs = errors.Join(errs, fmt.Errorf("failed to remove old direct routing: deleting old routes: %w", err))
				}
			}
		}
		if n.nodeConfig.EnableIPv6 {
			for _, cidr := range oldAllIP6AllocCidrs {
				if err := n.deleteDirectRoute(cidr, oldIP6); err != nil {
					errs = errors.Join(errs, fmt.Errorf("failed to remove old direct routing: deleting old routes: %w", err))
				}
			}
		}
	}

	if deleteTunnelRoutes {
		if n.nodeConfig.EnableIPv4 {
			for _, cidr := range oldAllIP4AllocCidrs {
				if err := n.deleteNodeRoute(cidr, false); err != nil {
					errs = errors.Join(errs, fmt.Errorf("failed to remove old encapsulation config: deleting old single cluster node route for ipv4: %w", err))
				}
			}
		}
		if n.nodeConfig.EnableIPv6 {
			for _, cidr := range oldAllIP6AllocCidrs {
				if err := n.deleteNodeRoute(cidr, false); err != nil {
					errs = errors.Join(errs, fmt.Errorf("failed to remove old encapsulation config: deleting old single cluster node route for ipv6: %w", err))
				}
			}
		}
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
	}

	if n.nodeConfig.EnableIPv6 {
		rule.Mark = linux_defaults.RouteMarkDecrypt
		if err := route.ReplaceRuleIPv6(rule); err != nil {
			n.log.Error("Replace IPv6 route decrypt rule failed", logfields.Error, err)
			return err
		}
	}

	return nil
}

// NodeConfigurationChanged is called when the LocalNodeConfiguration has changed
func (n *linuxNodeHandler) NodeConfigurationChanged(newConfig config.Config) error {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	prevConfig := n.nodeConfig
	n.nodeConfig = newConfig

	if n.enableEncapsulation == nil {
		n.enableEncapsulation = func(node *nodeTypes.Node) bool {
			if n.hybridMode() {
				// Check if the node requires a tunnel route in hybrid mode.
				// If node is directly reachable this will return false
				return n.nodeRequiresTunnelRoute(node)
			}
			return n.nodeConfig.EnableEncapsulation
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
				cidrs := info.GetCIDRs()
				var ipv4PodSubnets []*cidr.CIDR
				for _, c := range cidrs {
					if c.IP.To4() != nil {
						ipv4PodSubnets = append(ipv4PodSubnets, cidr.NewCIDR(&c))
					}
				}
				n.nodeConfig.IPv4PodSubnets = ipv4PodSubnets
			}
		}

		if err := n.replaceHostRules(); err != nil {
			n.log.Warn("Cannot replace Host rules", logfields.Error, err)
		}
		n.registerIpsecMetricOnce()
	} else {
		if err := n.removeDecryptRules(); err != nil {
			n.log.Warn("Cannot cleanup previous decryption rule state.", logfields.Error, err)
		}
		if err := n.ipsecAgent.DeleteXFRM(ipsec.AllReqID); err != nil {
			return fmt.Errorf("failed to delete xfrm policies on node configuration changed: %w", err)
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

// NodeDeviceNameWithDefaultRoute returns the node's device name which
// handles the default route in the current namespace
func NodeDeviceNameWithDefaultRoute(logger *slog.Logger) (string, error) {
	link, err := route.NodeDeviceWithDefaultRoute(logger, option.Config.EnableIPv4, option.Config.EnableIPv6)
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

func (n *linuxNodeHandler) hybridMode() bool {
	return n.nodeConfig.EnableEncapsulation && n.nodeConfig.RequiresNativeRouting
}

// nodeRequiresTunnelRoute returns true if the remote node is not in the same
// subnet group as the local node, based on the user-configured subnet topology.
// Nodes in the same subnet group use native routing; nodes in different groups
// ,or not found in any group) require tunnel encapsulation.
func (n *linuxNodeHandler) nodeRequiresTunnelRoute(remoteNode *nodeTypes.Node) bool {
	if remoteNode == nil {
		return true
	}

	remoteIP := remoteNode.GetNodeIP(false) // IPv4
	if remoteIP == nil {
		remoteIP = remoteNode.GetNodeIP(true) // IPv6
	}
	if remoteIP == nil {
		return true
	}

	ln, err := n.localNodeStore.Get(context.Background())
	if err != nil {
		return true
	}
	localIP := ln.GetNodeIP(false)
	if localIP == nil {
		localIP = ln.GetNodeIP(true) // IPv6
	}
	if localIP == nil {
		return true
	}

	localAddr, ok1 := netip.AddrFromSlice(localIP)
	remoteAddr, ok2 := netip.AddrFromSlice(remoteIP)
	if !ok1 || !ok2 {
		return true
	}

	localGroupID := n.lookupSubnetID(localAddr)
	remoteGroupID := n.lookupSubnetID(remoteAddr)

	// Same non-zero group = native routing, otherwise tunnel is required.
	return localGroupID != remoteGroupID || localGroupID == 0
}

// lookupSubnetID returns the subnet group identity for the given IP address
// by iterating the subnet topology table. Returns 0 if not found.
func (n *linuxNodeHandler) lookupSubnetID(addr netip.Addr) uint32 {
	if n.db == nil || n.subnetTable == nil {
		return 0
	}

	txn := n.db.ReadTxn()
	for entry := range n.subnetTable.All(txn) {
		if entry.Key.Contains(addr) {
			return entry.Value
		}
	}
	return 0
}

func (n *linuxNodeHandler) OverrideEnableEncapsulation(fn func(*nodeTypes.Node) bool) {
	n.enableEncapsulation = fn
}
