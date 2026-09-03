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
	"github.com/cilium/statedb"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/vishvananda/netlink"
	"go4.org/netipx"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/util/sets"

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
	"github.com/cilium/cilium/pkg/ip"
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
	cslices "github.com/cilium/cilium/pkg/slices"
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
	subnetTable statedb.RWTable[subnetmap.SubnetTableEntry]

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
	subnetTable statedb.RWTable[subnetmap.SubnetTableEntry],
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
		OnStop: func(_ cell.HookContext) error {
			nodeManager.Unsubscribe(handler)
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
	subnetTable statedb.RWTable[subnetmap.SubnetTableEntry],
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

func createDirectRouteSpec(log *slog.Logger, prefix netip.Prefix, nodeIP net.IP, skipUnreachable bool) (routeSpec *netlink.Route, addRoute bool, err error) {
	var routes []netlink.Route
	addRoute = true

	routeSpec = &netlink.Route{
		Dst:      netipx.PrefixIPNet(prefix),
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

func installDirectRoute(log *slog.Logger, prefix netip.Prefix, nodeIP net.IP, skipUnreachable bool) (routeSpec *netlink.Route, err error) {
	routeSpec, addRoute, err := createDirectRouteSpec(log, prefix, nodeIP, skipUnreachable)
	if err != nil {
		return
	}

	if addRoute {
		err = netlink.RouteReplace(routeSpec)
	}
	return
}

func (n *linuxNodeHandler) updateDirectRoutes(oldCIDRs, newCIDRs []netip.Prefix, oldIP, newIP net.IP, firstAddition, directRouteEnabled bool, directRouteSkipUnreachable bool) error {
	if !directRouteEnabled {
		// When the protocol family is disabled, the initial node addition will
		// trigger a deletion to clean up leftover entries. The deletion happens
		// in quiet mode as we don't know whether it exists or not
		if firstAddition {
			return n.deleteAllDirectRoutes(newCIDRs, newIP)
		}
		return nil
	}

	var addedCIDRs, removedCIDRs []netip.Prefix
	if oldIP.Equal(newIP) {
		oldSet, newSet := sets.New(oldCIDRs...), sets.New(newCIDRs...)
		addedCIDRs = newSet.Difference(oldSet).UnsortedList()
		removedCIDRs = oldSet.Difference(newSet).UnsortedList()
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

	for _, prefix := range addedCIDRs {
		if routeSpec, err := installDirectRoute(n.log, prefix, newIP, directRouteSkipUnreachable); err != nil {
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

func (n *linuxNodeHandler) deleteAllDirectRoutes(prefixes []netip.Prefix, nodeIP net.IP) error {
	var errs error
	for _, prefix := range prefixes {
		if err := n.deleteDirectRoute(prefix, nodeIP); err != nil {
			errs = errors.Join(errs, err)
		}
	}
	return errs
}

func (n *linuxNodeHandler) deleteDirectRoute(prefix netip.Prefix, nodeIP net.IP) error {
	if !prefix.IsValid() {
		return nil
	}

	family := netlink.FAMILY_V4
	familyStr := "ip4"
	if !prefix.Addr().Is4() {
		family = netlink.FAMILY_V6
		familyStr = "ip6"
	}

	filter := &netlink.Route{
		Dst:      netipx.PrefixIPNet(prefix),
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
func (n *linuxNodeHandler) createNodeRouteSpec(prefix netip.Prefix, isLocalNode bool) (route.Route, error) {
	var (
		local   net.IP
		nexthop *net.IP
		mtu     int
	)
	if prefix.Addr().Is4() {
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
		Prefix:   *netipx.PrefixIPNet(prefix),
		MTU:      mtu,
		Priority: option.Config.RouteMetric,
		Proto:    linux_defaults.RTProto,
	}, nil
}

func (n *linuxNodeHandler) lookupNodeRoute(prefix netip.Prefix, isLocalNode bool) (*route.Route, error) {
	if !prefix.IsValid() {
		return nil, nil
	}

	routeSpec, err := n.createNodeRouteSpec(prefix, isLocalNode)
	if err != nil {
		return nil, err
	}

	return route.Lookup(routeSpec)
}

func (n *linuxNodeHandler) updateNodeRoute(prefix netip.Prefix, addressFamilyEnabled bool, isLocalNode bool) error {
	if !prefix.IsValid() || !addressFamilyEnabled {
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

func (n *linuxNodeHandler) deleteNodeRoute(prefix netip.Prefix, isLocalNode bool) error {
	if !prefix.IsValid() {
		return nil
	}

	// Symmetric with deleteDirectRoute: no-op if the route is absent.
	existing, err := n.lookupNodeRoute(prefix, isLocalNode)
	if err != nil {
		return err
	}
	if existing == nil {
		return nil
	}
	if err := route.Delete(*existing); err != nil {
		n.log.Warn("Unable to delete route",
			append(existing.LogAttrs(), logfields.Error, err)...)
		return err
	}

	return nil
}

func (n *linuxNodeHandler) familyEnabled(prefix netip.Prefix) bool {
	return (prefix.Addr().Is4() && n.nodeConfig.EnableIPv4) || (prefix.Addr().Is6() && n.nodeConfig.EnableIPv6)
}

func (n *linuxNodeHandler) updateOrRemoveNodeRoutes(old, new []netip.Prefix, isLocalNode bool) error {
	var errs error
	oldSet, newSet := sets.New(old...), sets.New(new...)
	addedAuxRoutes := newSet.Difference(oldSet).UnsortedList()
	removedAuxRoutes := oldSet.Difference(newSet).UnsortedList()
	for _, prefix := range addedAuxRoutes {
		if err := n.updateNodeRoute(prefix, n.familyEnabled(prefix), isLocalNode); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to add aux route %q: %w", prefix, err))
		}
	}
	for _, prefix := range removedAuxRoutes {
		if err := n.deleteNodeRoute(prefix, isLocalNode); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to remove aux route %q: %w", prefix, err))
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

		oldAllIP4AllocCidrs, oldAllIP6AllocCidrs []netip.Prefix
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

	if n.hybridMode() {
		errs = errors.Join(errs, n.updateHybridRoutes(oldNode, newNode, oldIP4, newIP4, oldIP6, newIP6, firstAddition, isLocalNode))
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
			if err := n.deleteNodeRoute(ipv4AllocCIDR, isLocalNode); err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to clean up stale tunnel route for ipv4: %w", err))
			}
		}
		for _, ipv6AllocCIDR := range newAllIP6AllocCidrs {
			if err := n.deleteNodeRoute(ipv6AllocCIDR, isLocalNode); err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to clean up stale tunnel route for ipv6: %w", err))
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

	// Both delete functions are idempotent (no-op if the route isn't present),
	// so we always attempt both cleanups regardless of the last-installed mode.
	if n.nodeConfig.EnableIPv4 {
		for _, prefix := range oldAllIP4AllocCidrs {
			if err := n.deleteDirectRoute(prefix, oldIP4); err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to remove old direct route ipv4: %w", err))
			}
			if err := n.deleteNodeRoute(prefix, false); err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to remove old node route ipv4: %w", err))
			}
		}
	}
	if n.nodeConfig.EnableIPv6 {
		for _, prefix := range oldAllIP6AllocCidrs {
			if err := n.deleteDirectRoute(prefix, oldIP6); err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to remove old direct route ipv6: %w", err))
			}
			if err := n.deleteNodeRoute(prefix, false); err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to remove old node route ipv6: %w", err))
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
			return n.nodeConfig.EnableEncapsulation
		}
	}

	if err := n.updateOrRemoveNodeRoutes(
		cslices.Map(prevConfig.AuxiliaryPrefixes, ip.Prefix.Unwrap),
		cslices.Map(newConfig.AuxiliaryPrefixes, ip.Prefix.Unwrap),
		true,
	); err != nil {
		return fmt.Errorf("failed to update or remove node routes: %w", err)
	}

	if newConfig.EnableIPSec {
		// For the ENI ipam mode on EKS, this will be the interface that
		// the router (cilium_host) IP is associated to.
		if option.Config.IPAM == ipamOption.IPAMENI || option.Config.IPAM == ipamOption.IPAMAzure {
			if info := node.GetRouterInfo(); info != nil {
				var ipv4PodSubnets, ipv6PodSubnets []ip.Prefix
				for _, c := range info.GetCIDRs() {
					if c.Addr().Is4() {
						ipv4PodSubnets = append(ipv4PodSubnets, ip.PrefixFrom(c))
					} else {
						ipv6PodSubnets = append(ipv6PodSubnets, ip.PrefixFrom(c))
					}
				}
				// Only derive the pod subnets which have not been explicitly
				// configured.
				if len(option.Config.IPv4PodSubnets) == 0 {
					n.nodeConfig.IPv4PodSubnets = ipv4PodSubnets
				}
				if len(option.Config.IPv6PodSubnets) == 0 {
					n.nodeConfig.IPv6PodSubnets = ipv6PodSubnets
				}
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

// hybridMode reports whether both encapsulation and native routing are enabled,
// meaning route mode is selected per remote pod CIDR (via subnet topology)
// rather than applied globally.
func (n *linuxNodeHandler) hybridMode() bool {
	return n.nodeConfig.EnableEncapsulation && n.nodeConfig.RequiresNativeRouting
}

// localSubnetGroups returns the set of subnet groups that the local node's
// pod CIDRs belong to, per the admin-configured subnet topology.
func (n *linuxNodeHandler) localSubnetGroups() map[uint32]struct{} {
	groups := make(map[uint32]struct{})
	if n.localNodeStore == nil {
		return groups
	}
	ln, err := n.localNodeStore.Get(context.Background())
	if err != nil {
		return groups
	}
	collect := func(prefixes []netip.Prefix) {
		for _, p := range prefixes {
			if !p.IsValid() {
				continue
			}
			if gid := n.lookupSubnetID(p.Addr()); gid != 0 {
				groups[gid] = struct{}{}
			}
		}
	}
	collect(ln.GetIPv4AllocCIDRs())
	collect(ln.GetIPv6AllocCIDRs())
	return groups
}

// classifyRemoteCIDRs partitions prefixes into tunnel- and direct-eligible sets.
// A prefix is direct-eligible iff its subnet group (per admin-configured topology)
// matches one of the local node's groups and auto direct routing is enabled;
// otherwise it is tunnel-eligible (safe default when the group is unknown).
func (n *linuxNodeHandler) classifyRemoteCIDRs(prefixes []netip.Prefix, localGroups map[uint32]struct{}) (tunnel, direct []netip.Prefix) {
	autoDirect := n.nodeConfig.EnableAutoDirectRouting
	for _, prefix := range prefixes {
		if !prefix.IsValid() {
			continue
		}
		if autoDirect {
			if gid := n.lookupSubnetID(prefix.Addr()); gid != 0 {
				if _, ok := localGroups[gid]; ok {
					direct = append(direct, prefix)
					continue
				}
			}
		}
		tunnel = append(tunnel, prefix)
	}
	return
}

// updateHybridRoutes installs tunnel and direct routes to a remote node using
// per-CIDR classification: each of the remote node's pod CIDRs is routed via
// tunnel or directly based on its subnet-group membership relative to the
// local node. Also removes any stale route on the opposite side of the
// classification (in case a CIDR's group changed since the previous update).
func (n *linuxNodeHandler) updateHybridRoutes(oldNode, newNode *nodeTypes.Node, oldIP4, newIP4, oldIP6, newIP6 net.IP, firstAddition, isLocalNode bool) error {
	localGroups := n.localSubnetGroups()
	newTun4, newDir4 := n.classifyRemoteCIDRs(newNode.GetIPv4AllocCIDRs(), localGroups)
	newTun6, newDir6 := n.classifyRemoteCIDRs(newNode.GetIPv6AllocCIDRs(), localGroups)
	var oldTun4, oldDir4, oldTun6, oldDir6 []netip.Prefix
	if oldNode != nil {
		oldTun4, oldDir4 = n.classifyRemoteCIDRs(oldNode.GetIPv4AllocCIDRs(), localGroups)
		oldTun6, oldDir6 = n.classifyRemoteCIDRs(oldNode.GetIPv6AllocCIDRs(), localGroups)
	}

	var errs error
	if err := n.updateOrRemoveNodeRoutes(oldTun4, newTun4, isLocalNode); err != nil {
		errs = errors.Join(errs, fmt.Errorf("hybrid tunnel routes ipv4: %w", err))
	}
	if err := n.updateOrRemoveNodeRoutes(oldTun6, newTun6, isLocalNode); err != nil {
		errs = errors.Join(errs, fmt.Errorf("hybrid tunnel routes ipv6: %w", err))
	}
	if n.nodeConfig.EnableAutoDirectRouting {
		if err := n.updateDirectRoutes(oldDir4, newDir4, oldIP4, newIP4, firstAddition, n.nodeConfig.EnableIPv4, n.nodeConfig.DirectRoutingSkipUnreachable); err != nil {
			errs = errors.Join(errs, fmt.Errorf("hybrid direct routes ipv4: %w", err))
		}
		if err := n.updateDirectRoutes(oldDir6, newDir6, oldIP6, newIP6, firstAddition, n.nodeConfig.EnableIPv6, n.nodeConfig.DirectRoutingSkipUnreachable); err != nil {
			errs = errors.Join(errs, fmt.Errorf("hybrid direct routes ipv6: %w", err))
		}
	}

	// Defensive cleanup: a CIDR's classification may have changed since a prior
	// reconciliation (config edit or agent restart with stale kernel state).
	for _, p := range newDir4 {
		if err := n.deleteNodeRoute(p, isLocalNode); err != nil {
			errs = errors.Join(errs, fmt.Errorf("hybrid stale tunnel route ipv4: %w", err))
		}
	}
	for _, p := range newDir6 {
		if err := n.deleteNodeRoute(p, isLocalNode); err != nil {
			errs = errors.Join(errs, fmt.Errorf("hybrid stale tunnel route ipv6: %w", err))
		}
	}
	if err := n.deleteAllDirectRoutes(newTun4, newIP4); err != nil {
		errs = errors.Join(errs, fmt.Errorf("hybrid stale direct route ipv4: %w", err))
	}
	if err := n.deleteAllDirectRoutes(newTun6, newIP6); err != nil {
		errs = errors.Join(errs, fmt.Errorf("hybrid stale direct route ipv6: %w", err))
	}
	return errs
}

// lookupSubnetID returns the subnet group identity for the given IP address
// by iterating the subnet topology table. Returns 0 if not found.
func (n *linuxNodeHandler) lookupSubnetID(addr netip.Addr) uint32 {
	if n.db == nil || n.subnetTable == nil {
		return 0
	}
	txn := n.db.ReadTxn()
	entry, _, found := n.subnetTable.Get(txn, subnetmap.SubnetLPMIndex.Query(addr))
	if found {
		return entry.Value
	}
	return 0
}

func (n *linuxNodeHandler) OverrideEnableEncapsulation(fn func(*nodeTypes.Node) bool) {
	n.enableEncapsulation = fn
}
