// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
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

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/linux/ipsec"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/datapath/linux/route/reconciler"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/tables"
	dpTunnel "github.com/cilium/cilium/pkg/datapath/tunnel"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/idpool"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/nodemap"
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
	nodeConfig        datapath.LocalNodeConfiguration
	datapathConfig    DatapathConfiguration
	nodes             map[nodeTypes.Identity]*nodeTypes.Node
	ipsecUpdateNeeded map[nodeTypes.Identity]bool
	localNodeID       nodeTypes.Identity

	nodeMap nodemap.MapV2
	// Pool of available IDs for nodes.
	nodeIDs *idpool.IDPool
	// Node-scoped unique IDs for the nodes.
	nodeIDsByIPs map[string]uint16
	// reverse map of the above
	nodeIPsByIDs map[uint16]sets.Set[string]

	ipsecMetricCollector prometheus.Collector
	ipsecMetricOnce      sync.Once

	enableEncapsulation func(node *nodeTypes.Node) bool

	kprCfg kpr.KPRConfig

	db                  *statedb.DB
	desiredRouteManager *reconciler.DesiredRouteManager
	desiredRoutes       statedb.Table[*reconciler.DesiredRoute]
	devicesTable        statedb.Table[*tables.Device]
}

var (
	_ datapath.NodeHandler             = (*linuxNodeHandler)(nil)
	_ datapath.NodeConfigChangeHandler = (*linuxNodeHandler)(nil)
	_ datapath.NodeIDHandler           = (*linuxNodeHandler)(nil)
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
	db *statedb.DB,
	desiredRouteManager *reconciler.DesiredRouteManager,
	desiredRoutes statedb.Table[*reconciler.DesiredRoute],
	devicesTable statedb.Table[*tables.Device],
) (datapath.NodeHandler, datapath.NodeIDHandler) {
	datapathConfig := DatapathConfiguration{
		HostDevice:   defaults.HostDevice,
		TunnelDevice: tunnelConfig.DeviceName(),
	}

	handler := newNodeHandler(log, datapathConfig, nodeMap, kprCfg, db, desiredRouteManager, desiredRoutes, devicesTable)

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
	db *statedb.DB,
	desiredRouteManager *reconciler.DesiredRouteManager,
	desiredRoutes statedb.Table[*reconciler.DesiredRoute],
	devicesTable statedb.Table[*tables.Device],
) *linuxNodeHandler {
	return &linuxNodeHandler{
		log:                  log,
		datapathConfig:       datapathConfig,
		nodeConfig:           datapath.LocalNodeConfiguration{},
		nodes:                map[nodeTypes.Identity]*nodeTypes.Node{},
		nodeMap:              nodeMap,
		nodeIDs:              idpool.NewIDPool(minNodeID, maxNodeID),
		nodeIDsByIPs:         map[string]uint16{},
		nodeIPsByIDs:         map[uint16]sets.Set[string]{},
		ipsecMetricCollector: ipsec.NewXFRMCollector(log),
		ipsecUpdateNeeded:    map[nodeTypes.Identity]bool{},
		kprCfg:               kprCfg,
		db:                   db,
		desiredRouteManager:  desiredRouteManager,
		desiredRoutes:        desiredRoutes,
		devicesTable:         devicesTable,
		localNodeID: nodeTypes.Identity{
			Name:    nodeTypes.GetName(),
			Cluster: nodeTypes.GetClusterName(),
		},
	}
}

func (l *linuxNodeHandler) Name() string {
	return "linux-node-datapath"
}

func createDirectRouteSpec(log *slog.Logger, db *statedb.DB, devices statedb.Table[*tables.Device], owner *reconciler.RouteOwner, CIDR *cidr.CIDR, nodeIP net.IP, skipUnreachable bool) (routeSpec reconciler.DesiredRoute, addRoute bool, err error) {
	var routes []netlink.Route
	addRoute = true

	prefix, _ := netipx.FromStdIPNet(CIDR.IPNet)
	routeSpec = reconciler.DesiredRoute{
		Owner:  owner,
		Prefix: prefix,
		Table:  reconciler.TableMain,
	}
	routeSpec.Nexthop, _ = netipx.FromStdIP(nodeIP)

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

	var found bool
	routeSpec.Device, _, found = devices.Get(db.ReadTxn(), tables.DeviceIDIndex.Query(linkIndex))
	if !found {
		err = fmt.Errorf("unable to find device for link index %d", linkIndex)
	}

	return
}

func (n *linuxNodeHandler) updateDirectRoutes(nodeID string, oldCIDRs, newCIDRs []*cidr.CIDR, oldIP, newIP net.IP) error {
	var addedCIDRs, removedCIDRs []*cidr.CIDR
	addedCIDRs, removedCIDRs = cidr.DiffCIDRLists(oldCIDRs, newCIDRs)
	if !oldIP.Equal(newIP) {
		// If the node IP has changed, we want to update all new CIDRs, even if they already existed.
		addedCIDRs = newCIDRs
	}

	n.log.Debug("Updating direct route",
		logfields.NewIP, newIP,
		logfields.OldIP, oldIP,
		logfields.AddedCIDRs, addedCIDRs,
		logfields.RemovedCIDRs, removedCIDRs,
	)

	owner, err := n.desiredRouteManager.GetOrRegisterOwner("node-"+nodeID, reconciler.AdminDistanceDefault)
	if err != nil {
		return fmt.Errorf("failed to get or register route owner for node %q: %w", nodeID, err)
	}

	for _, cidr := range addedCIDRs {
		routeSpec, addroute, err := createDirectRouteSpec(n.log, n.db, n.devicesTable, owner, cidr, newIP, n.nodeConfig.DirectRoutingSkipUnreachable)
		if err != nil {
			return fmt.Errorf("failed to create direct route spec for CIDR %q: %w", cidr, err)
		}

		if addroute {
			if err := n.desiredRouteManager.UpsertRouteWait(routeSpec); err != nil {
				n.log.Warn("Unable to install direct node route",
					logfields.Route, routeSpec,
					logfields.Error, err,
				)

				return err
			}
		}
	}
	if err := n.deleteAllDirectRoutes(nodeID, removedCIDRs); err != nil {
		return fmt.Errorf("failed to delete all direct routes: %w", err)
	}

	return nil
}

func (n *linuxNodeHandler) deleteAllDirectRoutes(nodeID string, CIDRs []*cidr.CIDR) error {
	owner, err := n.desiredRouteManager.GetOrRegisterOwner("node-"+nodeID, reconciler.AdminDistanceDefault)
	if err != nil {
		return fmt.Errorf("failed to get or register owner for node %q: %w", nodeID, err)
	}

	var errs error
	for _, cidr := range CIDRs {
		prefix, _ := netipx.FromStdIPNet(cidr.IPNet)
		err = n.desiredRouteManager.DeleteRoute(reconciler.DesiredRoute{
			Owner:  owner,
			Prefix: prefix,
			Table:  reconciler.TableMain,
		})
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to delete routes for CIDR %q: %w", cidr, err))
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
func (n *linuxNodeHandler) createNodeRouteSpec(owner *reconciler.RouteOwner, hostDevice *tables.Device, prefixCidr *cidr.CIDR, isLocalNode bool) (reconciler.DesiredRoute, error) {
	var (
		local   netip.Addr
		nexthop netip.Addr
		mtu     int
	)

	prefix, _ := netipx.FromStdIPNet(prefixCidr.IPNet)
	if prefix.Addr().Is4() {
		if n.nodeConfig.CiliumInternalIPv4 == nil {
			return reconciler.DesiredRoute{}, fmt.Errorf("IPv4 router address unavailable")
		}

		local, _ = netipx.FromStdIP(n.nodeConfig.CiliumInternalIPv4)
		nexthop = local
	} else {
		if n.nodeConfig.CiliumInternalIPv6 == nil {
			return reconciler.DesiredRoute{}, fmt.Errorf("IPv6 router address unavailable")
		}

		if n.nodeConfig.NodeIPv6 == nil {
			return reconciler.DesiredRoute{}, fmt.Errorf("external IPv6 address unavailable")
		}

		// For ipv6, kernel will reject "ip r a $cidr via $ipv6_cilium_host dev cilium_host"
		// with "Error: Gateway can not be a local address". Instead, we have to remove "via"
		// as "ip r a $cidr dev cilium_host" to make it work.
		local, _ = netipx.FromStdIP(n.nodeConfig.CiliumInternalIPv6)
	}

	if !isLocalNode {
		mtu = n.nodeConfig.RouteMTU
	}

	// The default routing table accounts for encryption overhead for encrypt-node traffic
	return reconciler.DesiredRoute{
		Owner:    owner,
		Table:    reconciler.TableMain,
		Prefix:   prefix,
		Priority: uint32(option.Config.RouteMetric),

		Nexthop: nexthop,
		Src:     local,
		Device:  hostDevice,
		MTU:     uint32(mtu),
	}, nil
}

func (n *linuxNodeHandler) familyEnabled(c *cidr.CIDR) bool {
	return (c.IP.To4() != nil && n.nodeConfig.EnableIPv4) || (c.IP.To4() == nil && n.nodeConfig.EnableIPv6)
}

func (n *linuxNodeHandler) updateOrRemoveNodeRoutes(nodeID string, old, new []*cidr.CIDR, isLocalNode bool) error {
	owner, err := n.desiredRouteManager.GetOrRegisterOwner("node-"+nodeID, reconciler.AdminDistanceDefault)
	if err != nil {
		return fmt.Errorf("failed to get or register route owner for node %q: %w", nodeID, err)
	}

	hostDevice, _, found := n.devicesTable.Get(n.db.ReadTxn(), tables.DeviceNameIndex.Query(n.datapathConfig.HostDevice))
	if !found {
		return fmt.Errorf("host device %q not found in devices table", n.datapathConfig.HostDevice)
	}

	var errs error
	addedRoutes, removedRoutes := cidr.DiffCIDRLists(old, new)
	for _, prefix := range addedRoutes {
		if prefix == nil || !n.familyEnabled(prefix) {
			continue
		}

		nodeRoute, err := n.createNodeRouteSpec(owner, hostDevice, prefix, isLocalNode)
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to create node route spec for %q: %w", prefix, err))
			continue
		}

		err = n.desiredRouteManager.UpsertRouteWait(nodeRoute)
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to upsert node route %q: %w", prefix, err))
			continue
		}
	}
	for _, prefixCidr := range removedRoutes {
		prefix, _ := netipx.FromStdIPNet(prefixCidr.IPNet)
		err = n.desiredRouteManager.DeleteRoute(reconciler.DesiredRoute{
			Table:  reconciler.TableMain,
			Owner:  owner,
			Prefix: prefix,
		})
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to delete node route %q: %w", prefix, err))
			continue
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
		newAllIP4AllocCidrs, newAllIP6AllocCidrs []*cidr.CIDR
		oldIP4, oldIP6                           net.IP
		newIP4, newIP6                           net.IP
		isLocalNode                              = false
	)
	nodeID, err := n.allocateIDForNode(oldNode, newNode)
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to allocate ID for node %s: %w", newNode.Name, err))
	}

	if n.nodeConfig.EnableIPv4 {
		newAllIP4AllocCidrs = newNode.GetIPv4AllocCIDRs()
		newIP4 = newNode.GetNodeIP(false)
	}
	if n.nodeConfig.EnableIPv6 {
		newAllIP6AllocCidrs = newNode.GetIPv6AllocCIDRs()
		newIP6 = newNode.GetNodeIP(true)
	}

	if oldNode != nil {
		if n.nodeConfig.EnableIPv4 {
			oldAllIP4AllocCidrs = oldNode.GetIPv4AllocCIDRs()
			oldIP4 = oldNode.GetNodeIP(false)
		}
		if n.nodeConfig.EnableIPv6 {
			oldAllIP6AllocCidrs = oldNode.GetIPv6AllocCIDRs()
			oldIP6 = oldNode.GetNodeIP(true)
		}

		n.diffAndUnmapNodeIPs(oldNode.IPAddresses, newNode.IPAddresses)
	}

	if n.nodeConfig.EnableIPSec {
		errs = errors.Join(errs, n.enableIPsec(oldNode, newNode, nodeID))
	}

	// Local node update
	if newNode.IsLocal() {
		isLocalNode = true
		if n.nodeConfig.EnableLocalNodeRoute {
			if err := n.updateOrRemoveNodeRoutes(
				newNode.Identity().String(),
				append(oldAllIP4AllocCidrs, oldAllIP6AllocCidrs...),
				append(newAllIP4AllocCidrs, newAllIP6AllocCidrs...),
				isLocalNode); err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to enable local node route: update routes: %w", err))
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

	if n.nodeConfig.EnableAutoDirectRouting && !n.enableEncapsulation(newNode) {
		if n.nodeConfig.EnableIPv4 {
			if err := n.updateDirectRoutes(newNode.Identity().String(), oldAllIP4AllocCidrs, newAllIP4AllocCidrs, oldIP4, newIP4); err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to enable direct routes for ipv4: %w", err))
			}
		}
		if n.nodeConfig.EnableIPv6 {
			if err := n.updateDirectRoutes(newNode.Identity().String(), oldAllIP6AllocCidrs, newAllIP6AllocCidrs, oldIP6, newIP6); err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to enable direct routes for ipv6: %w", err))
			}
		}
		return errs
	}

	if n.enableEncapsulation(newNode) {
		if err := n.updateOrRemoveNodeRoutes(
			newNode.Identity().String(),
			append(oldAllIP4AllocCidrs, oldAllIP6AllocCidrs...),
			append(newAllIP4AllocCidrs, newAllIP6AllocCidrs...),
			isLocalNode); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to enable encapsulation: single cluster routes: %w", err))
		}

		return errs
	} else if firstAddition {
		owner, err := n.desiredRouteManager.GetOrRegisterOwner("node-"+newNode.Identity().String(), reconciler.AdminDistanceDefault)
		if err != nil {
			return fmt.Errorf("failed to get or register route owner for node %q: %w", nodeID, err)
		}

		for _, allocCIDR := range append(newAllIP4AllocCidrs, newAllIP6AllocCidrs...) {
			allocPrefix, _ := netipx.FromStdIPNet(allocCIDR.IPNet)
			err = n.desiredRouteManager.DeleteRoute(reconciler.DesiredRoute{
				Owner:    owner,
				Table:    reconciler.TableMain,
				Prefix:   allocPrefix,
				Priority: uint32(option.Config.RouteMetric),
			})
			if err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to delete node route %q: %w", allocCIDR, err))
				continue
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

	var errs error
	if owner, err := n.desiredRouteManager.GetOwner("node-" + oldNode.Identity().String()); err == nil {
		n.desiredRouteManager.RemoveOwner(owner)
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

	if err := n.updateOrRemoveNodeRoutes(n.localNodeID.String(), prevConfig.AuxiliaryPrefixes, newConfig.AuxiliaryPrefixes, true); err != nil {
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
		if err := n.removeEncryptRules(); err != nil {
			n.log.Warn("Cannot cleanup previous encryption rule state.", logfields.Error, err)
		}
		if err := ipsec.DeleteXFRM(n.log, ipsec.AllReqID); err != nil {
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

func (n *linuxNodeHandler) OverrideEnableEncapsulation(fn func(*nodeTypes.Node) bool) {
	n.enableEncapsulation = fn
}
