// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"syscall"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/vishvananda/netlink"
	"go4.org/netipx"
	"golang.org/x/sys/unix"
	"golang.org/x/time/rate"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/backoff"
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
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/manager"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	cslices "github.com/cilium/cilium/pkg/slices"
	"github.com/cilium/cilium/pkg/time"
)

const (
	wildcardIPv4             = "0.0.0.0"
	wildcardIPv6             = "0::0"
	linuxNodeRefreshInterval = time.Minute
)

// NeighLink contains the details of a NeighLink
type NeighLink struct {
	Name string `json:"link-name"`
}

type linuxNodeHandler struct {
	log *slog.Logger

	mutex          lock.RWMutex
	isInitialized  bool
	nodeConfig     config.Config
	datapathConfig DatapathConfiguration
	// nodes contains the last successfully reconciled node version. This cannot
	// be recovered from the node table, which only contains the latest desired
	// version, while nodeUpdate needs the previous realized version to remove
	// obsolete datapath state.
	nodes map[nodeTypes.Identity]*nodeTypes.Node
	// pendingNodes contains versions that may have been partially realized by
	// a failed update and therefore also need cleanup if the object is deleted.
	pendingNodes      map[nodeTypes.Identity]*nodeTypes.Node
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

	kprCfg kpr.KPRConfig

	ipsecCfg ipsecTypes.Config

	// configReady is closed after the first NodeConfigurationChanged call. Node
	// reconciliation must not run before the feature configuration it consumes
	// is available.
	configReady chan struct{}
}

var (
	_ node.Handler                      = (*linuxNodeHandler)(nil)
	_ config.ChangeHandler              = (*linuxNodeHandler)(nil)
	_ node.IDHandler                    = (*linuxNodeHandler)(nil)
	_ reconciler.Operations[*node.Node] = (*linuxNodeOps)(nil)
)

type linuxNodeOps struct {
	handler *linuxNodeHandler
}

// RegisterNodeReconciler declares the Linux datapath as a required node
// reconciler during Hive construction.
func RegisterNodeReconciler(writer *node.Writer) {
	writer.RegisterReconciler(node.LinuxNodeReconciler)
}

// NewNodeHandler constructs the Linux node datapath and provides node ID
// lookups.
func NewNodeHandler(
	lifecycle cell.Lifecycle,
	log *slog.Logger,
	tunnelConfig dpTunnel.Config,
	nodeMap nodemap.MapV2,
	nodeConfigNotifier *manager.NodeConfigNotifier,
	kprCfg kpr.KPRConfig,
	ipsecAgent ipsecTypes.Agent,
	localNodeStore *node.LocalNodeStore,
	params reconciler.Params,
	nodes statedb.Table[*node.Node],
	health cell.Health,
	daemonConfig *option.DaemonConfig,
) (node.Handler, node.IDHandler) {
	datapathConfig := DatapathConfiguration{
		HostDevice:   defaults.HostDevice,
		TunnelDevice: tunnelConfig.DeviceName(),
	}

	handler := newNodeHandler(log, datapathConfig, nodeMap, kprCfg, ipsecAgent, fakeipsec.Config{}, localNodeStore)
	checkpoint := newLinuxNodeCheckpoint(
		log,
		health,
		params.DB,
		nodes,
		func(ctx context.Context, restored nodeTypes.Node) error {
			// Pruning may start as soon as the node table is initialized, but the
			// datapath configuration is needed to determine which restored state to
			// remove.
			if err := handler.waitForConfig(ctx); err != nil {
				return err
			}

			handler.mutex.Lock()
			defer handler.mutex.Unlock()
			return handler.nodeDelete(&restored)
		},
		daemonConfig.StateDir,
	)
	nodeTable := nodes.(statedb.RWTable[*node.Node])

	nodeConfigNotifier.Subscribe(handler)

	lifecycle.Append(cell.Hook{
		OnStart: func(_ cell.HookContext) error {
			handler.RestoreNodeIDs()
			if err := checkpoint.start(); err != nil {
				return fmt.Errorf("starting Linux node checkpoint: %w", err)
			}

			params.JobGroup.Add(
				job.OneShot(
					"linux-node-refresh",
					func(ctx context.Context, health cell.Health) error {
						return refreshLinuxNodes(ctx, health, params.DB, nodeTable)
					},
				),
				job.OneShot("linux-node-checkpoint-writer", checkpoint.watch),
				job.OneShot(
					"linux-node-restored-pruning",
					checkpoint.prune,
					job.WithRetry(-1, &job.ExponentialBackoff{
						Min: nodeCheckpointCleanupRetryMin,
						Max: nodeCheckpointCleanupRetryMax,
					}),
				),
			)
			return nil
		},
		OnStop: func(_ cell.HookContext) error {
			if err := checkpoint.stop(); err != nil {
				log.Error("Failed to write final Linux node checkpoint",
					logfields.Error, err,
				)
			}
			return nil
		},
	})
	// Queue the registration after the start hook so restored node IDs and the
	// checkpoint are initialized before reconciliation can begin.
	params.JobGroup.Add(job.OneShot(
		"linux-node-reconciler-registration",
		func(ctx context.Context, _ cell.Health) error {
			if err := handler.waitForConfig(ctx); err != nil {
				return nil
			}

			_, err := reconciler.Register(
				params,
				nodeTable,
				(*node.Node).DeepCopy,
				func(n *node.Node, status reconciler.Status) *node.Node {
					n.Statuses = n.Statuses.Set(node.LinuxNodeReconciler.String(), status)
					return n
				},
				func(n *node.Node) reconciler.Status {
					return n.Statuses.Get(node.LinuxNodeReconciler.String())
				},
				&linuxNodeOps{handler: handler},
				nil,
				reconciler.WithName(node.LinuxNodeReconciler.String()),
				reconciler.WithoutPruning(),
			)
			if err != nil {
				return fmt.Errorf("registering Linux node reconciler: %w", err)
			}
			return nil
		},
	))

	return handler, handler
}

// refreshLinuxNodes periodically refreshes reconciled nodes. This is done
// explicitly instead of with reconciler.WithRefreshing so that the refresh
// interval can grow with the cluster size and nodes can be paced across it.
func refreshLinuxNodes(
	ctx context.Context,
	health cell.Health,
	db *statedb.DB,
	nodes statedb.RWTable[*node.Node],
) error {
	for {
		interval := backoff.ClusterSizeDependantInterval(
			linuxNodeRefreshInterval,
			nodes.NumObjects(db.ReadTxn()),
		)
		startWaiting := time.After(interval)
		refreshLinuxNodesOnce(ctx, db, nodes, interval)

		select {
		case <-ctx.Done():
			return nil
		case <-startWaiting:
		}
		health.OK("Node refresh complete")
	}
}

func refreshLinuxNodesOnce(
	ctx context.Context,
	db *statedb.DB,
	nodes statedb.RWTable[*node.Node],
	interval time.Duration,
) {
	targets := []string{}
	for n := range nodes.All(db.ReadTxn()) {
		targets = append(targets, n.Fullname())
	}
	if len(targets) == 0 {
		return
	}

	limiter := rate.NewLimiter(
		rate.Limit(float64(len(targets))/interval.Seconds()),
		1,
	)
	for _, fullname := range targets {
		if limiter.Wait(ctx) != nil {
			return
		}
		refreshLinuxNode(ctx, db, nodes, fullname)
	}
}

func refreshLinuxNode(
	ctx context.Context,
	db *statedb.DB,
	nodes statedb.RWTable[*node.Node],
	fullname string,
) {
	// marked records whether this invocation transitioned the node to
	// Refreshing, so a later terminal status belongs to this refresh attempt.
	marked := false
	for {
		n, _, watch, found := nodes.GetWatch(db.ReadTxn(), node.NodeByName(fullname))
		if !found {
			return
		}

		kind := n.Statuses.Get(node.LinuxNodeReconciler.String()).Kind
		if marked && (kind == reconciler.StatusKindDone || kind == reconciler.StatusKindError) {
			return
		}
		if !marked && kind == reconciler.StatusKindError {
			// Failed objects are already retried by the reconciler.
			return
		}
		if !marked && kind == reconciler.StatusKindDone {
			wtxn := db.WriteTxn(nodes)
			current, _, found := nodes.Get(wtxn, node.NodeByName(fullname))
			if found && current.Statuses.Get(node.LinuxNodeReconciler.String()).Kind == reconciler.StatusKindDone {
				current = current.DeepCopy()
				current.Statuses = current.Statuses.Set(
					node.LinuxNodeReconciler.String(),
					reconciler.StatusRefreshing(),
				)
				nodes.Insert(wtxn, current)
				wtxn.Commit()
				marked = true
			} else {
				wtxn.Abort()
			}
			continue
		}

		select {
		case <-ctx.Done():
			return
		case <-watch:
		}
	}
}

// newNodeHandler constructs the implementation of Linux node datapath
// operations.
func newNodeHandler(
	log *slog.Logger,
	datapathConfig DatapathConfiguration,
	nodeMap nodemap.MapV2,
	kprCfg kpr.KPRConfig,
	ipsecAgent ipsecTypes.Agent,
	ipsecCfg ipsecTypes.Config,
	localNodeStore *node.LocalNodeStore,
) *linuxNodeHandler {
	return &linuxNodeHandler{
		log:                  log,
		datapathConfig:       datapathConfig,
		nodeConfig:           config.Config{},
		nodes:                map[nodeTypes.Identity]*nodeTypes.Node{},
		pendingNodes:         map[nodeTypes.Identity]*nodeTypes.Node{},
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
		configReady:          make(chan struct{}),
	}
}

func (ops *linuxNodeOps) Update(
	_ context.Context,
	_ statedb.ReadTxn,
	_ statedb.Revision,
	desired *node.Node,
) error {
	n := desired.Node.DeepCopy()
	ops.handler.mutex.Lock()
	defer ops.handler.mutex.Unlock()

	old, found := ops.handler.nodes[n.Identity()]
	if pending, pendingFound := ops.handler.pendingNodes[n.Identity()]; pendingFound && !pending.DeepEqual(n) {
		// Use the last attempted version as old when a newer update supersedes a
		// failed one so partially realized state is removed. Retries of the same
		// version still use the last successful version and reattempt every
		// operation.
		old = pending
		found = true
	}
	if err := ops.handler.nodeUpdate(old, n, !found); err != nil {
		ops.handler.pendingNodes[n.Identity()] = n
		return err
	}
	ops.handler.nodes[n.Identity()] = n
	delete(ops.handler.pendingNodes, n.Identity())
	return nil
}

func (ops *linuxNodeOps) Delete(
	_ context.Context,
	_ statedb.ReadTxn,
	_ statedb.Revision,
	deleted *node.Node,
) error {
	ops.handler.mutex.Lock()
	defer ops.handler.mutex.Unlock()

	identity := deleted.Identity()
	old, found := ops.handler.nodes[identity]
	pending, pendingFound := ops.handler.pendingNodes[identity]
	if !found && !pendingFound {
		return nil
	}

	var errs error
	if pendingFound {
		errs = errors.Join(errs, ops.handler.nodeDelete(pending))
	}
	if found && (!pendingFound || !old.DeepEqual(pending)) {
		errs = errors.Join(errs, ops.handler.nodeDelete(old))
	}
	if errs != nil {
		return errs
	}
	delete(ops.handler.nodes, identity)
	delete(ops.handler.pendingNodes, identity)
	return nil
}

func (*linuxNodeOps) Prune(
	context.Context,
	statedb.ReadTxn,
	iter.Seq2[*node.Node, statedb.Revision],
) error {
	// Deletions are handled incrementally. State restored from nodes.json is
	// pruned separately by linuxNodeCheckpoint once the node table is initialized.
	return nil
}

// waitForConfig prevents reconciliation from running before the datapath
// feature configuration used by nodeUpdate and nodeDelete is available.
func (n *linuxNodeHandler) waitForConfig(ctx context.Context) error {
	select {
	case <-n.configReady:
		return nil
	case <-ctx.Done():
		return ctx.Err()
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

	nodeRoute, err := n.createNodeRouteSpec(prefix, isLocalNode)
	if err != nil {
		return err
	}
	if err := route.Delete(nodeRoute); err != nil {
		// Deletion is retried by the node reconciler and restored-state
		// pruning. A previous attempt may have removed the route before a
		// later operation failed, so an already absent route is success.
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		n.log.Warn("Unable to delete route",
			append(nodeRoute.LogAttrs(), logfields.Error, err)...)
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
		if rt, _ := n.lookupNodeRoute(prefix, isLocalNode); rt != nil {
			if err := n.deleteNodeRoute(prefix, isLocalNode); err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to remove aux route %q: %w", prefix, err))
			}
		}
	}
	return errs
}

func (n *linuxNodeHandler) NodeAdd(nodeTypes.Node) error {
	// Node events are consumed through linuxNodeOps. Keep the legacy callback
	// inert while node.Handler is still provided for explicit validation.
	return nil
}

func (n *linuxNodeHandler) NodeUpdate(nodeTypes.Node, nodeTypes.Node) error {
	// Node events are consumed through linuxNodeOps.
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

func (n *linuxNodeHandler) NodeDelete(nodeTypes.Node) error {
	// Node events are consumed through linuxNodeOps.
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
	if n.nodeConfig.EnableAutoDirectRouting && !n.enableEncapsulation(oldNode) {
		if n.nodeConfig.EnableIPv4 {
			for _, prefix := range oldAllIP4AllocCidrs {
				if err := n.deleteDirectRoute(prefix, oldIP4); err != nil {
					errs = errors.Join(errs, fmt.Errorf("failed to remove old direct routing: deleting old routes: %w", err))
				}
			}
		}
		if n.nodeConfig.EnableIPv6 {
			for _, prefix := range oldAllIP6AllocCidrs {
				if err := n.deleteDirectRoute(prefix, oldIP6); err != nil {
					errs = errors.Join(errs, fmt.Errorf("failed to remove old direct routing: deleting old routes: %w", err))
				}
			}
		}
	}

	if n.enableEncapsulation(oldNode) {
		if n.nodeConfig.EnableIPv4 {
			for _, prefix := range oldAllIP4AllocCidrs {
				if err := n.deleteNodeRoute(prefix, false); err != nil {
					errs = errors.Join(errs, fmt.Errorf("failed to remove old encapsulation config: deleting old single cluster node route for ipv4: %w", err))
				}
			}
		}
		if n.nodeConfig.EnableIPv6 {
			for _, prefix := range oldAllIP6AllocCidrs {
				if err := n.deleteNodeRoute(prefix, false); err != nil {
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
		n.enableEncapsulation = func(*nodeTypes.Node) bool { return n.nodeConfig.EnableEncapsulation }
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

	if !n.isInitialized {
		n.isInitialized = true
		// The reconciler may have observed nodes before the datapath was
		// initialized. Release those operations now that their configuration is
		// available.
		close(n.configReady)
	}

	return nil
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
