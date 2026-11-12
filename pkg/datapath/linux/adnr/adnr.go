// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package adnr

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	routeReconciler "github.com/cilium/cilium/pkg/datapath/linux/route/reconciler"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/logging/logfields"
	subnetmap "github.com/cilium/cilium/pkg/maps/subnet"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

func getOwnerName(nodeName string) string {
	const adnrOwnerPrefix = "adnr/"
	return adnrOwnerPrefix + nodeName
}

func deleteNodeRoutes(rm *routeReconciler.DesiredRouteManager, nodeName string) error {
	owner, err := rm.GetOwner(getOwnerName(nodeName))
	if err != nil {
		if errors.Is(err, routeReconciler.ErrOwnerDoesNotExist) {
			return nil
		}
		return fmt.Errorf("getting route owner for node %s: %w", nodeName, err)
	}
	return rm.RemoveOwner(owner)
}

func isDirectRoute(route *tables.Route, ip netip.Addr) bool {
	// `route.Gw == ip` is kept as a defensive check, see:
	// https://github.com/cilium/cilium/pull/8513
	return route.Dst.Contains(ip) &&
		(!route.Gw.IsValid() || route.Gw == ip)
}

func isNodeOnSameL2(
	nodeIP netip.Addr,
	routes statedb.Table[*tables.Route],
	db *statedb.DB,
) bool {
	for route := range routes.All(db.ReadTxn()) {
		// we iterate all the routes until we find a directRoute if present
		if isDirectRoute(route, nodeIP) {
			return true
		}
	}
	return false
}

func (h *Handler) getNodeRoutes(nodeName string, nodeIP netip.Addr, podCIDRs []netip.Prefix) ([]routeReconciler.DesiredRoute, error) {
	if len(podCIDRs) == 0 {
		return nil, nil
	}

	if !isNodeOnSameL2(nodeIP, h.routes, h.db) {
		if h.cfg.DirectRoutingSkipUnreachable {
			h.logger.Debug(
				"route to destination is not reachable, skipping it",
				logfields.NodeName, nodeName,
			)
			return nil, nil
		} else {
			return nil, fmt.Errorf("route to node %s is not reachable. Add `direct-routing-skip-unreachable` to skip unreachable routes", nodeName)
		}
	}

	owner, err := h.routeManager.GetOrRegisterOwner(getOwnerName(nodeName))
	if err != nil {
		return nil, fmt.Errorf("registering route owner for node %s: %w", nodeName, err)
	}

	routes := make([]routeReconciler.DesiredRoute, 0, len(podCIDRs))
	for _, prefix := range podCIDRs {
		routes = append(routes, routeReconciler.DesiredRoute{
			Owner:         owner,
			Table:         routeReconciler.TableMain,
			Prefix:        prefix,
			AdminDistance: routeReconciler.AdminDistanceDefault,
			Nexthop:       nodeIP,
		})
	}
	return routes, nil
}

func (h *Handler) replaceOwnerRoutes(owner *routeReconciler.RouteOwner, newRoutes []routeReconciler.DesiredRoute) error {
	desiredRoutes := make(map[routeReconciler.DesiredRouteKey]routeReconciler.DesiredRoute, len(newRoutes))
	for _, route := range newRoutes {
		desiredRoutes[route.GetFullKey()] = route
	}

	currentRoutes := slices.Collect(statedb.ToSeq(h.desiredRoutes.Prefix(
		h.db.ReadTxn(),
		routeReconciler.DesiredRouteIndex.Query(routeReconciler.DesiredRouteKey{Owner: owner}),
	)))
	for _, current := range currentRoutes {
		desired, exists := desiredRoutes[current.GetFullKey()]
		if !exists {
			// this is an old route we just delete it
			if err := h.routeManager.DeleteRoute(*current); err != nil {
				return err
			}
			continue
		}
		// We have an existing route that matches the desired route key.
		// Check if we need an update or if it is the same.
		// In any case we delete it from the desired routes map so that
		// we don't add it again.
		delete(desiredRoutes, current.GetFullKey())
		if current.SameSpec(&desired) {
			continue
		}
		if err := h.routeManager.UpsertRoute(desired); err != nil {
			return err
		}
	}

	for _, route := range desiredRoutes {
		if err := h.routeManager.UpsertRoute(route); err != nil {
			return err
		}
	}
	return nil
}

func (h *Handler) subnetGroup(addr netip.Addr) uint32 {
	if h.subnetTable == nil {
		return 0
	}
	entry, _, found := h.subnetTable.Get(h.db.ReadTxn(), subnetmap.SubnetLPMIndex.Query(addr))
	if !found {
		return 0
	}
	return entry.Value
}

func (h *Handler) getNodeCIDRs(n *node.Node) ([]netip.Prefix, []netip.Prefix, error) {
	if h.cfg.RoutingMode != option.RoutingModeHybrid {
		// When we are not in hybrid routing mode, if the node is reachable
		// on the same L2 network, we use all its Pod CIDRs.
		return n.GetIPv4AllocCIDRs(), n.GetIPv6AllocCIDRs(), nil
	}
	// In hybrid routing mode, even if the node is reachable on the same L2 network,
	// we only consider the direct Pod CIDRs that share a subnet group with the local node.
	local, _, found := h.nodes.Get(h.db.ReadTxn(), node.LocalNodeQuery)
	if !found {
		return nil, nil, fmt.Errorf("local node not found in hybrid routing mode")
	}

	// get local groups
	groups := make(map[uint32]struct{})
	for _, prefix := range append(local.GetIPv4AllocCIDRs(),
		local.GetIPv6AllocCIDRs()...) {
		if group := h.subnetGroup(prefix.Addr()); group != 0 {
			groups[group] = struct{}{}
		}
	}

	selectDirect := func(prefixes []netip.Prefix) []netip.Prefix {
		result := make([]netip.Prefix, 0, len(prefixes))
		for _, prefix := range prefixes {
			if _, found := groups[h.subnetGroup(prefix.Addr())]; found {
				result = append(result, prefix)
			}
		}
		return result
	}
	return selectDirect(n.GetIPv4AllocCIDRs()), selectDirect(n.GetIPv6AllocCIDRs()), nil
}

func (h *Handler) replaceNodeRoutes(n *node.Node) error {
	routes := []routeReconciler.DesiredRoute{}
	nodeName := n.Fullname()
	ipv4CIDRs, ipv6CIDRs, err := h.getNodeCIDRs(n)
	if err != nil {
		return err
	}
	if h.cfg.EnableIPv4 {
		// Unmap the IP to ensure IPv4-mapped IPv6 addresses are converted to IPv4.
		ipv4Routes, err := h.getNodeRoutes(nodeName, n.GetNodeIP(false).Unmap(), ipv4CIDRs)
		if err != nil {
			return err
		}
		routes = append(routes, ipv4Routes...)
	}
	if h.cfg.EnableIPv6 {
		ipv6Routes, err := h.getNodeRoutes(nodeName, n.GetNodeIP(true).Unmap(), ipv6CIDRs)
		if err != nil {
			return err
		}
		routes = append(routes, ipv6Routes...)
	}
	owner, err := h.routeManager.GetOrRegisterOwner(getOwnerName(nodeName))
	if err != nil {
		return fmt.Errorf("registering route owner for node %s: %w", nodeName, err)
	}
	return h.replaceOwnerRoutes(owner, routes)
}

func (h *Handler) processNodeChange(node *node.Node, isDeleted bool) error {
	if node.IsLocal() {
		// if the node is local, we don't need to add or remove routes for it.
		return nil
	}

	// here we always use `false` as default value because, with ADNR, encapsulation is disabled by default.
	// Only in case of explicit override we skip the node.
	if isDeleted || h.nodePolicy.EnableEncapsulation(&node.Node, false) {
		// just to be sure we delete any existing route for this node
		return deleteNodeRoutes(h.routeManager, node.Fullname())
	}
	return h.replaceNodeRoutes(node)
}

func updateHealth(health cell.Health, degradedMap map[string]cell.Health) {
	if len(degradedMap) == 0 {
		health.OK("Auto-direct-node-routes synchronized")
		return
	}
	health.Degraded(
		"failed to update Auto-direct-node-routes for one or more nodes",
		fmt.Errorf("%d failed nodes", len(degradedMap)),
	)
}

func (h *Handler) processNodeWithHealth(
	n *node.Node,
	deleted bool,
	degradedMap map[string]cell.Health,
	health cell.Health,
) {
	name := n.Fullname()
	if err := h.processNodeChange(n, deleted); err != nil {
		reporter, ok := degradedMap[name]
		if !ok {
			reporter = health.NewScope(name)
			degradedMap[name] = reporter
		}
		reporter.Degraded("failed to update node routes", err)
		return
	}

	// In case of successful processing, remove the health err if exists.
	if reporter, ok := degradedMap[name]; ok {
		reporter.Close()
		delete(degradedMap, name)
	}
}

func (h *Handler) run(ctx context.Context, health cell.Health) error {
	finalized := false

	wtxn := h.db.WriteTxn(h.nodes)
	changes, err := h.nodes.Changes(wtxn)
	if err != nil {
		wtxn.Abort()
		return fmt.Errorf("subscribing to node changes: %w", err)
	}
	wtxn.Commit()
	defer changes.Close()

	degradedMap := make(map[string]cell.Health)
	defer func() {
		for _, reporter := range degradedMap {
			reporter.Close()
		}
	}()

	var initializedWatch <-chan struct{}
	for {
		rtxn := h.db.ReadTxn()
		batch, watch := changes.Next(rtxn)

		for change := range batch {
			h.processNodeWithHealth(change.Object, change.Deleted, degradedMap, health)
		}

		if !finalized {
			// we cannot wait for the node table to be initialized
			// before starting the loop because other components need
			// the route information before marking the node table as
			// initialized (e.g. clustermesh). What we do instead is check
			// for initialization within the loop and finalize
			// the route manager once the node table is initialized.
			initialized, watch := h.nodes.Initialized(rtxn)
			if initialized {
				h.routeManager.FinalizeInitializer(h.initializer)
				finalized = true
				initializedWatch = nil
			} else {
				initializedWatch = watch
			}
		}

		updateHealth(health, degradedMap)

		// Give cancellation priority over a continuously ready watch.
		if ctx.Err() != nil {
			return nil
		}

		select {
		case <-ctx.Done():
			return nil
		case <-watch:
		case <-initializedWatch:
		}
	}
}
