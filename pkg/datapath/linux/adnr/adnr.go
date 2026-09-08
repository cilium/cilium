// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package adnr

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	routeReconciler "github.com/cilium/cilium/pkg/datapath/linux/route/reconciler"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
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
	nodeIP net.IP,
	routes statedb.Table[*tables.Route],
	db *statedb.DB,
) bool {
	ip, ok := netip.AddrFromSlice(nodeIP)
	if !ok {
		return false
	}
	// Unmap the IP to ensure IPv4-mapped IPv6 addresses are converted to IPv4.
	ip = ip.Unmap()
	for route := range routes.All(db.ReadTxn()) {
		// we iterate all the routes until we find a directRoute if present
		if isDirectRoute(route, ip) {
			return true
		}
	}
	return false
}

func (h *Handler) getNodeRoutes(nodeName string, nodeIP net.IP, podCIDRs []netip.Prefix) ([]routeReconciler.DesiredRoute, error) {
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
	ip, ok := netip.AddrFromSlice(nodeIP)
	if !ok {
		return nil, fmt.Errorf("invalid node IP for node %q: %v", nodeName, nodeIP)
	}
	for _, prefix := range podCIDRs {
		routes = append(routes, routeReconciler.DesiredRoute{
			Owner:         owner,
			Table:         routeReconciler.TableMain,
			Prefix:        prefix,
			AdminDistance: routeReconciler.AdminDistanceDefault,
			Nexthop:       ip.Unmap(),
		})
	}
	return routes, nil
}

func sameRoute(a, b *routeReconciler.DesiredRoute) bool {
	// we compare only exported fields of the route
	// and we exclude the status.
	return a.AdminDistance == b.AdminDistance &&
		a.Nexthop == b.Nexthop &&
		a.Src == b.Src &&
		reflect.DeepEqual(a.Device, b.Device) &&
		reflect.DeepEqual(a.MultiPath, b.MultiPath) &&
		a.MTU == b.MTU &&
		a.Scope == b.Scope &&
		a.Type == b.Type
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
		if sameRoute(current, &desired) {
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

func (h *Handler) replaceNodeRoutes(n *node.Node) error {
	routes := []routeReconciler.DesiredRoute{}
	nodeName := n.Fullname()
	if h.cfg.EnableIPv4 {
		ipv4Routes, err := h.getNodeRoutes(nodeName, n.GetNodeIP(false), n.GetIPv4AllocCIDRs())
		if err != nil {
			return err
		}
		routes = append(routes, ipv4Routes...)
	}
	if h.cfg.EnableIPv6 {
		ipv6Routes, err := h.getNodeRoutes(nodeName, n.GetNodeIP(true), n.GetIPv6AllocCIDRs())
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
	// Wait for the nodes table to be initialized before processing changes.
	// We do this before the for loop so that after the first batch of changes
	// we are sure, we can finalize the initializer.
	// the route reconciler will delete old routes for us after an agent restart.
	finalized := false
	_, initialized := h.nodes.Initialized(h.db.ReadTxn())
	select {
	case <-ctx.Done():
		return nil
	case <-initialized:
	}

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

	for {
		rtxn := h.db.ReadTxn()
		batch, watch := changes.Next(rtxn)

		for change := range batch {
			h.processNodeWithHealth(change.Object, change.Deleted, degradedMap, health)
		}

		if !finalized {
			h.routeManager.FinalizeInitializer(h.initializer)
			finalized = true
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
		}
	}
}
