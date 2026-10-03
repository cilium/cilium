// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/bgp/agent/signaler"
	"github.com/cilium/cilium/pkg/bgp/config"
	"github.com/cilium/cilium/pkg/bgp/manager/instance"
	"github.com/cilium/cilium/pkg/bgp/types"
	"github.com/cilium/cilium/pkg/datapath/tables"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// DefaultGatewayReconciler is a ConfigReconciler which handles auto-discovery
// of peer addresses: DefaultGateway mode (from the default route) and
// Unnumbered mode (the peer's IPv6 link-local address, from the neighbor table,
// on the configured interface). It runs with the highest priority to ensure peer
// addresses are populated before other reconcilers run.
type DefaultGatewayReconciler struct {
	logger        *slog.Logger
	DB            *statedb.DB
	routeTable    statedb.Table[*tables.Route]
	deviceTable   statedb.Table[*tables.Device]
	neighborTable statedb.Table[*tables.Neighbor]

	// mu protects discoveryFailed and unnumberedLinks.
	mu lock.Mutex
	// discoveryFailed holds the peers whose unnumbered interface or peer address
	// could not be discovered, keyed by instance and peer name. It exists so the
	// failure - a silently unconfigured peer otherwise - is logged loudly once
	// per occurrence instead of on every reconciliation round.
	discoveryFailed map[string]struct{}
	// unnumberedLinks holds the index of the link each unnumbered peer peers
	// over, keyed by instance and peer name. The neighbor table sees every
	// neighbor on the node, so it is what narrows the change observer down to
	// the handful of links an unnumbered peer address can come from.
	unnumberedLinks map[string]int
}

type DefaultGatewayReconcilerOut struct {
	cell.Out

	Reconciler ConfigReconciler `group:"bgp-config-reconciler"`
}

type DefaultGatewayReconcilerIn struct {
	cell.In

	Logger        *slog.Logger
	BGPConfig     config.BGPConfig
	DB            *statedb.DB
	JobGroup      job.Group
	Signaler      *signaler.BGPCPSignaler
	RouteTable    statedb.Table[*tables.Route]
	DeviceTable   statedb.Table[*tables.Device]
	NeighborTable statedb.Table[*tables.Neighbor]
}

var (
	ipv4Default = netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	ipv6Default = netip.PrefixFrom(netip.IPv6Unspecified(), 0)
)

func NewDefaultGatewayReconciler(p DefaultGatewayReconcilerIn) DefaultGatewayReconcilerOut {
	if !p.BGPConfig.BGPControlPlaneEnabled() {
		return DefaultGatewayReconcilerOut{}
	}

	logger := p.Logger.With(types.ReconcilerLogField, "DefaultGateway")

	// Add job observers for route and device change tracking
	p.JobGroup.Add(
		job.Observer("default-gateway-route-change-tracker",
			routeChangeTrackerObserver(p.Signaler, logger),
			statedb.Observable(p.DB, p.RouteTable)),
	)

	p.JobGroup.Add(
		job.Observer("device-change-device-change-tracker",
			deviceChangeTrackerObserver(p.Signaler, logger),
			statedb.Observable(p.DB, p.DeviceTable)),
	)

	r := &DefaultGatewayReconciler{
		logger:          logger,
		DB:              p.DB,
		routeTable:      p.RouteTable,
		deviceTable:     p.DeviceTable,
		neighborTable:   p.NeighborTable,
		discoveryFailed: make(map[string]struct{}),
		unnumberedLinks: make(map[string]int),
	}

	p.JobGroup.Add(
		job.Observer("default-gateway-neighbor-change-tracker",
			r.neighborChangeTrackerObserver(p.Signaler, logger),
			statedb.Observable(p.DB, p.NeighborTable)),
	)

	return DefaultGatewayReconcilerOut{Reconciler: r}
}

func (r *DefaultGatewayReconciler) Name() string {
	return DefaultGatewayReconcilerName
}

// Priority of default gateway reconciler is lower than pod cidr reconciler.
// This is so that pod cidr does not skip setting the policy due to peer address not being set.
func (r *DefaultGatewayReconciler) Priority() int {
	return DefaultGatewayReconcilerPriority
}

func (r *DefaultGatewayReconciler) Init(i *instance.BGPInstance) error {
	if i == nil {
		return fmt.Errorf("BUG: default gateway reconciler initialization with nil BGPInstance")
	}
	return nil
}

func (r *DefaultGatewayReconciler) Cleanup(i *instance.BGPInstance) {
	if i == nil {
		return
	}
	prefix := i.Name + "/"
	r.mu.Lock()
	defer r.mu.Unlock()
	maps.DeleteFunc(r.discoveryFailed, func(key string, _ struct{}) bool {
		return strings.HasPrefix(key, prefix)
	})
	maps.DeleteFunc(r.unnumberedLinks, func(key string, _ int) bool {
		return strings.HasPrefix(key, prefix)
	})
}

func (r *DefaultGatewayReconciler) Reconcile(ctx context.Context, p ReconcileParams) error {
	if err := p.ValidateParams(); err != nil {
		return err
	}

	l := r.logger.With(types.InstanceLogField, p.DesiredConfig.Name)

	// The links this instance's unnumbered peers are discovered on, rebuilt from
	// scratch every round and installed at the end so a peer that goes away, or moves
	// to another interface, stops being watched.
	unnumberedLinks := make(map[string]int)
	defer func() { r.setUnnumberedLinks(p.DesiredConfig.Name, unnumberedLinks) }()

	for i, peer := range p.DesiredConfig.Peers {
		if peer.PeerAddress != nil || peer.AutoDiscovery == nil {
			continue
		}

		switch peer.AutoDiscovery.Mode {
		case v2.BGPDefaultGatewayMode:
			defaultGateway, err := r.getDefaultGateway(peer.AutoDiscovery.DefaultGateway)
			if err != nil {
				l.Debug("Failed to get default gateway, skipping",
					logfields.Error, err)
				continue
			}

			p.DesiredConfig.Peers[i].PeerAddress = &defaultGateway

			l.Debug("Auto-discovered peer address",
				types.PeerLogField, peer.Name,
				logfields.Address, defaultGateway)
		case v2.BGPUnnumberedMode:
			if peer.AutoDiscovery.Unnumbered == nil {
				l.Debug("Unnumbered mode set without unnumbered configuration, skipping",
					types.PeerLogField, peer.Name)
				continue
			}

			// BGP unnumbered: the peer is not configured with an address at all,
			// it is reached over an interface at whatever IPv6 link-local address
			// Neighbor Discovery learned for it.
			iface := peer.AutoDiscovery.Unnumbered.Interface

			// Set the interface even if the peer address cannot be resolved yet:
			// the UnnumberedRAReconciler keys the Router Advertisements it sends
			// off it, and those are what let the peer learn this node's own
			// link-local address.
			p.DesiredConfig.Peers[i].PeerInterface = &iface

			peerAddress, linkIndex, err := r.getUnnumberedPeerAddress(iface)
			if linkIndex != 0 {
				// Watch the link even when no address could be resolved on it,
				// which is the common case on startup: the neighbor entry
				// appearing is what triggers the round that configures the peer.
				unnumberedLinks[p.DesiredConfig.Name+"/"+peer.Name] = linkIndex
			}
			if err != nil {
				r.reportDiscoveryFailure(l, p.DesiredConfig.Name, peer.Name, err)
				continue
			}

			r.clearDiscoveryFailure(l, p.DesiredConfig.Name, peer.Name)
			p.DesiredConfig.Peers[i].PeerAddress = &peerAddress

			l.Debug("Discovered unnumbered peer",
				types.PeerLogField, peer.Name,
				logfields.Interface, iface,
				logfields.Address, peerAddress)
		default:
			l.Debug("Unsupported auto-discovery mode",
				types.PeerLogField, peer.Name,
				logfields.Mode, peer.AutoDiscovery.Mode)
			continue
		}
	}

	return nil
}

// getDefaultGateway returns the default gateway address with lower priority using route and device
// statedb tables and the provided default gateway configuration.
func (r *DefaultGatewayReconciler) getDefaultGateway(defaultGateway *v2.DefaultGateway) (string, error) {
	var defaultRoute netip.Prefix
	switch defaultGateway.AddressFamily {
	case "ipv4":
		defaultRoute = ipv4Default
	case "ipv6":
		defaultRoute = ipv6Default
	default:
		return "", fmt.Errorf("invalid address family %s", defaultGateway.AddressFamily)
	}

	txn := r.DB.ReadTxn()
	// get routes from statedb route table
	// TODO: add RoutePrefixIndex Query to lookup routes by prefix
	routes := r.routeTable.All(txn)
	activeDefaultRoutes := []*tables.Route{}

	for route := range routes {
		// ignore routes that are not default routes or do not have a valid gateway
		if !route.Gw.IsValid() || route.Dst != defaultRoute {
			continue
		}
		// Only the main table holds the node's default gateway. Other tables
		// routinely hold their own default routes - Cilium itself installs a
		// "default via <cilium_host>" one, and a local table can hold a metric-0
		// "default dev lo" - which are not the way off the node and would
		// outrank the real default route, as they are usually installed with a
		// lower metric. Non-unicast types (local, blackhole, unreachable,
		// prohibit) do not forward anything either.
		if route.Table != tables.RT_TABLE_MAIN || route.Type != tables.RTN_UNICAST {
			continue
		}
		dev, _, found := r.deviceTable.Get(txn, tables.DeviceByIndex(route.LinkIndex))
		// ignore routes if the link through which it is reachable is not up
		if !found || dev.OperStatus != "up" {
			continue
		}
		if route.Gw.IsLinkLocalUnicast() {
			r.logger.Warn("link local address is not supported for default gateway mode of bgp auto-discovery",
				logfields.Gateway, route.Gw,
			)
			continue
		}
		activeDefaultRoutes = append(activeDefaultRoutes, route)
	}

	if len(activeDefaultRoutes) == 0 {
		return "", fmt.Errorf("no active default route found")
	}

	// return the gateway address with lowest priority
	return slices.MinFunc(activeDefaultRoutes, func(r0, r1 *tables.Route) int {
		return cmp.Compare(r0.Priority, r1.Priority)
	}).Gw.String(), nil
}

// getUnnumberedPeerAddress returns the address of the unnumbered peer reached over ifname:
// the IPv6 link-local address the node's Neighbor Discovery learned for it, zoned with the
// interface (e.g. "fe80::1%eth0"), as a link-local address has to be to be dialable. The
// index of the link it was looked for on is returned alongside, for the caller to watch.
//
// The neighbor entries are read from the neighbors table rather than resolved with a one-shot
// netlink call - which is what gobgp's own NeighborInterface support does - so that a peer
// whose entry is not in the cache yet, or which comes back with a different link-local
// address, is picked up by the reconciliation neighborChangeTrackerObserver triggers.
func (r *DefaultGatewayReconciler) getUnnumberedPeerAddress(ifname string) (string, int, error) {
	txn := r.DB.ReadTxn()

	dev, _, found := r.deviceTable.Get(txn, tables.DeviceByName(ifname))
	if !found {
		return "", 0, fmt.Errorf("interface %s not found", ifname)
	}

	var candidates, routers []netip.Addr
	for neigh := range r.neighborTable.List(txn, tables.NeighborsByLinkIndex(dev.Index)) {
		if !isUnnumberedPeerNeighbor(neigh, dev) {
			continue
		}
		candidates = append(candidates, neigh.IPAddr)
		if neigh.Flags&tables.NTF_ROUTER != 0 {
			routers = append(routers, neigh.IPAddr)
		}
	}
	// The peer of an unnumbered session is a router, and announces itself as one in the
	// Router Advertisements the node learns its link-local address from. Preferring the
	// neighbors flagged as such keeps the link usable when it carries more than the peer,
	// while still falling back to every neighbor for a peer that sends no RAs.
	if len(routers) > 0 {
		candidates = routers
	}

	switch len(candidates) {
	case 0:
		return "", dev.Index, fmt.Errorf("no IPv6 link-local neighbor discovered on interface %s", ifname)
	case 1:
		return candidates[0].WithZone(ifname).String(), dev.Index, nil
	default:
		// An unnumbered session is point-to-point, so several candidates leave no way to
		// tell which one the peer is. Guessing would peer with an arbitrary neighbor.
		slices.SortFunc(candidates, func(a, b netip.Addr) int { return a.Compare(b) })
		return "", dev.Index, fmt.Errorf("found %d IPv6 link-local neighbors on interface %s (%v), only point-to-point links are supported",
			len(candidates), ifname, candidates)
	}
}

// isUnnumberedPeerNeighbor reports whether a neighbor table entry can be the address of an
// unnumbered BGP peer.
func isUnnumberedPeerNeighbor(neigh *tables.Neighbor, dev *tables.Device) bool {
	if !neigh.IPAddr.Is6() || !neigh.IPAddr.IsLinkLocalUnicast() {
		return false
	}
	// A failed entry is a neighbor that did not answer, there is no point dialing it.
	if neigh.State&tables.NUD_FAILED != 0 {
		return false
	}
	// The link's own addresses are not peers. The kernel does not normally cache them as
	// neighbors, so this is just belt and braces.
	for _, addr := range dev.Addrs {
		if addr.Addr == neigh.IPAddr {
			return false
		}
	}
	return true
}

// setUnnumberedLinks replaces the links watched on behalf of an instance's unnumbered peers,
// which is what narrows neighborChangeTrackerObserver down to the neighbors that matter.
func (r *DefaultGatewayReconciler) setUnnumberedLinks(instanceName string, links map[string]int) {
	prefix := instanceName + "/"

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.unnumberedLinks == nil {
		r.unnumberedLinks = make(map[string]int)
	}
	maps.DeleteFunc(r.unnumberedLinks, func(key string, _ int) bool {
		return strings.HasPrefix(key, prefix)
	})
	maps.Copy(r.unnumberedLinks, links)
}

// watchesLink reports whether any unnumbered peer discovers its address on the given link.
func (r *DefaultGatewayReconciler) watchesLink(linkIndex int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, watched := range r.unnumberedLinks {
		if watched == linkIndex {
			return true
		}
	}
	return false
}

// reportDiscoveryFailure logs that an unnumbered peer could not be discovered, either because
// its interface could not be derived from the default route or because no peer address could
// be resolved on that interface. The peer is left unconfigured, which is expected transiently
// (the default route may not be installed and the peer may not have been discovered yet) but
// is a configuration error if it persists, so the first occurrence is logged at Warn and the
// repeats at Debug.
func (r *DefaultGatewayReconciler) reportDiscoveryFailure(l *slog.Logger, instanceName, peerName string, err error) {
	key := instanceName + "/" + peerName

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, reported := r.discoveryFailed[key]; reported {
		l.Debug("Failed to discover unnumbered peer, skipping",
			types.PeerLogField, peerName,
			logfields.Error, err)
		return
	}
	if r.discoveryFailed == nil {
		r.discoveryFailed = make(map[string]struct{})
	}
	r.discoveryFailed[key] = struct{}{}

	l.Warn("Failed to discover unnumbered peer, peer is not configured",
		types.PeerLogField, peerName,
		logfields.Error, err)
}

// clearDiscoveryFailure resets the state kept by reportDiscoveryFailure for a peer, logging the
// recovery if the peer was previously failing.
func (r *DefaultGatewayReconciler) clearDiscoveryFailure(l *slog.Logger, instanceName, peerName string) {
	key := instanceName + "/" + peerName

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, reported := r.discoveryFailed[key]; !reported {
		return
	}
	delete(r.discoveryFailed, key)

	l.Info("Discovered unnumbered peer again",
		types.PeerLogField, peerName)
}

// routeChangeTrackerObserver triggers BGP reconciliation when there is a change in IPv4 or IPv6 default route
func routeChangeTrackerObserver(signaler *signaler.BGPCPSignaler, logger *slog.Logger) job.ObserverFunc[statedb.Change[*tables.Route]] {
	return func(ctx context.Context, event statedb.Change[*tables.Route]) error {
		route := event.Object
		// check for default route change
		if route.Dst == ipv4Default ||
			route.Dst == ipv6Default {
			// trigger reconciliation for default route changes
			signaler.Event(struct{}{})
			logger.Debug("Default route change detected, triggering BGP reconciliation")
		}
		return nil
	}
}

// neighborChangeTrackerObserver triggers BGP reconciliation when an IPv6 link-local neighbor
// changes on a link an unnumbered peer is discovered on, as that is where the peer's address
// comes from. The neighbors table holds every neighbor on the node, most of which have nothing
// to do with BGP, so both filters are needed to keep unrelated neighbor churn - every ND state
// transition of every pod - from signaling a reconciliation.
func (r *DefaultGatewayReconciler) neighborChangeTrackerObserver(signaler *signaler.BGPCPSignaler, logger *slog.Logger) job.ObserverFunc[statedb.Change[*tables.Neighbor]] {
	return func(ctx context.Context, event statedb.Change[*tables.Neighbor]) error {
		neigh := event.Object
		if !neigh.IPAddr.Is6() || !neigh.IPAddr.IsLinkLocalUnicast() || !r.watchesLink(neigh.LinkIndex) {
			return nil
		}
		signaler.Event(struct{}{})
		logger.Debug("Link-local neighbor change detected on an unnumbered peering interface, triggering BGP reconciliation",
			logfields.Neighbor, neigh)
		return nil
	}
}

// deviceChangeTrackerObserver triggers BGP reconciliation when there is a change in the device table
func deviceChangeTrackerObserver(signaler *signaler.BGPCPSignaler, logger *slog.Logger) job.ObserverFunc[statedb.Change[*tables.Device]] {
	return func(ctx context.Context, event statedb.Change[*tables.Device]) error {
		// trigger reconciliation for device changes
		signaler.Event(struct{}{})
		logger.Debug("Device change detected, triggering BGP reconciliation")
		return nil
	}
}
