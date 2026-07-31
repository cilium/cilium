// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/bgp/agent/signaler"
	"github.com/cilium/cilium/pkg/bgp/manager/instance"
	"github.com/cilium/cilium/pkg/bgp/types"
	"github.com/cilium/cilium/pkg/datapath/tables"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

// DefaultGatewayReconciler is a ConfigReconciler which handles auto-discovery
// of peer addresses: DefaultGateway mode (from the default route) and
// Unnumbered mode (hands an interface to gobgp, which resolves the peer's IPv6
// link-local via ND itself; the interface is either configured explicitly or
// discovered as the one the default route egresses). It runs with the highest
// priority to ensure peer addresses are populated before other reconcilers run.
type DefaultGatewayReconciler struct {
	logger      *slog.Logger
	DB          *statedb.DB
	routeTable  statedb.Table[*tables.Route]
	deviceTable statedb.Table[*tables.Device]

	// mu protects derivationFailed.
	mu sync.Mutex
	// derivationFailed holds the peers whose unnumbered interface could not be
	// derived from the default route, keyed by instance and peer name. It exists
	// so the failure - a silently unconfigured peer otherwise - is logged loudly
	// once per occurrence instead of on every reconciliation round.
	derivationFailed map[string]struct{}
}

type DefaultGatewayReconcilerOut struct {
	cell.Out

	Reconciler ConfigReconciler `group:"bgp-config-reconciler"`
}

type DefaultGatewayReconcilerIn struct {
	cell.In

	Logger       *slog.Logger
	DaemonConfig *option.DaemonConfig
	DB           *statedb.DB
	JobGroup     job.Group
	Signaler     *signaler.BGPCPSignaler
	RouteTable   statedb.Table[*tables.Route]
	DeviceTable  statedb.Table[*tables.Device]
}

var (
	ipv4Default = netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	ipv6Default = netip.PrefixFrom(netip.IPv6Unspecified(), 0)
)

func NewDefaultGatewayReconciler(p DefaultGatewayReconcilerIn) DefaultGatewayReconcilerOut {
	if !p.DaemonConfig.BGPControlPlaneEnabled() {
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

	return DefaultGatewayReconcilerOut{
		Reconciler: &DefaultGatewayReconciler{
			logger:           logger,
			DB:               p.DB,
			routeTable:       p.RouteTable,
			deviceTable:      p.DeviceTable,
			derivationFailed: make(map[string]struct{}),
		},
	}
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
	maps.DeleteFunc(r.derivationFailed, func(key string, _ struct{}) bool {
		return strings.HasPrefix(key, prefix)
	})
}

func (r *DefaultGatewayReconciler) Reconcile(ctx context.Context, p ReconcileParams) error {
	if err := p.ValidateParams(); err != nil {
		return err
	}

	l := r.logger.With(types.InstanceLogField, p.DesiredConfig.Name)

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
			// BGP unnumbered: the peer is identified by an interface only. Hand
			// that interface to gobgp (PeerInterface, no PeerAddress) and let
			// gobgp's native unnumbered path resolve the peer's IPv6 link-local
			// from the kernel ND table AND derive the local link-local as the
			// transport source address. Resolving in the agent instead (setting a
			// zoned PeerAddress) skips gobgp's local-source derivation, so gobgp
			// never dials the peer. This relies on the gobgp AddPeer fix that runs
			// SetDefaultNeighborConfigValues (interface resolution) before
			// validating the neighbor address; without it an addressless neighbor
			// is rejected with "NeighborAddress is not configured".
			var iface string
			switch {
			case peer.AutoDiscovery.Unnumbered != nil:
				iface = peer.AutoDiscovery.Unnumbered.Interface
			case peer.AutoDiscovery.DefaultGateway != nil:
				// Interface names are not portable across a heterogeneous fleet
				// (they encode hardware location and vary with the driver), so
				// discover the link facing the peer by following the default route
				// of the requested address family. Only its egress interface is
				// used; the peer address still comes from gobgp's ND on that
				// interface.
				discovered, err := r.getDefaultGatewayInterface(peer.AutoDiscovery.DefaultGateway)
				if err != nil {
					r.reportDerivationFailure(l, p.DesiredConfig.Name, peer.Name, err)
					continue
				}
				iface = discovered
			default:
				// Rejected by the CRD validation rules, be defensive.
				l.Debug("Unnumbered mode set without unnumbered or defaultGateway configuration, skipping",
					types.PeerLogField, peer.Name)
				continue
			}

			r.clearDerivationFailure(l, p.DesiredConfig.Name, peer.Name)
			p.DesiredConfig.Peers[i].PeerInterface = &iface

			l.Debug("Configured unnumbered peer interface",
				types.PeerLogField, peer.Name,
				logfields.Interface, iface)
		default:
			l.Debug("Unsupported auto-discovery mode",
				types.PeerLogField, peer.Name,
				logfields.Mode, peer.AutoDiscovery.Mode)
			continue
		}
	}

	return nil
}

// defaultRoute pairs a default route with the device it egresses.
type defaultRoute struct {
	route *tables.Route
	dev   *tables.Device
}

// activeDefaultRoutes returns the node's default routes for the given address family whose
// egress device is present in the device table, ordered by ascending priority (metric), so the
// most preferred route comes first. Filtering on the route's gateway and on the state of the
// device is left to the caller, as it differs per auto-discovery mode.
func (r *DefaultGatewayReconciler) activeDefaultRoutes(addressFamily string) ([]defaultRoute, error) {
	var defaultPrefix netip.Prefix
	switch addressFamily {
	case "ipv4":
		defaultPrefix = ipv4Default
	case "ipv6":
		defaultPrefix = ipv6Default
	default:
		return nil, fmt.Errorf("invalid address family %s", addressFamily)
	}

	txn := r.DB.ReadTxn()
	// get routes from statedb route table
	// TODO: add RoutePrefixIndex Query to lookup routes by prefix
	var routes []defaultRoute
	for route := range r.routeTable.All(txn) {
		if route.Dst != defaultPrefix {
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
		if !found {
			continue
		}
		routes = append(routes, defaultRoute{route: route, dev: dev})
	}

	slices.SortStableFunc(routes, func(r0, r1 defaultRoute) int {
		return cmp.Compare(r0.route.Priority, r1.route.Priority)
	})

	return routes, nil
}

// getDefaultGateway returns the default gateway address with lower priority using route and device
// statedb tables and the provided default gateway configuration.
func (r *DefaultGatewayReconciler) getDefaultGateway(defaultGateway *v2.DefaultGateway) (string, error) {
	routes, err := r.activeDefaultRoutes(defaultGateway.AddressFamily)
	if err != nil {
		return "", err
	}

	for _, dr := range routes {
		// ignore routes that do not have a valid gateway
		if !dr.route.Gw.IsValid() {
			continue
		}
		// ignore routes if the link through which it is reachable is not up
		if dr.dev.OperStatus != linkOperStateUp {
			continue
		}
		if dr.route.Gw.IsLinkLocalUnicast() {
			r.logger.Warn("link local address is not supported for default gateway mode of bgp auto-discovery",
				logfields.Gateway, dr.route.Gw,
			)
			continue
		}
		// routes are ordered by priority, so the first match is the gateway of
		// the most preferred default route
		return dr.route.Gw.String(), nil
	}

	return "", fmt.Errorf("no active default route found")
}

// getDefaultGatewayInterface returns the name of the interface which the most preferred default
// route of the given address family egresses, for use as the interface of an unnumbered peer.
//
// Unlike getDefaultGateway, the gateway address itself is irrelevant here: only the route's
// egress link is taken, and the peer is subsequently reached over it at the IPv6 link-local
// address gobgp discovers via ND. Routes with a link-local gateway - the common case towards an
// unnumbered ToR, e.g. via fe80::1 or via 169.254.100.0 - and on-link default routes with no
// gateway at all are therefore both usable.
func (r *DefaultGatewayReconciler) getDefaultGatewayInterface(defaultGateway *v2.DefaultGateway) (string, error) {
	routes, err := r.activeDefaultRoutes(defaultGateway.AddressFamily)
	if err != nil {
		return "", err
	}

	for _, dr := range routes {
		if !deviceUsable(dr.dev) || dr.dev.Flags&net.FlagLoopback != 0 {
			continue
		}
		return dr.dev.Name, nil
	}

	return "", fmt.Errorf("no active default route found for address family %s", defaultGateway.AddressFamily)
}

// reportDerivationFailure logs that a peer's unnumbered interface could not be derived from the
// default route. The peer is left unconfigured, which is expected transiently (the default route
// may not be installed yet) but is a configuration error if it persists, so the first occurrence
// is logged at Warn and the repeats at Debug.
func (r *DefaultGatewayReconciler) reportDerivationFailure(l *slog.Logger, instanceName, peerName string, err error) {
	key := instanceName + "/" + peerName

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, reported := r.derivationFailed[key]; reported {
		l.Debug("Failed to derive unnumbered peer interface from the default route, skipping",
			types.PeerLogField, peerName,
			logfields.Error, err)
		return
	}
	if r.derivationFailed == nil {
		r.derivationFailed = make(map[string]struct{})
	}
	r.derivationFailed[key] = struct{}{}

	l.Warn("Failed to derive unnumbered peer interface from the default route, peer is not configured",
		types.PeerLogField, peerName,
		logfields.Error, err)
}

// clearDerivationFailure resets the state kept by reportDerivationFailure for a peer, logging the
// recovery if the peer was previously failing.
func (r *DefaultGatewayReconciler) clearDerivationFailure(l *slog.Logger, instanceName, peerName string) {
	key := instanceName + "/" + peerName

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, reported := r.derivationFailed[key]; !reported {
		return
	}
	delete(r.derivationFailed, key)

	l.Info("Derived unnumbered peer interface from the default route again",
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

// deviceChangeTrackerObserver triggers BGP reconciliation when there is a change in the device table
func deviceChangeTrackerObserver(signaler *signaler.BGPCPSignaler, logger *slog.Logger) job.ObserverFunc[statedb.Change[*tables.Device]] {
	return func(ctx context.Context, event statedb.Change[*tables.Device]) error {
		// trigger reconciliation for device changes
		signaler.Event(struct{}{})
		logger.Debug("Device change detected, triggering BGP reconciliation")
		return nil
	}
}
