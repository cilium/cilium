// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/bgp/agent/signaler"
	"github.com/cilium/cilium/pkg/bgp/manager/instance"
	"github.com/cilium/cilium/pkg/bgp/types"
	"github.com/cilium/cilium/pkg/datapath/tables"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// DefaultGatewayReconciler is a ConfigReconciler which handles auto-discovery
// of peer addresses for DefaultGateway mode. It runs with the highest priority
// to ensure peer addresses are populated before other reconcilers run.
type DefaultGatewayReconciler struct {
	logger      *slog.Logger
	DB          *statedb.DB
	routeTable  statedb.Table[*tables.Route]
	deviceTable statedb.Table[*tables.Device]
}

type DefaultGatewayReconcilerOut struct {
	cell.Out

	Reconciler ConfigReconciler `group:"bgp-config-reconciler"`
}

type DefaultGatewayReconcilerIn struct {
	cell.In

	Logger      *slog.Logger
	DB          *statedb.DB
	JobGroup    job.Group
	Signaler    *signaler.BGPCPSignaler
	RouteTable  statedb.Table[*tables.Route]
	DeviceTable statedb.Table[*tables.Device]
}

var (
	ipv4Default = netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	ipv6Default = netip.PrefixFrom(netip.IPv6Unspecified(), 0)
)

func NewDefaultGatewayReconciler(p DefaultGatewayReconcilerIn) DefaultGatewayReconcilerOut {
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
			logger:      logger,
			DB:          p.DB,
			routeTable:  p.RouteTable,
			deviceTable: p.DeviceTable,
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
		dev, _, found := r.deviceTable.Get(txn, tables.DeviceIDIndex.Query(route.LinkIndex))
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
