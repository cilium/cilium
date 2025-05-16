// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconcilerv2

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/bgpv1/agent/signaler"
	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/manager/store"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/datapath/tables"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

// NeighborReconciler is a ConfigReconciler which reconciles the peers of the
// provided BGP server with the provided CiliumBGPVirtualRouter.
type NeighborReconciler struct {
	logger       *slog.Logger
	DB           *statedb.DB
	routeTable   statedb.Table[*tables.Route]
	deviceTable  statedb.Table[*tables.Device]
	SecretStore  store.BGPCPResourceStore[*slim_corev1.Secret]
	PeerConfig   store.BGPCPResourceStore[*v2.CiliumBGPPeerConfig]
	DaemonConfig *option.DaemonConfig
	metadata     map[string]NeighborReconcilerMetadata
}

type NeighborReconcilerOut struct {
	cell.Out

	Reconciler ConfigReconciler `group:"bgp-config-reconciler-v2"`
}

type NeighborReconcilerIn struct {
	cell.In
	Logger       *slog.Logger
	SecretStore  store.BGPCPResourceStore[*slim_corev1.Secret]
	PeerConfig   store.BGPCPResourceStore[*v2.CiliumBGPPeerConfig]
	DaemonConfig *option.DaemonConfig

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

func NewNeighborReconciler(params NeighborReconcilerIn) NeighborReconcilerOut {
	logger := params.Logger.With(types.ReconcilerLogField, "Neighbor")

	params.JobGroup.Add(
		job.Observer("default-gateway-route-change-tracker",
			routeChangeTrackerObserver(params.Signaler, params.Logger),
			statedb.Observable(params.DB, params.RouteTable)),
	)

	params.JobGroup.Add(
		job.Observer("device-change-device-change-tracker",
			deviceChangeTrackerObserver(params.Signaler, params.Logger),
			statedb.Observable(params.DB, params.DeviceTable)),
	)

	return NeighborReconcilerOut{
		Reconciler: &NeighborReconciler{
			logger:       logger,
			DB:           params.DB,
			routeTable:   params.RouteTable,
			deviceTable:  params.DeviceTable,
			SecretStore:  params.SecretStore,
			PeerConfig:   params.PeerConfig,
			DaemonConfig: params.DaemonConfig,
			metadata:     make(map[string]NeighborReconcilerMetadata),
		},
	}
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

// PeerData keeps a peer and its configuration. It also keeps the TCP password from secret store.
// +deepequal-gen=true
// Note:  If you change PeerDate, do not forget to 'make generate-k8s-api', which will update DeepEqual method.
type PeerData struct {
	Peer     *v2.CiliumBGPNodePeer
	Config   *v2.CiliumBGPPeerConfigSpec
	Password string
}

// NeighborReconcilerMetadata keeps a map of running peers to peer configuration.
// Key is the peer name.
type NeighborReconcilerMetadata map[string]*PeerData

func (r *NeighborReconciler) getMetadata(i *instance.BGPInstance) NeighborReconcilerMetadata {
	return r.metadata[i.Name]
}

func (r *NeighborReconciler) upsertMetadata(i *instance.BGPInstance, d *PeerData) {
	if i == nil || d == nil {
		return
	}
	r.metadata[i.Name][d.Peer.Name] = d
}

func (r *NeighborReconciler) deleteMetadata(i *instance.BGPInstance, d *PeerData) {
	if i == nil || d == nil {
		return
	}
	delete(r.metadata[i.Name], d.Peer.Name)
}

func (r *NeighborReconciler) Name() string {
	return NeighborReconcilerName
}

// Priority of neighbor reconciler is higher than pod/service announcements.
// This is important for graceful restart case, where all expected routes are pushed
// into gobgp RIB before neighbors are added. So, gobgp can send out all prefixes
// within initial update message exchange with neighbors before sending EOR marker.
func (r *NeighborReconciler) Priority() int {
	return NeighborReconcilerPriority
}

func (r *NeighborReconciler) Init(i *instance.BGPInstance) error {
	if i == nil {
		return fmt.Errorf("BUG: %s reconciler initialization with nil BGPInstance", r.Name())
	}
	r.metadata[i.Name] = make(NeighborReconcilerMetadata)
	return nil
}

func (r *NeighborReconciler) Cleanup(i *instance.BGPInstance) {
	if i != nil {
		delete(r.metadata, i.Name)
	}
}

func (r *NeighborReconciler) Reconcile(ctx context.Context, p ReconcileParams) error {
	if err := p.ValidateParams(); err != nil {
		return err
	}

	var (
		l = r.logger.With(types.InstanceLogField, p.DesiredConfig.Name)

		toCreate []*PeerData
		toRemove []*PeerData
		toUpdate []*PeerData
	)
	curNeigh := r.getMetadata(p.BGPInstance)
	newNeigh := p.DesiredConfig.Peers

	l.Debug("Begin reconciling peers")

	type member struct {
		new *PeerData
		cur *PeerData
	}

	nset := map[string]*member{}

	for i, n := range newNeigh {
		l := l.With(types.PeerLogField, n.Name)
		// validate that peer has ASN and address. In current implementation these fields are
		// mandatory for a peer. Eventually we will relax this restriction with implementation
		// of BGP unnumbered.
		if n.PeerASN == nil {
			return fmt.Errorf("peer %s does not have a PeerASN", n.Name)
		}

		if n.PeerAddress == nil {
			// future auto-discovery modes can be added here to get the peer address
			switch n.AutoDiscovery.Mode {
			case v2.BGPDefaultGatewayMode:
				defaultGateway, err := r.getDefaultGateway(n.AutoDiscovery.DefaultGateway)
				if err != nil {
					l.Debug("failed to get default gateway, skipping",
						logfields.Error,
						err)
					continue
				}
				newNeigh[i].PeerAddress = &defaultGateway
			default:
				l.Debug("Peer does not have PeerAddress configured, skipping")
				continue
			}
		}

		var (
			key = r.neighborID(&newNeigh[i])
			h   *member
			ok  bool
		)

		config, exists, err := r.getPeerConfig(n.PeerConfigRef)
		if err != nil {
			return err
		}
		if !exists {
			continue // configured peer config does not exist, skip
		}

		passwd, err := r.getPeerPassword(p.DesiredConfig.Name, n.Name, config)
		if err != nil {
			return err
		}

		if h, ok = nset[key]; !ok {
			nset[key] = &member{
				new: &PeerData{
					Peer:     &newNeigh[i],
					Config:   config,
					Password: passwd,
				},
			}
			continue
		}
		h.new = &PeerData{
			Peer:     &newNeigh[i],
			Config:   config,
			Password: passwd,
		}
	}

	for i, n := range curNeigh {
		var (
			key = r.neighborID(n.Peer)
			h   *member
			ok  bool
		)

		if h, ok = nset[key]; !ok {
			nset[key] = &member{
				cur: curNeigh[i],
			}
			continue
		}
		h.cur = curNeigh[i]
	}

	for _, m := range nset {
		// present in new neighbors (set new) but not in current neighbors (set cur)
		if m.new != nil && m.cur == nil {
			toCreate = append(toCreate, m.new)
		}
		// present in current neighbors (set cur) but not in new neighbors (set new)
		if m.cur != nil && m.new == nil {
			toRemove = append(toRemove, m.cur)
		}
		// present in both new neighbors (set new) and current neighbors (set cur), update if they are not equal
		if m.cur != nil && m.new != nil {
			if !m.cur.DeepEqual(m.new) {
				toUpdate = append(toUpdate, m.new)
			}
		}
	}

	if len(toCreate) > 0 || len(toRemove) > 0 || len(toUpdate) > 0 {
		l.Info("Reconciling peers for instance")
	} else {
		l.Debug("No peer changes necessary")
	}

	// remove neighbors
	for _, n := range toRemove {
		l.Info("Removing peer", types.PeerLogField, n.Peer.Name)

		if err := p.BGPInstance.Router.RemoveNeighbor(ctx, types.ToNeighborV2(n.Peer, n.Config, "")); err != nil {
			return fmt.Errorf("failed to remove neigbhor %s from instance %s: %w", n.Peer.Name, p.DesiredConfig.Name, err)
		}
		// update metadata
		r.deleteMetadata(p.BGPInstance, n)
	}

	// update neighbors
	for _, n := range toUpdate {
		l.Info("Updating peer", types.PeerLogField, n.Peer.Name)

		if err := p.BGPInstance.Router.UpdateNeighbor(ctx, types.ToNeighborV2(n.Peer, n.Config, n.Password)); err != nil {
			return fmt.Errorf("failed to update neigbhor %s in instance %s: %w", n.Peer.Name, p.DesiredConfig.Name, err)
		}
		// update metadata
		r.upsertMetadata(p.BGPInstance, n)
	}

	// create new neighbors
	for _, n := range toCreate {
		l.Info("Adding peer", types.PeerLogField, n.Peer.Name)

		if err := p.BGPInstance.Router.AddNeighbor(ctx, types.ToNeighborV2(n.Peer, n.Config, n.Password)); err != nil {
			return fmt.Errorf("failed to add neigbhor %s in instance %s: %w", n.Peer.Name, p.DesiredConfig.Name, err)
		}
		// update metadata
		r.upsertMetadata(p.BGPInstance, n)
	}

	l.Debug("Done reconciling peers")
	return nil
}

// getDefaultGateway returns the default gateway address with lower priority using route and device
// statedb tables and the provided default gateway configuration.
func (r *NeighborReconciler) getDefaultGateway(defaultGateway *v2.DefaultGateway) (string, error) {
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
				logfields.Gateway, route.Gw.String(),
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

// getPeerConfig returns the CiliumBGPPeerConfigSpec for the given peerConfig.
// If peerConfig is not specified, returns the default config.
// If the referenced peerConfig does not exist, exists returns false.
func (r *NeighborReconciler) getPeerConfig(peerConfig *v2.PeerConfigReference) (conf *v2.CiliumBGPPeerConfigSpec, exists bool, err error) {
	if peerConfig == nil || peerConfig.Name == "" {
		// if peer config is not specified, return default config
		conf = &v2.CiliumBGPPeerConfigSpec{}
		conf.SetDefaults()
		return conf, true, nil
	}

	config, exists, err := r.PeerConfig.GetByKey(resource.Key{Name: peerConfig.Name})
	if err != nil || !exists {
		if errors.Is(err, store.ErrStoreUninitialized) {
			err = errors.Join(err, ErrAbortReconcile)
		}
		return nil, exists, err
	}

	conf = &config.Spec
	conf.SetDefaults()
	return conf, true, nil
}

func (r *NeighborReconciler) getPeerPassword(instanceName, peerName string, config *v2.CiliumBGPPeerConfigSpec) (string, error) {
	if config == nil {
		return "", nil
	}

	if config.AuthSecretRef != nil {
		secretRef := *config.AuthSecretRef

		secret, ok, err := r.fetchSecret(secretRef)
		if err != nil {
			return "", fmt.Errorf("failed to fetch secret %q: %w", secretRef, err)
		}
		if !ok {
			return "", nil
		}
		tcpPassword := string(secret["password"])
		if tcpPassword == "" {
			return "", fmt.Errorf("failed to fetch secret %q: missing password key", secretRef)
		}
		r.logger.Debug(
			"Using TCP password from secret",
			types.SecretRefLogField, secretRef,
			types.InstanceLogField, instanceName,
			types.PeerLogField, peerName,
		)
		return tcpPassword, nil
	}
	return "", nil
}

func (r *NeighborReconciler) fetchSecret(name string) (map[string][]byte, bool, error) {
	if r.SecretStore == nil {
		return nil, false, fmt.Errorf("SecretsNamespace not configured")
	}
	item, ok, err := r.SecretStore.GetByKey(resource.Key{Namespace: r.DaemonConfig.BGPSecretsNamespace, Name: name})
	if err != nil || !ok {
		if errors.Is(err, store.ErrStoreUninitialized) {
			err = errors.Join(err, ErrAbortReconcile)
		}
		return nil, ok, err
	}
	result := map[string][]byte{}
	for k, v := range item.Data {
		result[k] = []byte(v)
	}
	return result, true, nil
}

func (r *NeighborReconciler) neighborID(n *v2.CiliumBGPNodePeer) string {
	return fmt.Sprintf("%s%s%d", n.Name, *n.PeerAddress, *n.PeerASN)
}
