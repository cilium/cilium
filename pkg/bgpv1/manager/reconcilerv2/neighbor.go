// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconcilerv2

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"net/netip"
	"sort"
	"strings"

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
	"github.com/cilium/cilium/pkg/option"
)

// NeighborReconciler is a ConfigReconciler which reconciles the peers of the
// provided BGP server with the provided CiliumBGPVirtualRouter.
type NeighborReconciler struct {
	logger       *slog.Logger
	DB           *statedb.DB
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

	DB         *statedb.DB
	JobGroup   job.Group
	Signaler   *signaler.BGPCPSignaler
	RouteTable statedb.Table[*tables.Route]
}

func NewNeighborReconciler(params NeighborReconcilerIn) NeighborReconcilerOut {
	logger := params.Logger.With(types.ReconcilerLogField, "Neighbor")

	// add observer for default gateway changes
	params.JobGroup.Add(
		job.Observer("default-gateway-tracker", func(ctx context.Context, event statedb.Change[*tables.Route]) error {
			route := event.Object
			// check for default route change
			if route.Dst.String() == netip.PrefixFrom(netip.IPv4Unspecified(), 0).String() ||
				route.Dst.String() == netip.PrefixFrom(netip.IPv6Unspecified(), 0).String() {
				// trigger reconciliation for default route changes
				params.Signaler.Event(struct{}{})
				params.Logger.Debug("Default gateway change detected, triggering BGP reconciliation")
			}
			return nil
		}, statedb.Observable(params.DB, params.RouteTable)),
	)

	return NeighborReconcilerOut{
		Reconciler: &NeighborReconciler{
			logger:       logger,
			DB:           params.DB,
			SecretStore:  params.SecretStore,
			PeerConfig:   params.PeerConfig,
			DaemonConfig: params.DaemonConfig,
			metadata:     make(map[string]NeighborReconcilerMetadata),
		},
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
		// validate that peer has ASN and address. In current implementation these fields are
		// mandatory for a peer. Eventually we will relax this restriction with implementation
		// of BGP unnumbered.
		if n.PeerASN == nil {
			return fmt.Errorf("peer %s does not have a PeerASN", n.Name)
		}

		if n.PeerAddress == nil {
			// future auto-discovery modes can be added here to get the peer address
			switch n.AutoDiscovery.Mode {
			case "default-gateway":
				defaultGateway, err := r.getDefaultGateway(n.AutoDiscovery.DefaultGateway)
				if err != nil {
					r.logger.Error("failed to get default gateway", "error", err)
					continue
				}
				newNeigh[i].PeerAddress = &defaultGateway
			default:
				r.logger.Debug("Peer does not have PeerAddress configured, skipping", types.PeerLogField, n.Name)
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
	var defaultRoute string
	switch defaultGateway.AddressFamily {
	case "ipv4":
		defaultRoute = netip.PrefixFrom(netip.IPv4Unspecified(), 0).String()
	case "ipv6":
		defaultRoute = netip.PrefixFrom(netip.IPv6Unspecified(), 0).String()
	default:
		return "", fmt.Errorf("invalid address family %s", defaultGateway.AddressFamily)
	}
	// get routes from statedb route table
	txn := r.DB.ReadTxn()
	routeMeta := r.DB.GetTable(txn, "routes")
	routeTbl := statedb.AnyTable{Meta: routeMeta}
	routeObjs := routeTbl.All(txn)
	header := routeTbl.TableHeader()
	// extract indexes of required columns
	routeColumns := []string{"Destination", "Source", "Gateway", "LinkIndex", "Priority"}
	routeIdxs, err := getColumnIndexes(routeColumns, header)
	if err != nil {
		return "", fmt.Errorf("failed to get column indexes for route table: %w", err)
	}

	// get links from statedb device table
	deviceMeta := r.DB.GetTable(txn, "devices")
	deviceTbl := statedb.AnyTable{Meta: deviceMeta}
	deviceObjs := deviceTbl.All(txn)
	deviceHeader := deviceTbl.TableHeader()
	// extract indexes of required columns
	deviceColumns := []string{"Index", "OperStatus"}
	deviceIdxs, err := getColumnIndexes(deviceColumns, deviceHeader)
	if err != nil {
		return "", fmt.Errorf("failed to get column indexes for device table: %w", err)
	}

	defaultRoutes := [][]string{}
	for routeObj := range routeObjs {
		ro := routeObj.(statedb.TableWritable).TableRow()
		if ro[routeIdxs["Gateway"]] == "" || ro[routeIdxs["Destination"]] == "" {
			continue
		}
		if ro[routeIdxs["Destination"]] == defaultRoute {
			matched := validDefaultRoute(ro, routeIdxs, deviceObjs, deviceIdxs)
			if !matched {
				continue
			}
			r.logger.Debug("default gateway found", "gateway", ro[routeIdxs["Gateway"]])
			defaultRoutes = append(defaultRoutes, ro)
		}
	}
	if len(defaultRoutes) == 0 {
		return "", fmt.Errorf("failed to get default gateways from route table")
	}
	// sort the default routes by priority
	sort.Slice(defaultRoutes, func(i, j int) bool {
		iPriority := defaultRoutes[i][routeIdxs["Priority"]]
		jPriority := defaultRoutes[j][routeIdxs["Priority"]]
		// compare length of strings
		if len(iPriority) != len(jPriority) {
			return len(iPriority) < len(jPriority)
		}
		// if length of strings is same, compare lexicographically
		return iPriority < jPriority
	})
	// return the gateway address with lowest priority
	return defaultRoutes[0][routeIdxs["Gateway"]], nil
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

// getColumnIndexes returns a map of column names to their indexes in the header
func getColumnIndexes(names []string, header []string) (map[string]int, error) {
	columnIndexes := make(map[string]int)
loop:
	for _, name := range names {
		for i, name2 := range header {
			if strings.EqualFold(name, name2) {
				columnIndexes[name] = i
				continue loop
			}
		}
		return nil, fmt.Errorf("column %q not part of %v", name, header)
	}
	return columnIndexes, nil
}

// validDefaultRoute checks if the interface through which the default route is reachable is up
func validDefaultRoute(ro []string, routeIdxs map[string]int, deviceObjs iter.Seq2[any, statedb.Revision], deviceIdxs map[string]int) bool {
	for deviceObj := range deviceObjs {
		do := deviceObj.(statedb.TableWritable).TableRow()
		if do[deviceIdxs["Index"]] == ro[routeIdxs["LinkIndex"]] {
			if do[deviceIdxs["OperStatus"]] == "up" {
				return true
			}
		}
	}
	return false
}
