// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"context"
	"fmt"
	"net/netip"
	"slices"

	"github.com/cilium/cilium/pkg/bgpv1/agent"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s"
	v2api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/option"
	ciliumslices "github.com/cilium/cilium/pkg/slices"

	"github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"
)

const (
	podIPPoolNameLabel      = "io.cilium.podippool.name"
	podIPPoolNamespaceLabel = "io.cilium.podippool.namespace"
)

type ReconcileParams struct {
	CurrentServer *ServerWithConfig
	DesiredConfig *v2alpha1api.CiliumBGPVirtualRouter
	CiliumNode    *v2api.CiliumNode
}

// ConfigReconciler is a interface for reconciling a particular aspect
// of an old and new *v2alpha1api.CiliumBGPVirtualRouter
type ConfigReconciler interface {
	// Name returns the name of a reconciler.
	Name() string
	// Priority is used to determine the order in which reconcilers are called. Reconcilers are called from lowest to
	// highest.
	Priority() int
	// Reconcile If the `Config` field in `params.sc` is nil the reconciler should unconditionally
	// perform the reconciliation actions, as no previous configuration is present.
	Reconcile(ctx context.Context, params ReconcileParams) error
}

var ConfigReconcilers = cell.ProvidePrivate(
	NewPreflightReconciler,
	NewNeighborReconciler,
	NewExportPodCIDRReconciler,
	NewPodIPPoolReconciler,
	NewLBServiceReconciler,
	NewRoutePolicyReconciler,
)

type PreflightReconcilerOut struct {
	cell.Out

	Reconciler ConfigReconciler `group:"bgp-config-reconciler"`
}

// PreflightReconciler is a preflight task before any other reconciliation should
// take place.
//
// this reconciler handles any changes in current and desired BgpState which leads
// to a recreation of an existing BgpServer.
//
// this must be done first so that the following reconciliation functions act
// upon the recreated BgpServer with the desired permanent configurations.
//
// permanent configurations for BgpServers (ones that cannot be changed after creation)
// are router ID and local listening port.
type PreflightReconciler struct{}

func NewPreflightReconciler() PreflightReconcilerOut {
	return PreflightReconcilerOut{
		Reconciler: &PreflightReconciler{},
	}
}

func (r *PreflightReconciler) Name() string {
	return "Preflight"
}

func (r *PreflightReconciler) Priority() int {
	return 10
}

func (r *PreflightReconciler) Reconcile(ctx context.Context, p ReconcileParams) error {
	var (
		l = log.WithFields(
			logrus.Fields{
				"component": "manager.preflightReconciler",
			},
		)
	)

	// If we have no config attached, we don't need to perform a preflight for
	// reconciliation.
	//
	// This is the first time this server is being registered and BGPRouterManager
	// set any fields needing reconciliation in this function already.
	if p.CurrentServer.Config == nil {
		l.Debugf("Preflight for virtual router with ASN %v not necessary, first instantiation of this BgpServer.", p.DesiredConfig.LocalASN)
		return nil
	}

	l.Debugf("Begin preflight reoncilation for virtual router with ASN %v", p.DesiredConfig.LocalASN)
	bgpInfo, err := p.CurrentServer.Server.GetBGP(ctx)
	if err != nil {
		return fmt.Errorf("failed to retrieve BgpServer info for virtual router with ASN %v: %w", p.DesiredConfig.LocalASN, err)
	}

	// parse Node annotations into helper Annotation map
	annoMap, err := agent.NewAnnotationMap(p.CiliumNode.Annotations)
	if err != nil {
		return fmt.Errorf("failed to parse CiliumNode annotations for virtual router with ASN %v: %w", p.DesiredConfig.LocalASN, err)
	}

	// resolve local port from kubernetes annotations
	var localPort int32
	localPort = -1
	if attrs, ok := annoMap[p.DesiredConfig.LocalASN]; ok {
		if attrs.LocalPort != 0 {
			localPort = int32(attrs.LocalPort)
		}
	}

	routerID, err := annoMap.ResolveRouterID(p.DesiredConfig.LocalASN)
	if err != nil {
		if nodeIP := p.CiliumNode.GetIP(false); nodeIP == nil {
			return fmt.Errorf("failed to get ciliumnode IP %v: %w", nodeIP, err)
		} else {
			routerID = nodeIP.String()
		}
	}

	var shouldRecreate bool
	if localPort != bgpInfo.Global.ListenPort {
		shouldRecreate = true
		l.Infof("Virtual router with ASN %v local port has changed from %v to %v", p.DesiredConfig.LocalASN, bgpInfo.Global.ListenPort, localPort)
	}
	if routerID != bgpInfo.Global.RouterID {
		shouldRecreate = true
		l.Infof("Virtual router with ASN %v router ID has changed from %v to %v", p.DesiredConfig.LocalASN, bgpInfo.Global.RouterID, routerID)
	}
	if !shouldRecreate {
		l.Debugf("No preflight reconciliation necessary for virtual router with local ASN %v", p.DesiredConfig.LocalASN)
		return nil
	}

	l.Infof("Recreating virtual router with ASN %v for changes to take effect", p.DesiredConfig.LocalASN)
	globalConfig := types.ServerParameters{
		Global: types.BGPGlobal{
			ASN:        uint32(p.DesiredConfig.LocalASN),
			RouterID:   routerID,
			ListenPort: localPort,
			RouteSelectionOptions: &types.RouteSelectionOptions{
				AdvertiseInactiveRoutes: true,
			},
		},
	}

	// stop the old BgpServer
	p.CurrentServer.Server.Stop()

	// create a new one via ServerWithConfig constructor
	s, err := NewServerWithConfig(ctx, globalConfig)
	if err != nil {
		l.WithError(err).Errorf("Failed to start BGP server for virtual router with local ASN %v", p.DesiredConfig.LocalASN)
		return fmt.Errorf("failed to start BGP server for virtual router with local ASN %v: %w", p.DesiredConfig.LocalASN, err)
	}

	// replace the old underlying server with our recreated one
	p.CurrentServer.Server = s.Server

	// dump the existing config so all subsequent reconcilers perform their
	// actions as if this is a new BgpServer.
	p.CurrentServer.Config = nil

	// Clear the shadow state since any advertisements will be gone now that the server has been recreated.
	p.CurrentServer.ReconcilerMetadata = make(map[string]any)

	return nil
}

type NeighborReconcilerOut struct {
	cell.Out

	Reconciler ConfigReconciler `group:"bgp-config-reconciler"`
}

// NeighborReconciler is a ConfigReconciler which reconciles the peers of the
// provided BGP server with the provided CiliumBGPVirtualRouter.
type NeighborReconciler struct {
	SecretStore  BGPCPResourceStore[*slim_corev1.Secret]
	DaemonConfig *option.DaemonConfig
}

func NewNeighborReconciler(SecretStore BGPCPResourceStore[*slim_corev1.Secret], DaemonConfig *option.DaemonConfig) NeighborReconcilerOut {
	return NeighborReconcilerOut{
		Reconciler: &NeighborReconciler{
			SecretStore:  SecretStore,
			DaemonConfig: DaemonConfig,
		},
	}
}

func (r *NeighborReconciler) Name() string {
	return "Neighbor"
}

// Priority of neighbor reconciler is higher than pod/service announcements.
// This is important for graceful restart case, where all expected routes are pushed
// into gobgp RIB before neighbors are added. So, gobgp can send out all prefixes
// within initial update message exchange with neighbors before sending EOR marker.
func (r *NeighborReconciler) Priority() int {
	return 60
}

func (r *NeighborReconciler) Reconcile(ctx context.Context, p ReconcileParams) error {
	if p.DesiredConfig == nil {
		return fmt.Errorf("attempted neighbor reconciliation with nil CiliumBGPPeeringPolicy")
	}
	if p.CurrentServer == nil {
		return fmt.Errorf("attempted neighbor reconciliation with nil ServerWithConfig")
	}
	var (
		l = log.WithFields(
			logrus.Fields{
				"component": "manager.neighborReconciler",
			},
		)
		toCreate []*v2alpha1api.CiliumBGPNeighbor
		toRemove []*v2alpha1api.CiliumBGPNeighbor
		toUpdate []*v2alpha1api.CiliumBGPNeighbor
		curNeigh []v2alpha1api.CiliumBGPNeighbor = nil
	)
	newNeigh := p.DesiredConfig.Neighbors
	l.Debugf("Begin reconciling peers for virtual router with local ASN %v", p.DesiredConfig.LocalASN)

	// sc.Config can be nil if there is no previous configuration.
	if p.CurrentServer.Config != nil {
		curNeigh = p.CurrentServer.Config.Neighbors
	}

	// an nset member which book keeps which universe it exists in.
	type member struct {
		new *v2alpha1api.CiliumBGPNeighbor
		cur *v2alpha1api.CiliumBGPNeighbor
	}

	nset := map[string]*member{}

	// populate set from universe of new neighbors
	for i, n := range newNeigh {
		var (
			key = fmt.Sprintf("%s%d", n.PeerAddress, n.PeerASN)
			h   *member
			ok  bool
		)
		if h, ok = nset[key]; !ok {
			nset[key] = &member{
				new: &newNeigh[i],
			}
			continue
		}
		h.new = &newNeigh[i]
	}

	// populate set from universe of current neighbors
	for i, n := range curNeigh {
		var (
			key = fmt.Sprintf("%s%d", n.PeerAddress, n.PeerASN)
			h   *member
			ok  bool
		)
		if h, ok = nset[key]; !ok {
			nset[key] = &member{
				cur: &curNeigh[i],
			}
			continue
		}
		h.cur = &curNeigh[i]
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
			} else {
				// Fetch the secret to check if the TCP password changed.
				tcpPassword, err := r.fetchPeerPassword(p.CurrentServer, m.new)
				if err != nil {
					return err
				}
				if r.changedPeerPassword(p.CurrentServer, m.new, tcpPassword) {
					toUpdate = append(toUpdate, m.new)
				}
			}
		}
	}

	if len(toCreate) > 0 || len(toRemove) > 0 || len(toUpdate) > 0 {
		l.Infof("Reconciling peers for virtual router with local ASN %v", p.DesiredConfig.LocalASN)
	} else {
		l.Debugf("No peer changes necessary for virtual router with local ASN %v", p.DesiredConfig.LocalASN)
	}

	// create new neighbors
	for _, n := range toCreate {
		l.Infof("Adding peer %v %v to local ASN %v", n.PeerAddress, n.PeerASN, p.DesiredConfig.LocalASN)
		tcpPassword, err := r.fetchPeerPassword(p.CurrentServer, n)
		if err != nil {
			return fmt.Errorf("failed fetching password for neighbor %v %v: %w", n.PeerAddress, n.PeerASN, err)
		}
		if err := p.CurrentServer.Server.AddNeighbor(ctx, types.NeighborRequest{Neighbor: n, Password: tcpPassword, VR: p.DesiredConfig}); err != nil {
			return fmt.Errorf("failed while reconciling neighbor %v %v: %w", n.PeerAddress, n.PeerASN, err)
		}
		r.updatePeerPassword(p.CurrentServer, n, tcpPassword)
	}

	// update neighbors
	for _, n := range toUpdate {
		l.Infof("Updating peer %v %v in local ASN %v", n.PeerAddress, n.PeerASN, p.DesiredConfig.LocalASN)
		tcpPassword, err := r.fetchPeerPassword(p.CurrentServer, n)
		if err != nil {
			return fmt.Errorf("failed fetching password for neighbor %v %v: %w", n.PeerAddress, n.PeerASN, err)
		}
		if err := p.CurrentServer.Server.UpdateNeighbor(ctx, types.NeighborRequest{Neighbor: n, Password: tcpPassword, VR: p.DesiredConfig}); err != nil {
			return fmt.Errorf("failed while reconciling neighbor %v %v: %w", n.PeerAddress, n.PeerASN, err)
		}
		if r.changedPeerPassword(p.CurrentServer, n, tcpPassword) {
			r.updatePeerPassword(p.CurrentServer, n, tcpPassword)
		}
	}

	// remove neighbors
	for _, n := range toRemove {
		l.Infof("Removing peer %v %v from local ASN %v", n.PeerAddress, n.PeerASN, p.DesiredConfig.LocalASN)
		if err := p.CurrentServer.Server.RemoveNeighbor(ctx, types.NeighborRequest{Neighbor: n, VR: p.DesiredConfig}); err != nil {
			return fmt.Errorf("failed while reconciling neighbor %v %v: %w", n.PeerAddress, n.PeerASN, err)
		}
	}

	l.Infof("Done reconciling peers for virtual router with local ASN %v", p.DesiredConfig.LocalASN)
	return nil
}

type ExportPodCIDRReconcilerOut struct {
	cell.Out

	Reconciler ConfigReconciler `group:"bgp-config-reconciler"`
}

// exportPodCIDRReconciler is a ConfigReconciler which reconciles the
// advertisement of the private Kubernetes PodCIDR block.
type ExportPodCIDRReconciler struct{}

// ExportPodCIDRReconcilerMetadata keeps a list of all advertised Paths
type ExportPodCIDRReconcilerMetadata []*types.Path

func NewExportPodCIDRReconciler() ExportPodCIDRReconcilerOut {
	return ExportPodCIDRReconcilerOut{
		Reconciler: &ExportPodCIDRReconciler{},
	}
}

func (r *ExportPodCIDRReconciler) Name() string {
	return "ExportPodCIDR"
}

func (r *ExportPodCIDRReconciler) Priority() int {
	return 30
}

func (r *ExportPodCIDRReconciler) Reconcile(ctx context.Context, p ReconcileParams) error {
	if p.DesiredConfig == nil {
		return fmt.Errorf("attempted pod CIDR advertisements reconciliation with nil CiliumBGPPeeringPolicy")
	}
	if p.CurrentServer == nil {
		return fmt.Errorf("attempted pod CIDR advertisements reconciliation with nil ServerWithConfig")
	}
	if p.CiliumNode == nil {
		return fmt.Errorf("attempted pod CIDR advertisements reconciliation with nil local CiliumNode")
	}

	var toAdvertise []*types.Path
	for _, cidr := range p.CiliumNode.Spec.IPAM.PodCIDRs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return fmt.Errorf("failed to parse prefix %s: %w", cidr, err)
		}
		toAdvertise = append(toAdvertise, types.NewPathForPrefix(prefix))
	}

	advertisements, err := exportAdvertisementsReconciler(&advertisementsReconcilerParams{
		ctx:       ctx,
		name:      "pod CIDR",
		component: "manager.exportPodCIDRReconciler",
		enabled:   *p.DesiredConfig.ExportPodCIDR,

		sc:   p.CurrentServer,
		newc: p.DesiredConfig,

		currentAdvertisements: r.getMetadata(p.CurrentServer),
		toAdvertise:           toAdvertise,
	})

	if err != nil {
		return err
	}

	// Update the server config's list of current advertisements only if the
	// reconciliation logic didn't return any error
	r.storeMetadata(p.CurrentServer, advertisements)
	return nil
}

func (r *ExportPodCIDRReconciler) getMetadata(sc *ServerWithConfig) ExportPodCIDRReconcilerMetadata {
	if _, found := sc.ReconcilerMetadata[r.Name()]; !found {
		sc.ReconcilerMetadata[r.Name()] = make(ExportPodCIDRReconcilerMetadata, 0)
	}
	return sc.ReconcilerMetadata[r.Name()].(ExportPodCIDRReconcilerMetadata)
}

func (r *ExportPodCIDRReconciler) storeMetadata(sc *ServerWithConfig, meta ExportPodCIDRReconcilerMetadata) {
	sc.ReconcilerMetadata[r.Name()] = meta
}

type LBServiceReconcilerOut struct {
	cell.Out

	Reconciler ConfigReconciler `group:"bgp-config-reconciler"`
}

type LBServiceReconciler struct {
	diffStore   DiffStore[*slim_corev1.Service]
	epDiffStore DiffStore[*k8s.Endpoints]
}

// LBServiceReconcilerMetadata keeps a map of services to the respective advertised Paths
type LBServiceReconcilerMetadata map[resource.Key][]*types.Path

type localServices map[k8s.ServiceID]struct{}

func NewLBServiceReconciler(diffStore DiffStore[*slim_corev1.Service], epDiffStore DiffStore[*k8s.Endpoints]) LBServiceReconcilerOut {
	if diffStore == nil {
		return LBServiceReconcilerOut{}
	}

	return LBServiceReconcilerOut{
		Reconciler: &LBServiceReconciler{
			diffStore:   diffStore,
			epDiffStore: epDiffStore,
		},
	}
}

func (r *LBServiceReconciler) Name() string {
	return "LBService"
}

func (r *LBServiceReconciler) Priority() int {
	return 40
}

func (r *LBServiceReconciler) Reconcile(ctx context.Context, p ReconcileParams) error {
	if p.CiliumNode == nil {
		return fmt.Errorf("attempted load balancer service reconciliation with nil local CiliumNode")
	}

	var existingSelector *slim_metav1.LabelSelector
	if p.CurrentServer != nil && p.CurrentServer.Config != nil {
		existingSelector = p.CurrentServer.Config.ServiceSelector
	}

	ls := r.populateLocalServices(p.CiliumNode.Name)

	// If the existing selector was updated, went from nil to something or something to nil, we need to perform full
	// reconciliation and check if every existing announcement's service still matches the selector.
	changed := (existingSelector != nil && p.DesiredConfig.ServiceSelector != nil && !p.DesiredConfig.ServiceSelector.DeepEqual(existingSelector)) ||
		((existingSelector == nil) != (p.DesiredConfig.ServiceSelector == nil))

	if changed {
		if err := r.fullReconciliation(ctx, p.CurrentServer, p.DesiredConfig, ls); err != nil {
			return fmt.Errorf("full reconciliation: %w", err)
		}

		return nil
	}

	if err := r.svcDiffReconciliation(ctx, p.CurrentServer, p.DesiredConfig, ls); err != nil {
		return fmt.Errorf("svc Diff reconciliation: %w", err)
	}

	return nil
}

func (r *LBServiceReconciler) getMetadata(sc *ServerWithConfig) LBServiceReconcilerMetadata {
	if _, found := sc.ReconcilerMetadata[r.Name()]; !found {
		sc.ReconcilerMetadata[r.Name()] = make(LBServiceReconcilerMetadata)
	}
	return sc.ReconcilerMetadata[r.Name()].(LBServiceReconcilerMetadata)
}

func (r *LBServiceReconciler) resolveSvcFromEndpoints(eps *k8s.Endpoints) (*slim_corev1.Service, bool, error) {
	k := resource.Key{
		Name:      eps.ServiceID.Name,
		Namespace: eps.ServiceID.Namespace,
	}
	return r.diffStore.GetByKey(k)
}

// Populate locally available services used for externalTrafficPolicy=local handling
func (r *LBServiceReconciler) populateLocalServices(localNodeName string) localServices {
	ls := make(localServices)

endpointsLoop:
	for _, eps := range r.epDiffStore.List() {
		svc, exists, err := r.resolveSvcFromEndpoints(eps)
		if err != nil {
			// Cannot resolve service from endpoints. We have nothing to do here.
			continue
		}

		if !exists {
			// No service associated with this endpoint. We're not interested in this.
			continue
		}

		// We only need Endpoints tracking for externalTrafficPolicy=Local
		if svc.Spec.ExternalTrafficPolicy != slim_corev1.ServiceExternalTrafficPolicyLocal {
			continue
		}

		svcID := eps.ServiceID

		for _, be := range eps.Backends {
			if be.NodeName == localNodeName {
				// At least one endpoint is available on this node. We
				// can make unavailable to available.
				if _, found := ls[svcID]; !found {
					ls[svcID] = struct{}{}
				}
				continue endpointsLoop
			}
		}
	}

	return ls
}

// NeighborReconcilerMetadata keeps a map of peers to passwords, fetched from
// secrets. Key is PeerAddress+PeerASN.
type NeighborReconcilerMetadata map[string]string

func (r *NeighborReconciler) getMetadata(sc *ServerWithConfig) NeighborReconcilerMetadata {
	if _, found := sc.ReconcilerMetadata[r.Name()]; !found {
		sc.ReconcilerMetadata[r.Name()] = make(NeighborReconcilerMetadata)
	}
	return sc.ReconcilerMetadata[r.Name()].(NeighborReconcilerMetadata)
}

func (r *NeighborReconciler) fetchPeerPassword(sc *ServerWithConfig, n *v2alpha1api.CiliumBGPNeighbor) (string, error) {
	peerPasswords := r.getMetadata(sc)

	l := log.WithFields(
		logrus.Fields{
			"component": "manager.fetchPeerPassword",
		},
	)
	if n.AuthSecretRef != nil {
		secretRef := *n.AuthSecretRef
		old := peerPasswords[fmt.Sprintf("%s%d", n.PeerAddress, n.PeerASN)]

		secret, ok, err := r.fetchSecret(secretRef)
		if err != nil {
			return "", fmt.Errorf("failed to fetch secret %q: %w", secretRef, err)
		}
		if !ok {
			if old != "" {
				l.Errorf("Failed to fetch secret %q: not found (will continue with old secret)", secretRef)
				return old, nil
			}
			l.Errorf("Failed to fetch secret %q: not found (will continue with empty password)", secretRef)
			return "", nil
		}
		tcpPassword := string(secret["password"])
		if tcpPassword == "" {
			return "", fmt.Errorf("failed to fetch secret %q: missing password key", secretRef)
		}
		l.Debugf("Using TCP password from secret %q", secretRef)
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
		return nil, ok, err
	}
	result := map[string][]byte{}
	for k, v := range item.Data {
		result[k] = []byte(v)
	}
	return result, true, nil
}

func (r *NeighborReconciler) changedPeerPassword(sc *ServerWithConfig, n *v2alpha1api.CiliumBGPNeighbor, tcpPassword string) bool {
	peerPasswords := r.getMetadata(sc)

	key := fmt.Sprintf("%s%d", n.PeerAddress, n.PeerASN)
	old := peerPasswords[key]
	return old != tcpPassword
}

func (r *NeighborReconciler) updatePeerPassword(sc *ServerWithConfig, n *v2alpha1api.CiliumBGPNeighbor, tcpPassword string) {
	peerPasswords := r.getMetadata(sc)

	key := fmt.Sprintf("%s%d", n.PeerAddress, n.PeerASN)
	peerPasswords[key] = tcpPassword
}

func hasLocalEndpoints(svc *slim_corev1.Service, ls localServices) bool {
	_, found := ls[k8s.ServiceID{Name: svc.GetName(), Namespace: svc.GetNamespace()}]
	return found
}

// fullReconciliation reconciles all services, this is a heavy operation due to the potential amount of services and
// thus should be avoided if partial reconciliation is an option.
func (r *LBServiceReconciler) fullReconciliation(ctx context.Context, sc *ServerWithConfig, newc *v2alpha1api.CiliumBGPVirtualRouter, ls localServices) error {
	// Loop over all existing announcements, delete announcements for services which no longer exist
	serviceAnnouncements := r.getMetadata(sc)
	for svcKey := range serviceAnnouncements {
		_, found, err := r.diffStore.GetByKey(svcKey)
		if err != nil {
			return fmt.Errorf("diffStore.GetByKey(); %w", err)
		}
		// if the service no longer exists, withdraw all associated routes
		if !found {
			if err := r.withdrawService(ctx, sc, svcKey); err != nil {
				return fmt.Errorf("withdrawService(): %w", err)
			}
			continue
		}
	}

	// Loop over all services, reconcile any updates to the service
	iter := r.diffStore.IterKeys()
	for iter.Next() {
		svcKey := iter.Key()
		svc, found, err := r.diffStore.GetByKey(iter.Key())
		if err != nil {
			return fmt.Errorf("diffStore.GetByKey(); %w", err)
		}
		if !found {
			// edgecase: If the service was removed between the call to IterKeys() and GetByKey()
			if err := r.withdrawService(ctx, sc, svcKey); err != nil {
				return fmt.Errorf("withdrawService(): %w", err)
			}
			continue
		}

		r.reconcileService(ctx, sc, newc, svc, ls)
	}
	return nil
}

// svcDiffReconciliation performs reconciliation, only on services which have been created, updated or deleted since
// the last diff reconciliation.
func (r *LBServiceReconciler) svcDiffReconciliation(ctx context.Context, sc *ServerWithConfig, newc *v2alpha1api.CiliumBGPVirtualRouter, ls localServices) error {
	upserted, deleted, err := r.diffStore.Diff()
	if err != nil {
		return fmt.Errorf("svc store diff: %w", err)
	}

	// For externalTrafficPolicy=local, we need to take care of
	// the endpoint changes in addition to the service changes.
	// Take a diff of the endpoints and get affected services.
	// We don't handle service deletion here since we only see
	// the key, we cannot resolve associated service, so we have
	// nothing to do.
	epsUpserted, _, err := r.epDiffStore.Diff()
	if err != nil {
		return fmt.Errorf("endpoints store diff: %w", err)
	}

	for _, eps := range epsUpserted {
		svc, exists, err := r.resolveSvcFromEndpoints(eps)
		if err != nil {
			// Cannot resolve service from endpoints. We have nothing to do here.
			continue
		}

		if !exists {
			// No service associated with this endpoint. We're not interested in this.
			continue
		}

		// We only need Endpoints tracking for externalTrafficPolicy=Local
		if svc.Spec.ExternalTrafficPolicy != slim_corev1.ServiceExternalTrafficPolicyLocal {
			continue
		}

		upserted = append(upserted, svc)
	}

	// We may have duplicated services that changes happened for both of
	// service and associated endpoints.
	deduped := ciliumslices.UniqueFunc(
		upserted,
		func(i int) resource.Key {
			return resource.Key{
				Name:      upserted[i].GetName(),
				Namespace: upserted[i].GetNamespace(),
			}
		},
	)

	for _, svc := range deduped {
		if err := r.reconcileService(ctx, sc, newc, svc, ls); err != nil {
			return fmt.Errorf("reconcile service: %w", err)
		}
	}

	// Loop over the deleted services
	for _, svcKey := range deleted {
		if err := r.withdrawService(ctx, sc, svcKey); err != nil {
			return fmt.Errorf("withdrawService(): %w", err)
		}
	}

	return nil
}

// svcDesiredRoutes determines which, if any routes should be announced for the given service. This determines the
// desired state.
func (r *LBServiceReconciler) svcDesiredRoutes(newc *v2alpha1api.CiliumBGPVirtualRouter, svc *slim_corev1.Service, ls localServices) ([]netip.Prefix, error) {
	if newc.ServiceSelector == nil {
		// If the vRouter has no service selector, there are no desired routes.
		return nil, nil
	}

	// Ignore non-loadbalancer services.
	if svc.Spec.Type != slim_corev1.ServiceTypeLoadBalancer {
		return nil, nil
	}

	// The vRouter has a service selector, so determine the desired routes.
	svcSelector, err := slim_metav1.LabelSelectorAsSelector(newc.ServiceSelector)
	if err != nil {
		return nil, fmt.Errorf("labelSelectorAsSelector: %w", err)
	}

	// Ignore non matching services.
	if !svcSelector.Matches(serviceLabelSet(svc)) {
		return nil, nil
	}

	// Ignore service managed by an unsupported LB class.
	if svc.Spec.LoadBalancerClass != nil && *svc.Spec.LoadBalancerClass != v2alpha1api.BGPLoadBalancerClass {
		// The service is managed by a different LB class.
		return nil, nil
	}

	// Ignore externalTrafficPolicy == Local && no local endpoints.
	if svc.Spec.ExternalTrafficPolicy == slim_corev1.ServiceExternalTrafficPolicyLocal &&
		!hasLocalEndpoints(svc, ls) {
		return nil, nil
	}

	var desiredRoutes []netip.Prefix
	for _, ingress := range svc.Status.LoadBalancer.Ingress {
		if ingress.IP == "" {
			continue
		}

		addr, err := netip.ParseAddr(ingress.IP)
		if err != nil {
			continue
		}

		desiredRoutes = append(desiredRoutes, netip.PrefixFrom(addr, addr.BitLen()))
	}

	return desiredRoutes, err
}

// reconcileService gets the desired routes of a given service and makes sure that is what is being announced.
// Adding missing announcements or withdrawing unwanted ones.
func (r *LBServiceReconciler) reconcileService(ctx context.Context, sc *ServerWithConfig, newc *v2alpha1api.CiliumBGPVirtualRouter, svc *slim_corev1.Service, ls localServices) error {
	serviceAnnouncements := r.getMetadata(sc)
	svcKey := resource.NewKey(svc)

	desiredCidrs, err := r.svcDesiredRoutes(newc, svc, ls)
	if err != nil {
		return fmt.Errorf("svcDesiredRoutes(): %w", err)
	}

	for _, desiredCidr := range desiredCidrs {
		// If this route has already been announced, don't add it again
		if slices.IndexFunc(serviceAnnouncements[svcKey], func(existing *types.Path) bool {
			return desiredCidr.String() == existing.NLRI.String()
		}) != -1 {
			continue
		}

		// Advertise the new cidr
		advertPathResp, err := sc.Server.AdvertisePath(ctx, types.PathRequest{
			Path: types.NewPathForPrefix(desiredCidr),
		})
		if err != nil {
			return fmt.Errorf("failed to advertise service route %v: %w", desiredCidr, err)
		}
		serviceAnnouncements[svcKey] = append(serviceAnnouncements[svcKey], advertPathResp.Path)
	}

	// Loop over announcements in reverse order so we can delete entries without effecting iteration.
	for i := len(serviceAnnouncements[svcKey]) - 1; i >= 0; i-- {
		announcement := serviceAnnouncements[svcKey][i]
		// If the announcement is within the list of desired routes, don't remove it
		if slices.IndexFunc(desiredCidrs, func(existing netip.Prefix) bool {
			return existing.String() == announcement.NLRI.String()
		}) != -1 {
			continue
		}

		if err := sc.Server.WithdrawPath(ctx, types.PathRequest{Path: announcement}); err != nil {
			return fmt.Errorf("failed to withdraw service route %s: %w", announcement.NLRI, err)
		}

		// Delete announcement from slice
		serviceAnnouncements[svcKey] = slices.Delete(serviceAnnouncements[svcKey], i, i+1)
	}

	return nil
}

// withdrawService removes all announcements for the given service
func (r *LBServiceReconciler) withdrawService(ctx context.Context, sc *ServerWithConfig, key resource.Key) error {
	serviceAnnouncements := r.getMetadata(sc)
	advertisements := serviceAnnouncements[key]
	// Loop in reverse order so we can delete without effect to the iteration.
	for i := len(advertisements) - 1; i >= 0; i-- {
		advertisement := advertisements[i]
		if err := sc.Server.WithdrawPath(ctx, types.PathRequest{Path: advertisement}); err != nil {
			// Persist remaining advertisements
			serviceAnnouncements[key] = advertisements
			return fmt.Errorf("failed to withdraw deleted service route: %v: %w", advertisement.NLRI, err)
		}

		// Delete the advertisement after each withdraw in case we error half way through
		advertisements = slices.Delete(advertisements, i, i+1)
	}

	// If all were withdrawn without error, we can delete the whole svc from the map
	delete(serviceAnnouncements, key)

	return nil
}

func serviceLabelSet(svc *slim_corev1.Service) labels.Labels {
	svcLabels := maps.Clone(svc.Labels)
	if svcLabels == nil {
		svcLabels = make(map[string]string)
	}
	svcLabels["io.kubernetes.service.name"] = svc.Name
	svcLabels["io.kubernetes.service.namespace"] = svc.Namespace
	return labels.Set(svcLabels)
}

func podIPPoolLabelSet(pool *v2alpha1api.CiliumPodIPPool) labels.Labels {
	poolLabels := maps.Clone(pool.Labels)
	if poolLabels == nil {
		poolLabels = make(map[string]string)
	}
	poolLabels[podIPPoolNameLabel] = pool.Name
	poolLabels[podIPPoolNamespaceLabel] = pool.Namespace
	return labels.Set(poolLabels)
}
