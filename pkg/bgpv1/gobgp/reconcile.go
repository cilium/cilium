// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gobgp

import (
	"context"
	"fmt"
	"net"

	gobgp "github.com/osrg/gobgp/v3/api"
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"

	"github.com/cilium/cilium/pkg/bgpv1/agent"
	"github.com/cilium/cilium/pkg/hive/cell"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// ConfigReconciler is a interface for reconciling a particular aspect
// of an old and new *v2alpha1api.CiliumBGPVirtualRouter
type ConfigReconciler interface {
	// Priority is used to determine the order in which reconcilers are called. Reconcilers are called from lowest to
	// highest.
	Priority() int
	// If the `Config` field in `sc` is nil the reconciler should unconditionally
	// perform the reconciliation actions, as no previous configuration is present.
	Reconcile(ctx context.Context, m *BGPRouterManager, sc *ServerWithConfig, newc *v2alpha1api.CiliumBGPVirtualRouter, cstate *agent.ControlPlaneState) error
}

var ConfigReconcilers = cell.ProvidePrivate(
	NewPreflightReconciler,
	NewNeighborReconciler,
	NewExportPodCIDRReconciler,
	NewLBServiceReconciler,
)

type preflightReconcilerOut struct {
	cell.Out

	Reconciler ConfigReconciler `group:"bgp-config-reconciler"`
}

type PreflightReconciler struct{}

func NewPreflightReconciler() preflightReconcilerOut {
	return preflightReconcilerOut{
		Reconciler: &PreflightReconciler{},
	}
}

func (r *PreflightReconciler) Priority() int {
	return 10
}

func (r *PreflightReconciler) Reconcile(ctx context.Context, m *BGPRouterManager, sc *ServerWithConfig, newc *v2alpha1api.CiliumBGPVirtualRouter, cstate *agent.ControlPlaneState) error {
	return preflightReconciler(ctx, m, sc, newc, cstate)
}

// preflightReconciler is a preflight task before any other reconciliation should
// take place.
//
// this reconciler handles any changes in current and desired BgpState which leads
// to a recreation of an existing BgpServer.
//
// this must be done first so that the following reconciliation functions act
// upon the recreated BgpServer with the desired permanent configurations.
//
// permanent configurations for gobgp BgpServers (ones that cannot be changed after creation)
// are router ID and local listening port.
func preflightReconciler(ctx context.Context, _ *BGPRouterManager, sc *ServerWithConfig, newc *v2alpha1api.CiliumBGPVirtualRouter, cstate *agent.ControlPlaneState) error {
	var (
		l = log.WithFields(
			logrus.Fields{
				"component": "gobgp.preflightReconciler",
			},
		)
	)

	// If we have no config attached, we don't need to perform a preflight for
	// reconciliation.
	//
	// This is the first time this server is being registered and BGPRouterManager
	// set any fields needing reconciliation in this function already.
	if sc.Config == nil {
		l.Debugf("Preflight for virtual router with ASN %v not necessary, first instantiation of this BgpServer.", newc.LocalASN)
		return nil
	}

	l.Debugf("Begin preflight reoncilation for virtual router with ASN %v", newc.LocalASN)
	bgpInfo, err := sc.Server.GetBgp(ctx, &gobgp.GetBgpRequest{})
	if err != nil {
		return fmt.Errorf("failed to retrieve BgpServer info for virtual router with ASN %v: %w", newc.LocalASN, err)
	}

	// resolve local port from kubernetes annotations
	var localPort int32
	localPort = -1
	if attrs, ok := cstate.Annotations[newc.LocalASN]; ok {
		if attrs.LocalPort != 0 {
			localPort = int32(attrs.LocalPort)
		}
	}

	// resolve router ID, if we have an annotation and it can be parsed into
	// a valid ipv4 address use this,
	//
	// if not determine if Cilium is configured with an IPv4 address, if so use
	// this.
	//
	// if neither, return an error, we cannot assign an router ID.
	var routerID string
	_, ok := cstate.Annotations[newc.LocalASN]
	switch {
	case ok && !net.ParseIP(cstate.Annotations[newc.LocalASN].RouterID).IsUnspecified():
		routerID = cstate.Annotations[newc.LocalASN].RouterID
	case !cstate.IPv4.IsUnspecified():
		routerID = cstate.IPv4.String()
	default:
		return fmt.Errorf("router id not specified by annotation and no IPv4 address assigned by cilium, cannot resolve router id for virtual router with local ASN %v", newc.LocalASN)
	}

	var shouldRecreate bool
	if localPort != bgpInfo.Global.ListenPort {
		shouldRecreate = true
		l.Infof("Virtual router with ASN %v local port has changed from %v to %v", newc.LocalASN, bgpInfo.Global.ListenPort, localPort)
	}
	if routerID != bgpInfo.Global.RouterId {
		shouldRecreate = true
		l.Infof("Virtual router with ASN %v router ID has changed from %v to %v", newc.LocalASN, bgpInfo.Global.RouterId, routerID)
	}
	if !shouldRecreate {
		l.Debugf("No preflight reconciliation necessary for virtual router with local ASN %v", newc.LocalASN)
		return nil
	}

	l.Infof("Recreating virtual router with ASN %v for changes to take effect", newc.LocalASN)

	startReq := &gobgp.StartBgpRequest{
		Global: &gobgp.Global{
			Asn:        uint32(newc.LocalASN),
			RouterId:   routerID,
			ListenPort: localPort,
			RouteSelectionOptions: &gobgp.RouteSelectionOptionsConfig{
				AdvertiseInactiveRoutes: true,
			},
		},
	}

	// stop the old BgpServer
	sc.Server.Stop()

	// create a new one via ServerWithConfig constructor
	s, err := NewServerWithConfig(ctx, startReq)
	if err != nil {
		l.WithError(err).Errorf("Failed to start BGP server for virtual router with local ASN %v", newc.LocalASN)
		return fmt.Errorf("failed to start BGP server for virtual router with local ASN %v: %w", newc.LocalASN, err)
	}

	// replace the old underlying server with our recreated one
	sc.Server = s.Server

	// dump the existing config so all subsequent reconcilers perform their
	// actions as if this is a new BgpServer.
	sc.Config = nil

	// Clear the shadow state since any advertisements will be gone now that the server has been recreated.
	sc.PodCIDRAnnouncements = nil
	sc.ServiceAnnouncements = make(map[resource.Key][]Advertisement)

	return nil
}

type neighborReconcilerOut struct {
	cell.Out

	Reconciler ConfigReconciler `group:"bgp-config-reconciler"`
}

type NeighborReconciler struct{}

func NewNeighborReconciler() neighborReconcilerOut {
	return neighborReconcilerOut{
		Reconciler: &NeighborReconciler{},
	}
}

func (r *NeighborReconciler) Priority() int {
	return 20
}

func (r *NeighborReconciler) Reconcile(ctx context.Context, m *BGPRouterManager, sc *ServerWithConfig, newc *v2alpha1api.CiliumBGPVirtualRouter, cstate *agent.ControlPlaneState) error {
	return neighborReconciler(ctx, m, sc, newc, cstate)
}

// neighborReconciler is a ConfigReconcilerFunc which reconciles the peers of
// the provided BGP server with the provided CiliumBGPVirtualRouter.
func neighborReconciler(ctx context.Context, _ *BGPRouterManager, sc *ServerWithConfig, newc *v2alpha1api.CiliumBGPVirtualRouter, _ *agent.ControlPlaneState) error {
	if newc == nil {
		return fmt.Errorf("attempted neighbor reconciliation with nil CiliumBGPPeeringPolicy")
	}
	if sc == nil {
		return fmt.Errorf("attempted neighbor reconciliation with nil ServerWithConfig")
	}
	var (
		l = log.WithFields(
			logrus.Fields{
				"component": "gobgp.neighborReconciler",
			},
		)
		toCreate []*v2alpha1api.CiliumBGPNeighbor
		toRemove []*v2alpha1api.CiliumBGPNeighbor
		curNeigh []v2alpha1api.CiliumBGPNeighbor = nil
	)
	newNeigh := newc.Neighbors
	l.Debugf("Begin reconciling peers for virtual router with local ASN %v", newc.LocalASN)

	// sc.Config can be nil if there is no previous configuration.
	if sc.Config != nil {
		curNeigh = sc.Config.Neighbors
	}

	// an nset member which book keeps which universe it exists in.
	type member struct {
		a bool
		b bool
		n *v2alpha1api.CiliumBGPNeighbor
	}

	nset := map[string]*member{}

	// populate set from universe a, new neighbors
	for i, n := range newNeigh {
		var (
			key = fmt.Sprintf("%s%d", n.PeerAddress, n.PeerASN)
			h   *member
			ok  bool
		)
		if h, ok = nset[key]; !ok {
			nset[key] = &member{
				a: true,
				n: &newNeigh[i],
			}
			continue
		}
		h.a = true
	}

	// populate set from universe b, current neighbors
	for i, n := range curNeigh {
		var (
			key = fmt.Sprintf("%s%d", n.PeerAddress, n.PeerASN)
			h   *member
			ok  bool
		)
		if h, ok = nset[key]; !ok {
			nset[key] = &member{
				b: true,
				n: &curNeigh[i],
			}
			continue
		}
		h.b = true
	}

	for _, m := range nset {
		// present in new neighbors (set a) but not in current neighbors (set b)
		if m.a && !m.b {
			toCreate = append(toCreate, m.n)
		}
		// present in current neighbors (set b) but not in new neighbors (set a)
		if m.b && !m.a {
			toRemove = append(toRemove, m.n)
		}
	}

	if len(toCreate) > 0 || len(toRemove) > 0 {
		l.Infof("Reconciling peers for virtual router with local ASN %v", newc.LocalASN)
	} else {
		l.Debugf("No peer changes necessary for virtual router with local ASN %v", newc.LocalASN)
	}

	// create new neighbors
	for _, n := range toCreate {
		l.Infof("Adding peer %v %v to local ASN %v", n.PeerAddress, n.PeerASN, newc.LocalASN)
		if err := sc.AddNeighbor(ctx, n); err != nil {
			return fmt.Errorf("failed while reconciling neighbor %v %v: %w", n.PeerAddress, n.PeerASN, err)
		}
	}

	// remove neighbors
	for _, n := range toRemove {
		l.Infof("Removing peer %v %v to local ASN %v", n.PeerAddress, n.PeerASN, newc.LocalASN)
		if err := sc.RemoveNeighbor(ctx, n); err != nil {
			return fmt.Errorf("failed while reconciling neighbor %v %v: %w", n.PeerAddress, n.PeerASN, err)
		}
	}

	l.Infof("Done reconciling peers for virtual router with local ASN %v", newc.LocalASN)
	return nil
}

type exportPodCIDRReconcilerOut struct {
	cell.Out

	Reconciler ConfigReconciler `group:"bgp-config-reconciler"`
}

type ExportPodCIDRReconciler struct{}

func NewExportPodCIDRReconciler() exportPodCIDRReconcilerOut {
	return exportPodCIDRReconcilerOut{
		Reconciler: &ExportPodCIDRReconciler{},
	}
}

func (r *ExportPodCIDRReconciler) Priority() int {
	return 30
}

func (r *ExportPodCIDRReconciler) Reconcile(ctx context.Context, m *BGPRouterManager, sc *ServerWithConfig, newc *v2alpha1api.CiliumBGPVirtualRouter, cstate *agent.ControlPlaneState) error {
	return exportPodCIDRReconciler(ctx, m, sc, newc, cstate)
}

// exportPodCIDRReconciler is a ConfigReconcilerFunc which reconciles the
// advertisement of the private Kubernetes PodCIDR block.
func exportPodCIDRReconciler(ctx context.Context, _ *BGPRouterManager, sc *ServerWithConfig, newc *v2alpha1api.CiliumBGPVirtualRouter, cstate *agent.ControlPlaneState) error {
	if newc == nil {
		return fmt.Errorf("attempted pod CIDR advertisements reconciliation with nil CiliumBGPPeeringPolicy")
	}
	if sc == nil {
		return fmt.Errorf("attempted pod CIDR advertisements reconciliation with nil ServerWithConfig")
	}
	if cstate == nil {
		return fmt.Errorf("attempted pod CIDR advertisements reconciliation with nil ControlPlaneState")
	}

	toAdvertise := []*net.IPNet{}
	for _, cidr := range cstate.PodCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("failed to parse cidr %s: %w", cidr, err)
		}
		toAdvertise = append(toAdvertise, ipNet)
	}

	advertisements, err := exportAdvertisementsReconciler(&advertisementsReconcilerParams{
		ctx:       ctx,
		name:      "pod CIDR",
		component: "gobgp.exportPodCIDRReconciler",
		enabled:   newc.ExportPodCIDR,

		sc:   sc,
		newc: newc,

		currentAdvertisements: sc.PodCIDRAnnouncements,
		toAdvertise:           toAdvertise,
	})

	if err != nil {
		return err
	}

	// Update the server config's list of current advertisements only if the
	// reconciliation logic didn't return any error
	sc.PodCIDRAnnouncements = advertisements
	return nil
}

type lbServiceReconcilerOut struct {
	cell.Out

	Reconciler ConfigReconciler `group:"bgp-config-reconciler"`
}

type LBServiceReconciler struct {
	diffStore DiffStore[*slim_corev1.Service]
}

func NewLBServiceReconciler(diffStore DiffStore[*slim_corev1.Service]) lbServiceReconcilerOut {
	if diffStore == nil {
		return lbServiceReconcilerOut{}
	}

	return lbServiceReconcilerOut{
		Reconciler: &LBServiceReconciler{
			diffStore: diffStore,
		},
	}
}

func (r *LBServiceReconciler) Priority() int {
	return 40
}

func (r *LBServiceReconciler) Reconcile(
	ctx context.Context,
	m *BGPRouterManager,
	sc *ServerWithConfig,
	newc *v2alpha1api.CiliumBGPVirtualRouter,
	cstate *agent.ControlPlaneState,
) error {
	var existingSelector *slim_metav1.LabelSelector
	if sc != nil && sc.Config != nil {
		existingSelector = sc.Config.ServiceSelector
	}

	// If the existing selector was updated, went from nil to something or something to nil, we need to perform full
	// reconciliation and check if every existing announcement's service still matches the selector.
	changed := (existingSelector != nil && newc.ServiceSelector != nil && !newc.ServiceSelector.DeepEqual(existingSelector)) ||
		((existingSelector == nil) != (newc.ServiceSelector == nil))

	if changed {
		if err := r.fullReconciliation(ctx, m, sc, newc, cstate); err != nil {
			return fmt.Errorf("full reconciliation: %w", err)
		}

		return nil
	}

	if err := r.svcDiffReconciliation(ctx, m, sc, newc, cstate); err != nil {
		return fmt.Errorf("svc Diff reconciliation: %w", err)
	}

	return nil
}

// fullReconciliation reconciles all services, this is a heavy operation due to the potential amount of services and
// thus should be avoided if partial reconciliation is an option.
func (r *LBServiceReconciler) fullReconciliation(ctx context.Context, m *BGPRouterManager, sc *ServerWithConfig, newc *v2alpha1api.CiliumBGPVirtualRouter, cstate *agent.ControlPlaneState) error {
	// Loop over all existing announcements, delete announcements for services which no longer exist
	for svcKey := range sc.ServiceAnnouncements {
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

		r.reconcileService(ctx, sc, newc, svc)
	}
	return nil
}

// svcDiffReconciliation performs reconciliation, only on services which have been created, updated or deleted since
// the last diff reconciliation.
func (r *LBServiceReconciler) svcDiffReconciliation(ctx context.Context, m *BGPRouterManager, sc *ServerWithConfig, newc *v2alpha1api.CiliumBGPVirtualRouter, cstate *agent.ControlPlaneState) error {
	upserted, deleted, err := r.diffStore.Diff()
	if err != nil {
		return fmt.Errorf("svc store diff: %w", err)
	}

	for _, svc := range upserted {
		if err := r.reconcileService(ctx, sc, newc, svc); err != nil {
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
func (r *LBServiceReconciler) svcDesiredRoutes(newc *v2alpha1api.CiliumBGPVirtualRouter, svc *slim_corev1.Service) ([]*net.IPNet, error) {
	if newc.ServiceSelector == nil {
		// If the vRouter has no service selector, there are no desired routes
		return nil, nil
	}

	// Ignore non-loadbalancer services
	if svc.Spec.Type != slim_corev1.ServiceTypeLoadBalancer {
		return nil, nil
	}

	svcSelector, err := slim_metav1.LabelSelectorAsSelector(newc.ServiceSelector)
	if err != nil {
		return nil, fmt.Errorf("labelSelectorAsSelector: %w", err)
	}

	// Ignore non matching services
	if !svcSelector.Matches(serviceLabelSet(svc)) {
		return nil, nil
	}

	var desiredRoutes []*net.IPNet
	for _, ingress := range svc.Status.LoadBalancer.Ingress {
		if ingress.IP == "" {
			continue
		}

		cidr := &net.IPNet{
			IP: net.ParseIP(ingress.IP),
		}
		if cidr.IP.To4() == nil {
			cidr.Mask = net.CIDRMask(128, 128)
		} else {
			cidr.Mask = net.CIDRMask(32, 32)
		}

		desiredRoutes = append(desiredRoutes, cidr)
	}

	return desiredRoutes, err
}

// reconcileService gets the desired routes of a given service and makes sure that is what is being announced.
// Adding missing announcements or withdrawing unwanted ones.
func (r *LBServiceReconciler) reconcileService(ctx context.Context, sc *ServerWithConfig, newc *v2alpha1api.CiliumBGPVirtualRouter, svc *slim_corev1.Service) error {
	svcKey := resource.NewKey(svc)

	desiredCidrs, err := r.svcDesiredRoutes(newc, svc)
	if err != nil {
		return fmt.Errorf("svcDesiredRoutes(): %w", err)
	}

	for _, desiredCidr := range desiredCidrs {
		// If this route has already been announced, don't add it again
		if slices.IndexFunc(sc.ServiceAnnouncements[svcKey], func(existing Advertisement) bool {
			return cidrEqual(desiredCidr, existing.Net)
		}) != -1 {
			continue
		}

		// Advertise the new cidr
		advert, err := sc.AdvertisePath(ctx, desiredCidr)
		if err != nil {
			return fmt.Errorf("failed to advertise service route %v: %w", desiredCidr, err)
		}
		sc.ServiceAnnouncements[svcKey] = append(sc.ServiceAnnouncements[svcKey], advert)
	}

	// Loop over announcements in reverse order so we can delete entries without effecting iteration.
	for i := len(sc.ServiceAnnouncements[svcKey]) - 1; i >= 0; i-- {
		announcement := sc.ServiceAnnouncements[svcKey][i]
		// If the announcement is within the list of desired routes, don't remove it
		if slices.IndexFunc(desiredCidrs, func(existing *net.IPNet) bool {
			return cidrEqual(existing, announcement.Net)
		}) != -1 {
			continue
		}

		if err := sc.WithdrawPath(ctx, announcement); err != nil {
			return fmt.Errorf("failed to withdraw service route %s: %w", announcement, err)
		}

		// Delete announcement from slice
		sc.ServiceAnnouncements[svcKey] = slices.Delete(sc.ServiceAnnouncements[svcKey], i, i+1)
	}

	return nil
}

// withdrawService removes all announcements for the given service
func (r *LBServiceReconciler) withdrawService(ctx context.Context, sc *ServerWithConfig, key resource.Key) error {
	advertisements := sc.ServiceAnnouncements[key]
	// Loop in reverse order so we can delete without effect to the iteration.
	for i := len(advertisements) - 1; i >= 0; i-- {
		advertisement := advertisements[i]
		if err := sc.WithdrawPath(ctx, advertisement); err != nil {
			// Persist remaining advertisements
			sc.ServiceAnnouncements[key] = advertisements
			return fmt.Errorf("failed to withdraw deleted service route: %v: %w", advertisement.Net, err)
		}

		// Delete the advertisement after each withdraw in case we error half way through
		advertisements = slices.Delete(advertisements, i, i+1)
	}

	// If all were withdrawn without error, we can delete the whole svc from the map
	delete(sc.ServiceAnnouncements, key)

	return nil
}

func cidrEqual(a, b *net.IPNet) bool {
	aOnes, aSize := a.Mask.Size()
	bOnes, bSize := b.Mask.Size()
	return a.IP.Equal(b.IP) && aOnes == bOnes && aSize == bSize
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
