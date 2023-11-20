// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"context"
	"fmt"
	"net/netip"
	"slices"

	"golang.org/x/exp/maps"

	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	ciliumslices "github.com/cilium/cilium/pkg/slices"
)

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

	ls := r.populateLocalServices(p.CiliumNode.Name)

	if r.requiresFullReconciliation(p) {
		return r.fullReconciliation(ctx, p.CurrentServer, p.DesiredConfig, ls)
	}
	return r.svcDiffReconciliation(ctx, p.CurrentServer, p.DesiredConfig, ls)
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

// requiresFullReconciliation returns true if the desired config requires full reconciliation
// (reconciliation of all services), false if partial (diff) reconciliation is sufficient.
func (r *LBServiceReconciler) requiresFullReconciliation(p ReconcileParams) bool {
	var existingSelector *slim_metav1.LabelSelector
	if p.CurrentServer != nil && p.CurrentServer.Config != nil {
		existingSelector = p.CurrentServer.Config.ServiceSelector
	}
	// If the existing selector was updated, went from nil to something or something to nil, we need to perform full
	// reconciliation and check if every existing announcement's service still matches the selector.
	return (existingSelector != nil && p.DesiredConfig.ServiceSelector != nil && !p.DesiredConfig.ServiceSelector.DeepEqual(existingSelector)) ||
		((existingSelector == nil) != (p.DesiredConfig.ServiceSelector == nil))
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

func hasLocalEndpoints(svc *slim_corev1.Service, ls localServices) bool {
	_, found := ls[k8s.ServiceID{Name: svc.GetName(), Namespace: svc.GetNamespace()}]
	return found
}

// fullReconciliation reconciles all services, this is a heavy operation due to the potential amount of services and
// thus should be avoided if partial reconciliation is an option.
func (r *LBServiceReconciler) fullReconciliation(ctx context.Context, sc *ServerWithConfig, newc *v2alpha1api.CiliumBGPVirtualRouter, ls localServices) error {
	toReconcile, toWithdraw, err := r.fullReconciliationServiceList(sc)
	if err != nil {
		return err
	}
	for _, svc := range toReconcile {
		if err := r.reconcileService(ctx, sc, newc, svc, ls); err != nil {
			return fmt.Errorf("failed to reconcile service %s/%s: %w", svc.Namespace, svc.Name, err)
		}
	}
	for _, svc := range toWithdraw {
		if err := r.withdrawService(ctx, sc, svc); err != nil {
			return fmt.Errorf("failed to withdraw service %s/%s: %w", svc.Namespace, svc.Name, err)
		}
	}
	return nil
}

// svcDiffReconciliation performs reconciliation, only on services which have been created, updated or deleted since
// the last diff reconciliation.
func (r *LBServiceReconciler) svcDiffReconciliation(ctx context.Context, sc *ServerWithConfig, newc *v2alpha1api.CiliumBGPVirtualRouter, ls localServices) error {
	toReconcile, toWithdraw, err := r.diffReconciliationServiceList()
	if err != nil {
		return err
	}
	for _, svc := range toReconcile {
		if err := r.reconcileService(ctx, sc, newc, svc, ls); err != nil {
			return fmt.Errorf("failed to reconcile service %s/%s: %w", svc.Namespace, svc.Name, err)
		}
	}
	// Loop over the deleted services
	for _, svcKey := range toWithdraw {
		if err := r.withdrawService(ctx, sc, svcKey); err != nil {
			return fmt.Errorf("failed to withdraw service %s: %w", svcKey, err)
		}
	}
	return nil
}

// fullReconciliationServiceList return a list of services to reconcile and to withdraw when performing
// full service reconciliation.
func (r *LBServiceReconciler) fullReconciliationServiceList(sc *ServerWithConfig) (toReconcile []*slim_corev1.Service, toWithdraw []resource.Key, err error) {
	// Loop over all existing announcements, find announcements for services which no longer exist
	serviceAnnouncements := r.getMetadata(sc)
	for svcKey := range serviceAnnouncements {
		_, found, err := r.diffStore.GetByKey(svcKey)
		if err != nil {
			return nil, nil, fmt.Errorf("diffStore.GetByKey(): %w", err)
		}
		// if the service no longer exists, withdraw it
		if !found {
			toWithdraw = append(toWithdraw, svcKey)
		}
	}

	// Loop over all services, find services to reconcile
	iter := r.diffStore.IterKeys()
	for iter.Next() {
		svcKey := iter.Key()
		svc, found, err := r.diffStore.GetByKey(iter.Key())
		if err != nil {
			return nil, nil, fmt.Errorf("diffStore.GetByKey(): %w", err)
		}
		if !found {
			// edgecase: If the service was removed between the call to IterKeys() and GetByKey()
			toWithdraw = append(toWithdraw, svcKey)
			continue
		}
		toReconcile = append(toReconcile, svc)
	}

	return toReconcile, toWithdraw, nil
}

// diffReconciliationServiceList returns a list of services to reconcile and to withdraw when
// performing partial (diff) service reconciliation.
func (r *LBServiceReconciler) diffReconciliationServiceList() (toReconcile []*slim_corev1.Service, toWithdraw []resource.Key, err error) {
	upserted, deleted, err := r.diffStore.Diff()
	if err != nil {
		return nil, nil, fmt.Errorf("svc store diff: %w", err)
	}

	// For externalTrafficPolicy=local, we need to take care of
	// the endpoint changes in addition to the service changes.
	// Take a diff of the endpoints and get affected services.
	// We don't handle service deletion here since we only see
	// the key, we cannot resolve associated service, so we have
	// nothing to do.
	epsUpserted, _, err := r.epDiffStore.Diff()
	if err != nil {
		return nil, nil, fmt.Errorf("endpoints store diff: %w", err)
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

	return deduped, deleted, nil
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
func (r *LBServiceReconciler) reconcileService(ctx context.Context, sc *ServerWithConfig, newc *v2alpha1api.CiliumBGPVirtualRouter, svc *slim_corev1.Service, ls localServices) error {

	desiredRoutes, err := r.svcDesiredRoutes(newc, svc, ls)
	if err != nil {
		return fmt.Errorf("failed to retrieve svc desired routes: %w", err)
	}
	return r.reconcileServiceRoutes(ctx, sc, svc, desiredRoutes)
}

// reconcileServiceRoutes ensures that desired routes of a given service are announced,
// adding missing announcements or withdrawing unwanted ones.
func (r *LBServiceReconciler) reconcileServiceRoutes(ctx context.Context, sc *ServerWithConfig, svc *slim_corev1.Service, desiredRoutes []netip.Prefix) error {
	serviceAnnouncements := r.getMetadata(sc)
	svcKey := resource.NewKey(svc)

	for _, desiredCidr := range desiredRoutes {
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
		if slices.IndexFunc(desiredRoutes, func(existing netip.Prefix) bool {
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
