// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"fmt"
	"maps"
	"net"
	"net/netip"

	"github.com/Potterli20/golibs-fork/netutil"
	"github.com/cilium/hive/cell"
	"github.com/projectdiscovery/mapcidr"
	"go4.org/netipx"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/manager/store"
	"github.com/cilium/cilium/pkg/bgpv1/types"
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

type ServiceReconciler struct {
	diffStore   store.DiffStore[*slim_corev1.Service]
	epDiffStore store.DiffStore[*k8s.Endpoints]
}

// LBServiceReconcilerMetadata keeps a map of services to the respective advertised Paths
type LBServiceReconcilerMetadata map[resource.Key][]*types.Path

type localServices map[k8s.ServiceID]struct{}

// pathReference holds reference information about an advertised path
type pathReference struct {
	count uint32
	path  *types.Path
}

// pathReferencesMap holds path references of resources producing path advertisement, indexed by path's NLRI string
type pathReferencesMap map[string]*pathReference

type RoutesMap map[resource.Key]map[*netip.Prefix]*types.Path

func NewServiceReconciler(diffStore store.DiffStore[*slim_corev1.Service], epDiffStore store.DiffStore[*k8s.Endpoints]) LBServiceReconcilerOut {
	if diffStore == nil {
		return LBServiceReconcilerOut{}
	}

	return LBServiceReconcilerOut{
		Reconciler: &ServiceReconciler{
			diffStore:   diffStore,
			epDiffStore: epDiffStore,
		},
	}
}

func (r *ServiceReconciler) Name() string {
	return "Service"
}

func (r *ServiceReconciler) Priority() int {
	// ServiceReconciler.Priority() > RoutePolicyReconciler.Priority()
	return 80
}

func (r *ServiceReconciler) Init(sc *instance.ServerWithConfig) error {
	if sc == nil {
		return fmt.Errorf("BUG: service reconciler initialization with nil ServerWithConfig")
	}
	r.diffStore.InitDiff(r.diffID(sc.ASN))
	r.epDiffStore.InitDiff(r.diffID(sc.ASN))
	return nil
}

func (r *ServiceReconciler) Cleanup(sc *instance.ServerWithConfig) {
	if sc != nil {
		r.diffStore.CleanupDiff(r.diffID(sc.ASN))
		r.epDiffStore.CleanupDiff(r.diffID(sc.ASN))
	}
}

func (r *ServiceReconciler) Reconcile(ctx context.Context, p ReconcileParams) error {
	sc := p.CurrentServer

	if p.CiliumNode == nil {
		return fmt.Errorf("attempted service reconciliation with nil local CiliumNode")
	}

	var reconciliationServiceList func(*instance.ServerWithConfig) ([]*slim_corev1.Service, []resource.Key, error)
	if r.requiresFullReconciliation(p) {
		// reconciliation for all services, this is a heavy operation due to the potential amount of services and
		// thus should be avoided if partial reconciliation is an option.
		reconciliationServiceList = r.fullReconciliationServiceList
	} else {
		// reconciliation for only on services which have been created, updated or deleted since the last diff reconciliation.
		reconciliationServiceList = r.diffReconciliationServiceList
	}

	toReconcile, toWithdraw, err := reconciliationServiceList(sc)
	if err != nil {
		return err
	}

	if len(toReconcile) > 0 || len(toWithdraw) > 0 {
		if err := r.updateRoutes(ctx, sc, toReconcile, toWithdraw, p); err != nil {
			return fmt.Errorf("failed to update routes: %w", err)
		}
	}

	return nil
}

func (r *ServiceReconciler) getMetadata(sc *instance.ServerWithConfig) LBServiceReconcilerMetadata {
	if _, found := sc.ReconcilerMetadata[r.Name()]; !found {
		sc.ReconcilerMetadata[r.Name()] = make(LBServiceReconcilerMetadata)
	}
	return sc.ReconcilerMetadata[r.Name()].(LBServiceReconcilerMetadata)
}

func (r *ServiceReconciler) getRoutes(sc *instance.ServerWithConfig) RoutesMap {
	if _, found := sc.ReconcilerMetadata["RoutesMap"]; !found {
		sc.ReconcilerMetadata["RoutesMap"] = make(RoutesMap)
	}
	return sc.ReconcilerMetadata["RoutesMap"].(RoutesMap)
}

func (r *ServiceReconciler) resolveSvcFromEndpoints(eps *k8s.Endpoints) (*slim_corev1.Service, bool, error) {
	k := resource.Key{
		Name:      eps.ServiceID.Name,
		Namespace: eps.ServiceID.Namespace,
	}
	return r.diffStore.GetByKey(k)
}

// requiresFullReconciliation returns true if the desired config requires full reconciliation
// (reconciliation of all services), false if partial (diff) reconciliation is sufficient.
func (r *ServiceReconciler) requiresFullReconciliation(p ReconcileParams) bool {
	var existingSelector *slim_metav1.LabelSelector
	if p.CurrentServer != nil && p.CurrentServer.Config != nil {
		existingSelector = p.CurrentServer.Config.ServiceSelector
	} else {
		return true // the first reconciliation should be always full
	}
	// If the existing selector was updated, went from nil to something or something to nil, we need to perform full
	// reconciliation and check if every existing announcement's service still matches the selector.
	return (existingSelector != nil && p.DesiredConfig.ServiceSelector != nil && !p.DesiredConfig.ServiceSelector.DeepEqual(existingSelector)) ||
		((existingSelector == nil) != (p.DesiredConfig.ServiceSelector == nil))
}

// Populate locally available services used for externalTrafficPolicy=local handling
func (r *ServiceReconciler) populateLocalServices(localNodeName string) (localServices, error) {
	ls := make(localServices)

	epList, err := r.epDiffStore.List()
	if err != nil {
		return nil, fmt.Errorf("failed to list endpoints from diffstore: %w", err)
	}

endpointsLoop:
	for _, eps := range epList {
		_, exists, err := r.resolveSvcFromEndpoints(eps)
		if err != nil {
			// Cannot resolve service from endpoints. We have nothing to do here.
			continue
		}

		if !exists {
			// No service associated with this endpoint. We're not interested in this.
			continue
		}

		svcID := eps.ServiceID

		for _, be := range eps.Backends {
			if !be.Terminating && be.NodeName == localNodeName {
				// At least one endpoint is available on this node. We
				// can make unavailable to available.
				if _, found := ls[svcID]; !found {
					ls[svcID] = struct{}{}
				}
				continue endpointsLoop
			}
		}
	}

	return ls, nil
}

func hasLocalEndpoints(svc *slim_corev1.Service, ls localServices) bool {
	_, found := ls[k8s.ServiceID{Name: svc.GetName(), Namespace: svc.GetNamespace()}]
	return found
}

// fullReconciliationServiceList return a list of services to reconcile and to withdraw when performing
// full service reconciliation.
func (r *ServiceReconciler) fullReconciliationServiceList(sc *instance.ServerWithConfig) (toReconcile []*slim_corev1.Service, toWithdraw []resource.Key, err error) {
	// Init diff in diffstores, so that it contains only changes since the last full reconciliation.
	// Despite doing it in Init(), we still need this InitDiff to clean up the old diff when the instance is re-created
	// by the preflight reconciler. Once Init() is called upon re-create by preflight, we can remove this.
	r.diffStore.InitDiff(r.diffID(sc.ASN))
	r.epDiffStore.InitDiff(r.diffID(sc.ASN))

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

	// Reconcile all existing services
	svcList, err := r.diffStore.List()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list services from diffstore: %w", err)
	}
	toReconcile = append(toReconcile, svcList...)

	return toReconcile, toWithdraw, nil
}

// diffReconciliationServiceList returns a list of services to reconcile and to withdraw when
// performing partial (diff) service reconciliation.
func (r *ServiceReconciler) diffReconciliationServiceList(sc *instance.ServerWithConfig) (toReconcile []*slim_corev1.Service, toWithdraw []resource.Key, err error) {
	upserted, deleted, err := r.diffStore.Diff(r.diffID(sc.ASN))
	if err != nil {
		return nil, nil, fmt.Errorf("svc store diff: %w", err)
	}

	// For externalTrafficPolicy=local, we need to take care of
	// the endpoint changes in addition to the service changes.
	// Take a diff of the endpoints and get affected services.
	// We don't handle service deletion here since we only see
	// the key, we cannot resolve associated service, so we have
	// nothing to do.
	epsUpserted, _, err := r.epDiffStore.Diff(r.diffID(sc.ASN))
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

		// We only need Endpoints tracking for externalTrafficPolicy=Local or internalTrafficPolicy=Local.
		if svc.Spec.ExternalTrafficPolicy == slim_corev1.ServiceExternalTrafficPolicyLocal ||
			(svc.Spec.InternalTrafficPolicy != nil && *svc.Spec.InternalTrafficPolicy == slim_corev1.ServiceInternalTrafficPolicyLocal) {
			upserted = append(upserted, svc)
		}
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
func (r *ServiceReconciler) svcDesiredRoutes(newc *v2alpha1api.CiliumBGPVirtualRouter, svc *slim_corev1.Service, ls localServices) ([]netip.Prefix, error) {
	if newc.ServiceSelector == nil {
		// If the vRouter has no service selector, there are no desired routes.
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

	var desiredRoutes []netip.Prefix
	// Loop over the service advertisements and determine the desired routes.
	for _, svcAdv := range newc.ServiceAdvertisements {
		switch svcAdv {
		case v2alpha1api.BGPLoadBalancerIPAddr:
			desiredRoutes = append(desiredRoutes, r.lbSvcDesiredRoutes(svc, ls)...)
		case v2alpha1api.BGPClusterIPAddr:
			desiredRoutes = append(desiredRoutes, r.clusterIPDesiredRoutes(svc, ls)...)
		case v2alpha1api.BGPExternalIPAddr:
			desiredRoutes = append(desiredRoutes, r.externalIPDesiredRoutes(svc, ls)...)
		}
	}

	return desiredRoutes, err
}

func (r *ServiceReconciler) externalIPDesiredRoutes(svc *slim_corev1.Service, ls localServices) []netip.Prefix {
	var desiredRoutes []netip.Prefix
	// Ignore externalTrafficPolicy == Local && no local endpoints.
	if svc.Spec.ExternalTrafficPolicy == slim_corev1.ServiceExternalTrafficPolicyLocal &&
		!hasLocalEndpoints(svc, ls) {
		return desiredRoutes
	}
	for _, extIP := range svc.Spec.ExternalIPs {
		if extIP == "" {
			continue
		}
		addr, err := netip.ParseAddr(extIP)
		if err != nil {
			continue
		}
		desiredRoutes = append(desiredRoutes, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return desiredRoutes
}

func (r *ServiceReconciler) clusterIPDesiredRoutes(svc *slim_corev1.Service, ls localServices) []netip.Prefix {
	var desiredRoutes []netip.Prefix
	// Ignore internalTrafficPolicy == Local && no local endpoints.
	if svc.Spec.InternalTrafficPolicy != nil && *svc.Spec.InternalTrafficPolicy == slim_corev1.ServiceInternalTrafficPolicyLocal &&
		!hasLocalEndpoints(svc, ls) {
		return desiredRoutes
	}
	if svc.Spec.ClusterIP == "" || len(svc.Spec.ClusterIPs) == 0 || svc.Spec.ClusterIP == corev1.ClusterIPNone {
		return desiredRoutes
	}
	ips := sets.New[string]()
	if svc.Spec.ClusterIP != "" {
		ips.Insert(svc.Spec.ClusterIP)
	}
	for _, clusterIP := range svc.Spec.ClusterIPs {
		if clusterIP == "" || clusterIP == corev1.ClusterIPNone {
			continue
		}
		ips.Insert(clusterIP)
	}
	for _, ip := range sets.List(ips) {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			continue
		}
		desiredRoutes = append(desiredRoutes, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return desiredRoutes
}

func (r *ServiceReconciler) lbSvcDesiredRoutes(svc *slim_corev1.Service, ls localServices) []netip.Prefix {
	var desiredRoutes []netip.Prefix
	if svc.Spec.Type != slim_corev1.ServiceTypeLoadBalancer {
		return desiredRoutes
	}
	// Ignore externalTrafficPolicy == Local && no local endpoints.
	if svc.Spec.ExternalTrafficPolicy == slim_corev1.ServiceExternalTrafficPolicyLocal &&
		!hasLocalEndpoints(svc, ls) {
		return desiredRoutes
	}
	// Ignore service managed by an unsupported LB class.
	if svc.Spec.LoadBalancerClass != nil && *svc.Spec.LoadBalancerClass != v2alpha1api.BGPLoadBalancerClass {
		// The service is managed by a different LB class.
		return desiredRoutes
	}
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
	return desiredRoutes
}

func (r *ServiceReconciler) diffID(asn uint32) string {
	return fmt.Sprintf("%s-%d", r.Name(), asn)
}

func (r *ServiceReconciler) advertisePath(ctx context.Context, sc *instance.ServerWithConfig, pathRefs pathReferencesMap, prefix netip.Prefix) (*types.Path, error) {
	if ref, exists := pathRefs[prefix.String()]; exists && ref.count > 0 {
		// path already advertised for another resource
		ref.count += 1
		return ref.path, nil
	}

	advertPathResp, err := sc.Server.AdvertisePath(ctx, types.PathRequest{
		Path: types.NewPathForPrefix(prefix),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to advertise service route %v: %w", prefix, err)
	}

	// set only in case of no error
	pathRefs[prefix.String()] = &pathReference{
		count: 1,
		path:  advertPathResp.Path,
	}
	return advertPathResp.Path, nil
}

func (r *ServiceReconciler) withdrawPath(ctx context.Context, sc *instance.ServerWithConfig, pathRefs pathReferencesMap, path *types.Path) error {
	if ref, exists := pathRefs[path.NLRI.String()]; exists && ref.count > 1 {
		// path still needs to be advertised for another resource
		ref.count -= 1
		return nil
	}

	if err := sc.Server.WithdrawPath(ctx, types.PathRequest{Path: path}); err != nil {
		return fmt.Errorf("failed to withdraw service route %s: %w", path.NLRI, err)
	}

	// delete only in case of no error
	delete(pathRefs, path.NLRI.String())
	return nil
}

func (r *ServiceReconciler) computePathReferences(metadata LBServiceReconcilerMetadata) pathReferencesMap {
	pathRefs := make(pathReferencesMap)
	for _, resPaths := range metadata {
		for _, path := range resPaths {
			ref, exists := pathRefs[path.NLRI.String()]
			if !exists {
				pathRefs[path.NLRI.String()] = &pathReference{
					count: 1,
					path:  path,
				}
			} else {
				ref.count += 1
			}
		}
	}
	return pathRefs
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

func (r *ServiceReconciler) getSumDesiredRoutes(sc *instance.ServerWithConfig, desiredEndPoints map[*netip.Prefix]bool) (map[*netip.Prefix]bool, error) {
	toSummarizeRoutes := make(map[*netip.Prefix]bool)
	sumDesiredRoutes := make(map[*netip.Prefix]bool)

	lbPool := sc.ReconcilerMetadata["lbPool"]
	lbPoolList := lbPool.([]types.LbPool)
	for desiredCidr := range desiredEndPoints {
		for _, lbPool := range lbPoolList {
			if lbPool.Summarize {
				for _, cidr := range lbPool.Cidrs {
					cidrPrefix := netip.MustParsePrefix(cidr.String())
					//check if service ip-addr in loadbalancer pool
					if desiredCidr.Overlaps(cidrPrefix) {
						// Separate routes by summarization flag
						if lbPool.Summarize {
							toSummarizeRoutes[desiredCidr] = true
						} else {
							sumDesiredRoutes[desiredCidr] = true
						}
					}
				}
			}
		}
	}

	// The variable to_SummarizeRoutes is needed to convert map *netip.Prefix to []*netip.IPNet
	var toSummarizeRoutesIPNet []*net.IPNet
	for cidr := range toSummarizeRoutes {
		toSummarizeRoutesIPNet = append(toSummarizeRoutesIPNet, netipx.PrefixIPNet(*cidr))
	}

	summarizedRoutes := make(map[*netip.Prefix]bool)
	if len(toSummarizeRoutesIPNet) != 1 {
		// Summarize (aggregate) routes with summarization flag
		summarizedRoutesLst, _ := mapcidr.AggregateApproxIPs(toSummarizeRoutesIPNet)
		for _, route := range summarizedRoutesLst {
			// Convert back *netip.Prefix to map *netip.IPNet
			routePref, err := netutil.IPNetToPrefixNoMapped(route)
			if err != nil {
				return nil, fmt.Errorf("failed to *netip.Prefix to map *netip.IPNet: %w", err)
			}
			summarizedRoutes[&routePref] = true
		}
	} else {
		routePref, err := netutil.IPNetToPrefixNoMapped(toSummarizeRoutesIPNet[0])
		if err != nil {
			return nil, fmt.Errorf("failed to *netip.Prefix to map *netip.IPNet: %w", err)
		}
		summarizedRoutes[&routePref] = true
	}

	maps.Copy(sumDesiredRoutes, summarizedRoutes)

	return sumDesiredRoutes, nil
}

func (r *ServiceReconciler) updateRoutes(ctx context.Context, sc *instance.ServerWithConfig, toReconcile []*slim_corev1.Service, toWithdraw []resource.Key, p ReconcileParams) error {
	newc := p.DesiredConfig

	serviceAnnouncements := r.getMetadata(sc)
	_ = serviceAnnouncements

	// compute existing path to resource references
	pathRefs := r.computePathReferences(r.getMetadata(sc))

	routes := r.getRoutes(sc)

	ls, err := r.populateLocalServices(p.CiliumNode.Name)
	if err != nil {
		return err
	}

	// Endpoint means an advertised ip-address of service
	desiredEndPoints := make(map[*netip.Prefix]bool)
	for _, svc := range toReconcile {
		svcKey := resource.NewKey(svc)
		if _, ok := routes[svcKey]; !ok {
			routes[svcKey] = make(map[*netip.Prefix]*types.Path)
		}
		desiredRoutes, err := r.svcDesiredRoutes(newc, svc, ls)
		if err != nil {
			return fmt.Errorf("failed to retrieve svc desired routes: %w", err)
		}
		for _, cidr := range desiredRoutes {
			desiredEndPoints[&cidr] = true
		}

		sumDesiredRoutes, err := r.getSumDesiredRoutes(sc, desiredEndPoints)
		if err != nil {
			return err
		}

		for cidr := range routes[svcKey] {
			// Check if the advertised cidr is desired
			_, ok := sumDesiredRoutes[cidr]
			if !ok {
				if err := r.withdrawPath(ctx, sc, pathRefs, routes[svcKey][cidr]); err != nil {
					return fmt.Errorf("failed to withdraw service route %s: %w", cidr, err)
				}
				delete(routes[svcKey], cidr)
			}
		}

		for cidr := range sumDesiredRoutes {
			// Check if the cidr is new
			_, ok := routes[svcKey][cidr]
			if !ok {
				path, err := r.advertisePath(ctx, sc, pathRefs, *cidr)
				if err != nil {
					return err
				}
				routes[svcKey][cidr] = path
			}
		}
	}

	for _, svcKey := range toWithdraw {
		for cidr := range routes[svcKey] {
			if err := r.withdrawPath(ctx, sc, pathRefs, routes[svcKey][cidr]); err != nil {
				return fmt.Errorf("failed to withdraw service route %s: %w", cidr, err)
			}
			delete(routes[svcKey], cidr)
		}
	}

	return nil
}
