// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconcilerv2

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/manager/store"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	ciliumslices "github.com/cilium/cilium/pkg/slices"
)

type ServiceReconcilerOut struct {
	cell.Out

	Reconciler ConfigReconciler `group:"bgp-config-reconciler-v2"`
}

type ServiceReconcilerIn struct {
	cell.In

	Logger        logrus.FieldLogger
	PeerAdvert    *CiliumPeerAdvertisement
	LBIPPoolStore store.BGPCPResourceStore[*v2alpha1.CiliumLoadBalancerIPPool]
	SvcDiffStore  store.DiffStore[*slim_corev1.Service]
	EPDiffStore   store.DiffStore[*k8s.Endpoints]
}

type ServiceReconciler struct {
	logger       logrus.FieldLogger
	peerAdvert   *CiliumPeerAdvertisement
	lbPoolStore  store.BGPCPResourceStore[*v2alpha1.CiliumLoadBalancerIPPool]
	svcDiffStore store.DiffStore[*slim_corev1.Service]
	epDiffStore  store.DiffStore[*k8s.Endpoints]
}

func NewServiceReconciler(in ServiceReconcilerIn) ServiceReconcilerOut {
	if in.SvcDiffStore == nil || in.EPDiffStore == nil || in.LBIPPoolStore == nil {
		return ServiceReconcilerOut{}
	}

	return ServiceReconcilerOut{
		Reconciler: &ServiceReconciler{
			logger:       in.Logger,
			peerAdvert:   in.PeerAdvert,
			lbPoolStore:  in.LBIPPoolStore,
			svcDiffStore: in.SvcDiffStore,
			epDiffStore:  in.EPDiffStore,
		},
	}
}

// ServiceReconcilerMetadata holds any announced service CIDRs per address family.
type ServiceReconcilerMetadata struct {
	ServicePaths          ResourceAFPathsMap
	ServiceAdvertisements PeerAdvertisements
	ServiceRoutePolicies  ResourceRoutePolicyMap // contains cluster IP and external IP route policies
	LBPoolRoutePolicies   ResourceRoutePolicyMap // contains load balancer IP pool route policies
}

func (r *ServiceReconciler) getMetadata(i *instance.BGPInstance) ServiceReconcilerMetadata {
	if _, found := i.Metadata[r.Name()]; !found {
		i.Metadata[r.Name()] = ServiceReconcilerMetadata{
			ServicePaths:          make(ResourceAFPathsMap),
			ServiceAdvertisements: make(PeerAdvertisements),
			ServiceRoutePolicies:  make(ResourceRoutePolicyMap),
			LBPoolRoutePolicies:   make(ResourceRoutePolicyMap),
		}
	}
	return i.Metadata[r.Name()].(ServiceReconcilerMetadata)
}

func (r *ServiceReconciler) setMetadata(i *instance.BGPInstance, metadata ServiceReconcilerMetadata) {
	i.Metadata[r.Name()] = metadata
}

func (r *ServiceReconciler) Name() string {
	return "Service"
}

func (r *ServiceReconciler) Priority() int {
	return 40
}

func (r *ServiceReconciler) Reconcile(ctx context.Context, p ReconcileParams) error {
	if p.DesiredConfig == nil {
		return fmt.Errorf("BUG: attempted service reconciliation with nil CiliumBGPNodeConfig")
	}

	if p.CiliumNode == nil {
		return fmt.Errorf("BUG: attempted service reconciliation with nil local CiliumNode")
	}

	desiredPeerAdverts, err := r.peerAdvert.GetConfiguredAdvertisements(p.DesiredConfig, v2alpha1.BGPServiceAdvert)
	if err != nil {
		return err
	}

	ls, err := r.populateLocalServices(p.CiliumNode.Name)
	if err != nil {
		return fmt.Errorf("failed to populate local services: %w", err)
	}

	// must be done before reconciling paths and policies since it sets metadata with latest desiredPeerAdverts
	reqFullReconcile := r.modifiedServiceAdvertisements(p, desiredPeerAdverts)

	return r.reconcileServices(ctx, p, ls, reqFullReconcile)
}

func (r *ServiceReconciler) reconcileServices(ctx context.Context, p ReconcileParams, ls sets.Set[resource.Key], fullReconcile bool) error {
	var desiredSvcRoutePolicies ResourceRoutePolicyMap
	var desiredSvcPaths ResourceAFPathsMap
	var err error

	if fullReconcile {
		r.logger.Debug("performing all services reconciliation")

		desiredSvcRoutePolicies, err = r.getAllRoutePolicies(p, ls)
		if err != nil {
			return err
		}

		// BGP configuration for service advertisement changed, we should reconcile all services.
		desiredSvcPaths, err = r.getAllPaths(p, ls)
		if err != nil {
			return err
		}
	} else {
		r.logger.Debug("performing modified services reconciliation")

		// get services to reconcile and to withdraw.
		// Note : we should only call svc diff only once in a reconcile loop.
		toReconcile, toWithdraw, err := r.diffReconciliationServiceList()
		if err != nil {
			return err
		}

		desiredSvcRoutePolicies, err = r.getDiffRoutePolicies(p, toReconcile, toWithdraw, ls)
		if err != nil {
			return err
		}

		// BGP configuration is unchanged, only reconcile modified services.
		desiredSvcPaths, err = r.getDiffPaths(p, toReconcile, toWithdraw, ls)
		if err != nil {
			return err
		}
	}

	// reconcile service route policies
	err = r.reconcileSvcRoutePolicies(ctx, p, desiredSvcRoutePolicies)
	if err != nil {
		return fmt.Errorf("failed to reconcile service route policies: %w", err)
	}

	// reconcile LB pool route policies, we always do full reconciliation for LB pool route policies
	err = r.reconcileLBIPPoolRoutePolicies(ctx, p)
	if err != nil {
		return fmt.Errorf("failed to reconcile lb route policies: %w", err)
	}

	// reconcile service paths
	err = r.reconcilePaths(ctx, p, desiredSvcPaths)
	if err != nil {
		return fmt.Errorf("failed to reconcile service paths: %w", err)
	}

	return nil
}

func (r *ServiceReconciler) reconcileLBIPPoolRoutePolicies(ctx context.Context, p ReconcileParams) error {
	desiredLBRoutePolicies, err := r.getLBIPPoolRoutePolicies(p)
	if err != nil {
		return fmt.Errorf("failed to get desired lb route policies: %w", err)
	}

	metadata := r.getMetadata(p.BGPInstance)
	for lbPoolKey, desiredLBPoolRoutePolicies := range desiredLBRoutePolicies {
		currentLBPoolRoutePolicies, exists := metadata.LBPoolRoutePolicies[lbPoolKey]
		if !exists && len(desiredLBPoolRoutePolicies) == 0 {
			// no route policies to reconcile
			continue
		}

		updatedLBPoolRoutePolicies, rErr := ReconcileRoutePolicies(&ReconcileRoutePoliciesParams{
			Logger:          r.logger.WithField(types.InstanceLogField, p.DesiredConfig.Name),
			Ctx:             ctx,
			Router:          p.BGPInstance.Router,
			DesiredPolicies: desiredLBPoolRoutePolicies,
			CurrentPolicies: currentLBPoolRoutePolicies,
		})

		if rErr == nil && len(desiredLBPoolRoutePolicies) == 0 {
			// no error is reported and desiredLBPoolRoutePolicies is empty, we should delete the lbPool
			delete(metadata.LBPoolRoutePolicies, lbPoolKey)
		} else {
			// update lbPool route policies with returned updatedLBPoolRoutePolicies even if there was an error.
			metadata.LBPoolRoutePolicies[lbPoolKey] = updatedLBPoolRoutePolicies
		}
		err = errors.Join(err, rErr)
	}
	r.setMetadata(p.BGPInstance, metadata)

	return err
}

func (r *ServiceReconciler) getLBIPPoolRoutePolicies(p ReconcileParams) (ResourceRoutePolicyMap, error) {
	metadata := r.getMetadata(p.BGPInstance)

	desiredLBRoutePolicies := make(ResourceRoutePolicyMap)

	for lbPoolKey := range metadata.LBPoolRoutePolicies {
		_, exists, err := r.lbPoolStore.GetByKey(lbPoolKey)
		if err != nil {
			return nil, err
		}

		if !exists {
			// mark the route policy for deletion
			desiredLBRoutePolicies[lbPoolKey] = nil
		}
	}

	lbPools, err := r.lbPoolStore.List()
	if err != nil {
		return nil, fmt.Errorf("failed to list load balancer IP pools: %w", err)
	}

	for _, lbPool := range lbPools {
		desiredLBPoolRoutePolicies, err := r.getLBRoutePolicies(p, lbPool)
		if err != nil {
			return nil, err
		}

		// reconcile route policies for lbPool
		lbKey := resource.Key{
			Name:      lbPool.Name,
			Namespace: lbPool.Namespace,
		}

		desiredLBRoutePolicies[lbKey] = desiredLBPoolRoutePolicies
	}

	return desiredLBRoutePolicies, nil
}

func (r *ServiceReconciler) reconcileSvcRoutePolicies(ctx context.Context, p ReconcileParams, desiredSvcRoutePolicies ResourceRoutePolicyMap) error {
	var err error
	metadata := r.getMetadata(p.BGPInstance)
	for svcKey, desiredSvcRoutePolicies := range desiredSvcRoutePolicies {
		currentSvcRoutePolicies, exists := metadata.ServiceRoutePolicies[svcKey]
		if !exists && len(desiredSvcRoutePolicies) == 0 {
			continue
		}

		updatedSvcRoutePolicies, rErr := ReconcileRoutePolicies(&ReconcileRoutePoliciesParams{
			Logger:          r.logger.WithField(types.InstanceLogField, p.DesiredConfig.Name),
			Ctx:             ctx,
			Router:          p.BGPInstance.Router,
			DesiredPolicies: desiredSvcRoutePolicies,
			CurrentPolicies: currentSvcRoutePolicies,
		})

		if rErr == nil && len(desiredSvcRoutePolicies) == 0 {
			delete(metadata.ServiceRoutePolicies, svcKey)
		} else {
			metadata.ServiceRoutePolicies[svcKey] = updatedSvcRoutePolicies
		}
		err = errors.Join(err, rErr)
	}
	r.setMetadata(p.BGPInstance, metadata)

	return err
}

func (r *ServiceReconciler) getAllRoutePolicies(p ReconcileParams, ls sets.Set[resource.Key]) (ResourceRoutePolicyMap, error) {
	desiredSvcRoutePolicies := make(ResourceRoutePolicyMap)

	// check for services which are no longer present
	svcRoutePolicies := r.getMetadata(p.BGPInstance).ServiceRoutePolicies
	for svcKey := range svcRoutePolicies {
		_, exists, err := r.svcDiffStore.GetByKey(svcKey)
		if err != nil {
			return nil, fmt.Errorf("svcDiffStore.GetByKey(): %w", err)
		}

		// if the service no longer exists, withdraw it
		if !exists {
			desiredSvcRoutePolicies[svcKey] = nil
		}
	}

	// check all services for route policies
	svcList, err := r.svcDiffStore.List()
	if err != nil {
		return nil, fmt.Errorf("failed to list services from svcDiffstore: %w", err)
	}

	for _, svc := range svcList {
		svcKey := resource.Key{
			Name:      svc.GetName(),
			Namespace: svc.GetNamespace(),
		}

		// get desired route policies for the service
		svcRoutePolicies, err := r.getDesiredSvcRoutePolicies(p, svc, ls)
		if err != nil {
			return nil, err
		}

		desiredSvcRoutePolicies[svcKey] = svcRoutePolicies
	}

	return desiredSvcRoutePolicies, nil
}

func (r *ServiceReconciler) getDiffRoutePolicies(p ReconcileParams, toUpdate []*slim_corev1.Service, toRemove []resource.Key, ls sets.Set[resource.Key]) (ResourceRoutePolicyMap, error) {
	desiredSvcRoutePolicies := make(ResourceRoutePolicyMap)

	for _, svc := range toUpdate {
		svcKey := resource.Key{
			Name:      svc.GetName(),
			Namespace: svc.GetNamespace(),
		}

		// get desired route policies for the service
		svcRoutePolicies, err := r.getDesiredSvcRoutePolicies(p, svc, ls)
		if err != nil {
			return nil, err
		}

		desiredSvcRoutePolicies[svcKey] = svcRoutePolicies
	}

	for _, svcKey := range toRemove {
		// for withdrawn services, we need to set route policies to nil.
		desiredSvcRoutePolicies[svcKey] = nil
	}

	return desiredSvcRoutePolicies, nil
}

func (r *ServiceReconciler) getDesiredSvcRoutePolicies(p ReconcileParams, svc *slim_corev1.Service, ls sets.Set[resource.Key]) (RoutePolicyMap, error) {
	// get cluster IP route policy
	desiredClusterRoutePolicies, err := r.getClusterIPRoutePolicies(p, svc, ls)
	if err != nil {
		return nil, fmt.Errorf("failed to get desired cluster IP route policies: %w", err)
	}

	desiredExternalIPRoutePolicies, err := r.getExternalIPRoutePolicies(p, svc, ls)
	if err != nil {
		return nil, fmt.Errorf("failed to get desired external IP route policies: %w", err)
	}

	// merge two route policies, both will have unique names since name contains advertisement type
	desiredSvcRPs := desiredClusterRoutePolicies
	for k, v := range desiredExternalIPRoutePolicies {
		desiredSvcRPs[k] = v
	}

	return desiredSvcRPs, nil
}

func (r *ServiceReconciler) reconcilePaths(ctx context.Context, p ReconcileParams, desiredSvcPaths ResourceAFPathsMap) error {
	var err error
	metadata := r.getMetadata(p.BGPInstance)
	for svc, desiredAFPaths := range desiredSvcPaths {
		// check if service exists
		currentAFPaths, exists := metadata.ServicePaths[svc]
		if !exists && len(desiredAFPaths) == 0 {
			// service does not exist in our local state, and there is nothing to advertise
			continue
		}

		// reconcile service paths
		updatedAFPaths, rErr := ReconcileAFPaths(&ReconcileAFPathsParams{
			Logger:       r.logger.WithField(types.InstanceLogField, p.DesiredConfig.Name),
			Ctx:          ctx,
			Router:       p.BGPInstance.Router,
			DesiredPaths: desiredAFPaths,
			CurrentPaths: currentAFPaths,
		})

		if rErr == nil && len(desiredAFPaths) == 0 {
			// no error is reported and desiredAFPaths is empty, we should delete the service
			delete(metadata.ServicePaths, svc)
		} else {
			// update service paths with returned updatedAFPaths even if there was an error.
			metadata.ServicePaths[svc] = updatedAFPaths
		}
		err = errors.Join(err, rErr)
	}
	r.setMetadata(p.BGPInstance, metadata)

	return err
}

// modifiedServiceAdvertisements compares local advertisement state with desiredPeerAdverts, if they differ, it updates the local state and returns true
// for full reconciliation.
func (r *ServiceReconciler) modifiedServiceAdvertisements(p ReconcileParams, desiredPeerAdverts PeerAdvertisements) bool {
	// current metadata
	serviceMetadata := r.getMetadata(p.BGPInstance)

	// check if BGP advertisement configuration modified
	modified := !PeerAdvertisementsEqual(serviceMetadata.ServiceAdvertisements, desiredPeerAdverts)

	// update local state, if modified
	if modified {
		r.setMetadata(p.BGPInstance, ServiceReconcilerMetadata{
			ServicePaths:          serviceMetadata.ServicePaths,
			ServiceRoutePolicies:  serviceMetadata.ServiceRoutePolicies,
			LBPoolRoutePolicies:   serviceMetadata.LBPoolRoutePolicies,
			ServiceAdvertisements: desiredPeerAdverts,
		})
	}

	return modified
}

// Populate locally available services used for externalTrafficPolicy=local handling
func (r *ServiceReconciler) populateLocalServices(localNodeName string) (sets.Set[resource.Key], error) {
	ls := sets.New[resource.Key]()

	epList, err := r.epDiffStore.List()
	if err != nil {
		return nil, fmt.Errorf("failed to list EPs from diffstore: %w", err)
	}

endpointsLoop:
	for _, eps := range epList {
		_, exists, err := r.resolveSvcFromEndpoints(eps)
		if err != nil {
			// Cannot resolve service from EPs. We have nothing to do here.
			continue
		}

		if !exists {
			// No service associated with this endpoint. We're not interested in this.
			continue
		}

		svcKey := resource.Key{
			Name:      eps.ServiceID.Name,
			Namespace: eps.ServiceID.Namespace,
		}

		for _, be := range eps.Backends {
			if !be.Terminating && be.NodeName == localNodeName {
				// At least one endpoint is available on this node. We
				// can add service to the local services set.
				ls.Insert(svcKey)
				continue endpointsLoop
			}
		}
	}

	return ls, nil
}

func hasLocalEndpoints(svc *slim_corev1.Service, ls sets.Set[resource.Key]) bool {
	return ls.Has(resource.Key{Name: svc.GetName(), Namespace: svc.GetNamespace()})
}

func (r *ServiceReconciler) resolveSvcFromEndpoints(eps *k8s.Endpoints) (*slim_corev1.Service, bool, error) {
	k := resource.Key{
		Name:      eps.ServiceID.Name,
		Namespace: eps.ServiceID.Namespace,
	}
	return r.svcDiffStore.GetByKey(k)
}

func (r *ServiceReconciler) getAllPaths(p ReconcileParams, ls sets.Set[resource.Key]) (ResourceAFPathsMap, error) {
	desiredServiceAFPaths := make(ResourceAFPathsMap)

	// check for services which are no longer present
	serviceAFPaths := r.getMetadata(p.BGPInstance).ServicePaths
	for svcKey := range serviceAFPaths {
		_, exists, err := r.svcDiffStore.GetByKey(svcKey)
		if err != nil {
			return nil, fmt.Errorf("svcDiffStore.GetByKey(): %w", err)
		}

		// if the service no longer exists, withdraw it
		if !exists {
			desiredServiceAFPaths[svcKey] = nil
		}
	}

	// check all services for advertisement
	svcList, err := r.svcDiffStore.List()
	if err != nil {
		return nil, fmt.Errorf("failed to list services from svcDiffstore: %w", err)
	}

	for _, svc := range svcList {
		svcKey := resource.Key{
			Name:      svc.GetName(),
			Namespace: svc.GetNamespace(),
		}

		afPaths, err := r.getServiceAFPaths(p, svc, ls)
		if err != nil {
			return nil, err
		}

		desiredServiceAFPaths[svcKey] = afPaths
	}

	return desiredServiceAFPaths, nil
}

func (r *ServiceReconciler) getDiffPaths(p ReconcileParams, toReconcile []*slim_corev1.Service, toWithdraw []resource.Key, ls sets.Set[resource.Key]) (ResourceAFPathsMap, error) {
	desiredServiceAFPaths := make(ResourceAFPathsMap)
	for _, svc := range toReconcile {
		svcKey := resource.Key{
			Name:      svc.GetName(),
			Namespace: svc.GetNamespace(),
		}

		afPaths, err := r.getServiceAFPaths(p, svc, ls)
		if err != nil {
			return nil, err
		}

		desiredServiceAFPaths[svcKey] = afPaths
	}

	for _, svcKey := range toWithdraw {
		// for withdrawn services, we need to set paths to nil.
		desiredServiceAFPaths[svcKey] = nil
	}

	return desiredServiceAFPaths, nil
}

// diffReconciliationServiceList returns a list of services to reconcile and to withdraw when
// performing partial (diff) service reconciliation.
func (r *ServiceReconciler) diffReconciliationServiceList() (toReconcile []*slim_corev1.Service, toWithdraw []resource.Key, err error) {
	upserted, deleted, err := r.svcDiffStore.Diff()
	if err != nil {
		return nil, nil, fmt.Errorf("svc store diff: %w", err)
	}

	// For externalTrafficPolicy=local, we need to take care of
	// the endpoint changes in addition to the service changes.
	// Take a diff of the EPs and get affected services.
	// We don't handle service deletion here since we only see
	// the key, we cannot resolve associated service, so we have
	// nothing to do.
	epsUpserted, _, err := r.epDiffStore.Diff()
	if err != nil {
		return nil, nil, fmt.Errorf("EPs store diff: %w", err)
	}

	for _, eps := range epsUpserted {
		svc, exists, err := r.resolveSvcFromEndpoints(eps)
		if err != nil {
			// Cannot resolve service from EPs. We have nothing to do here.
			continue
		}

		if !exists {
			// No service associated with this endpoint. We're not interested in this.
			continue
		}

		// We only need Endpoints tracking for externalTrafficPolicy=Local or internalTrafficPolicy=Local services.
		if svc.Spec.ExternalTrafficPolicy == slim_corev1.ServiceExternalTrafficPolicyLocal ||
			(svc.Spec.InternalTrafficPolicy != nil && *svc.Spec.InternalTrafficPolicy == slim_corev1.ServiceInternalTrafficPolicyLocal) {
			upserted = append(upserted, svc)
		}
	}

	// We may have duplicated services that changes happened for both of
	// service and associated EPs.
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

func (r *ServiceReconciler) getServiceAFPaths(p ReconcileParams, svc *slim_corev1.Service, ls sets.Set[resource.Key]) (AFPathsMap, error) {
	desiredFamilyAdverts := make(AFPathsMap)
	metadata := r.getMetadata(p.BGPInstance)

	for _, peerFamilyAdverts := range metadata.ServiceAdvertisements {
		for family, familyAdverts := range peerFamilyAdverts {
			agentFamily := types.ToAgentFamily(family)

			for _, advert := range familyAdverts {
				// get prefixes for the service
				desiredPrefixes, err := r.getServicePrefixes(svc, advert, ls)
				if err != nil {
					return nil, err
				}

				for _, prefix := range desiredPrefixes {
					path := types.NewPathForPrefix(prefix)
					path.Family = agentFamily

					// we only add path corresponding to the family of the prefix.
					if agentFamily.Afi == types.AfiIPv4 && prefix.Addr().Is4() {
						addPathToAFPathsMap(desiredFamilyAdverts, agentFamily, path)
					}
					if agentFamily.Afi == types.AfiIPv6 && prefix.Addr().Is6() {
						addPathToAFPathsMap(desiredFamilyAdverts, agentFamily, path)
					}
				}
			}
		}
	}
	return desiredFamilyAdverts, nil
}

func (r *ServiceReconciler) getServicePrefixes(svc *slim_corev1.Service, advert v2alpha1.BGPAdvertisement, ls sets.Set[resource.Key]) ([]netip.Prefix, error) {
	if advert.AdvertisementType != v2alpha1.BGPServiceAdvert {
		return nil, fmt.Errorf("unexpected advertisement type: %s", advert.AdvertisementType)
	}

	if advert.Selector == nil || advert.Service == nil {
		// advertisement has no selector or no service options, default behavior is not to match any service.
		return nil, nil
	}

	// The vRouter has a service selector, so determine the desired routes.
	svcSelector, err := slim_metav1.LabelSelectorAsSelector(advert.Selector)
	if err != nil {
		return nil, fmt.Errorf("labelSelectorAsSelector: %w", err)
	}

	// Ignore non matching services.
	if !svcSelector.Matches(serviceLabelSet(svc)) {
		return nil, nil
	}

	var desiredRoutes []netip.Prefix
	// Loop over the service upsertAdverts and determine the desired routes.
	for _, svcAdv := range advert.Service.Addresses {
		switch svcAdv {
		case v2alpha1.BGPLoadBalancerIPAddr:
			desiredRoutes = append(desiredRoutes, r.getLBSvcPaths(svc, ls)...)
		case v2alpha1.BGPClusterIPAddr:
			desiredRoutes = append(desiredRoutes, r.getClusterIPPaths(svc, ls)...)
		case v2alpha1.BGPExternalIPAddr:
			desiredRoutes = append(desiredRoutes, r.getExternalIPPaths(svc, ls)...)
		}
	}

	return desiredRoutes, nil
}

func (r *ServiceReconciler) getExternalIPPaths(svc *slim_corev1.Service, ls sets.Set[resource.Key]) []netip.Prefix {
	var desiredRoutes []netip.Prefix
	// Ignore externalTrafficPolicy == Local && no local EPs.
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

func (r *ServiceReconciler) getClusterIPPaths(svc *slim_corev1.Service, ls sets.Set[resource.Key]) []netip.Prefix {
	var desiredRoutes []netip.Prefix
	// Ignore internalTrafficPolicy == Local && no local EPs.
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

func (r *ServiceReconciler) getLBSvcPaths(svc *slim_corev1.Service, ls sets.Set[resource.Key]) []netip.Prefix {
	var desiredRoutes []netip.Prefix
	if svc.Spec.Type != slim_corev1.ServiceTypeLoadBalancer {
		return desiredRoutes
	}
	// Ignore externalTrafficPolicy == Local && no local EPs.
	if svc.Spec.ExternalTrafficPolicy == slim_corev1.ServiceExternalTrafficPolicyLocal &&
		!hasLocalEndpoints(svc, ls) {
		return desiredRoutes
	}
	// Ignore service managed by an unsupported LB class.
	if svc.Spec.LoadBalancerClass != nil && *svc.Spec.LoadBalancerClass != v2alpha1.BGPLoadBalancerClass {
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

func (r *ServiceReconciler) getLBRoutePolicies(p ReconcileParams, lbPool *v2alpha1.CiliumLoadBalancerIPPool) (RoutePolicyMap, error) {
	desiredLBPoolRoutePolicies := make(RoutePolicyMap)

	for peer, afAdverts := range r.getMetadata(p.BGPInstance).ServiceAdvertisements {
		for fam, adverts := range afAdverts {
			agentFamily := types.ToAgentFamily(fam)

			for _, advert := range adverts {
				policy, err := r.getLBRoutePolicy(p, peer, agentFamily, lbPool, advert)
				if err != nil {
					return nil, fmt.Errorf("failed to get desired lb route policy: %w", err)
				}
				if policy != nil {
					desiredLBPoolRoutePolicies[policy.Name] = policy
				}
			}
		}
	}

	return desiredLBPoolRoutePolicies, nil
}

func (r *ServiceReconciler) getLBRoutePolicy(p ReconcileParams, peer string, family types.Family, lbPool *v2alpha1.CiliumLoadBalancerIPPool, advert v2alpha1.BGPAdvertisement) (*types.RoutePolicy, error) {

	peerAddr, err := GetPeerAddressFromConfig(p.DesiredConfig, peer)
	if err != nil {
		return nil, fmt.Errorf("failed to get peer address: %w", err)
	}

	valid, err := checkServiceAdvertisement(advert, v2alpha1.BGPLoadBalancerIPAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to check service advertisement: %w", err)
	}

	if !valid || lbPool.Spec.Disabled {
		return nil, nil
	}

	labelSelector, err := slim_metav1.LabelSelectorAsSelector(advert.Selector)
	if err != nil {
		return nil, fmt.Errorf("failed constructing LabelSelector: %w", err)
	}

	// check if advertisement matches lb pool labels
	if !labelSelector.Matches(labels.Set(lbPool.Labels)) {
		return nil, nil
	}

	var v4Prefixes, v6Prefixes types.PolicyPrefixMatchList

	for _, cidrBlock := range lbPool.Spec.Blocks {
		cidr, err := netip.ParsePrefix(string(cidrBlock.Cidr))
		if err != nil {
			r.logger.WithError(err).Warnf("failed to parse IPAM pool CIDR %s", cidrBlock.Cidr)
			continue
		}

		if family.Afi == types.AfiIPv4 && cidr.Addr().Is4() {
			v4Prefixes = append(v4Prefixes, &types.RoutePolicyPrefixMatch{CIDR: cidr, PrefixLenMin: MaxPrefixLenIPv4, PrefixLenMax: MaxPrefixLenIPv4})
		}

		if family.Afi == types.AfiIPv6 && cidr.Addr().Is6() {
			v6Prefixes = append(v6Prefixes, &types.RoutePolicyPrefixMatch{CIDR: cidr, PrefixLenMin: MaxPrefixLenIPv6, PrefixLenMax: MaxPrefixLenIPv6})
		}
	}

	// if there are no prefixes found, return nil
	if len(v4Prefixes) == 0 && len(v6Prefixes) == 0 {
		return nil, nil
	}

	policyName := PolicyName(peer, family.Afi.String(), advert.AdvertisementType, lbPool.Name)
	policy, err := CreatePolicy(policyName, peerAddr, v4Prefixes, v6Prefixes, advert)
	if err != nil {
		return nil, fmt.Errorf("failed to create lb pool route policy: %w", err)
	}

	return policy, nil
}

func (r *ServiceReconciler) getExternalIPRoutePolicies(p ReconcileParams, svc *slim_corev1.Service, ls sets.Set[resource.Key]) (RoutePolicyMap, error) {
	desiredSvcRoutePolicies := make(RoutePolicyMap)

	for peer, afAdverts := range r.getMetadata(p.BGPInstance).ServiceAdvertisements {
		for fam, adverts := range afAdverts {
			agentFamily := types.ToAgentFamily(fam)

			for _, advert := range adverts {
				policy, err := r.getExternalIPRoutePolicy(p, peer, agentFamily, svc, advert, ls)
				if err != nil {
					return nil, fmt.Errorf("failed to get desired external IP route policy: %w", err)
				}
				if policy != nil {
					desiredSvcRoutePolicies[policy.Name] = policy
				}
			}
		}
	}

	return desiredSvcRoutePolicies, nil
}

func (r *ServiceReconciler) getExternalIPRoutePolicy(p ReconcileParams, peer string, family types.Family, svc *slim_corev1.Service, advert v2alpha1.BGPAdvertisement, ls sets.Set[resource.Key]) (*types.RoutePolicy, error) {
	// get the peer address
	peerAddr, err := GetPeerAddressFromConfig(p.DesiredConfig, peer)
	if err != nil {
		return nil, fmt.Errorf("failed to get peer address: %w", err)
	}

	valid, err := checkServiceAdvertisement(advert, v2alpha1.BGPExternalIPAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to check service advertisement: %w", err)
	}

	if !valid {
		return nil, nil
	}

	labelSelector, err := slim_metav1.LabelSelectorAsSelector(advert.Selector)
	if err != nil {
		return nil, fmt.Errorf("failed constructing LabelSelector: %w", err)
	}

	if !labelSelector.Matches(serviceLabelSet(svc)) {
		return nil, nil
	}

	// Ignore externalTrafficPolicy == Local && no local EPs.
	if svc.Spec.ExternalTrafficPolicy == slim_corev1.ServiceExternalTrafficPolicyLocal &&
		!hasLocalEndpoints(svc, ls) {
		return nil, nil
	}

	var v4Prefixes, v6Prefixes types.PolicyPrefixMatchList
	for _, extIP := range svc.Spec.ExternalIPs {
		if extIP == "" {
			continue
		}
		addr, err := netip.ParseAddr(extIP)
		if err != nil {
			continue
		}

		if family.Afi == types.AfiIPv4 && addr.Is4() {
			v4Prefixes = append(v4Prefixes, &types.RoutePolicyPrefixMatch{CIDR: netip.PrefixFrom(addr, addr.BitLen()), PrefixLenMin: addr.BitLen(), PrefixLenMax: addr.BitLen()})
		}

		if family.Afi == types.AfiIPv6 && addr.Is6() {
			v6Prefixes = append(v6Prefixes, &types.RoutePolicyPrefixMatch{CIDR: netip.PrefixFrom(addr, addr.BitLen()), PrefixLenMin: addr.BitLen(), PrefixLenMax: addr.BitLen()})
		}
	}

	if len(v4Prefixes) == 0 && len(v6Prefixes) == 0 {
		return nil, nil
	}

	policyName := PolicyName(peer, family.Afi.String(), advert.AdvertisementType, fmt.Sprintf("%s-%s-%s", svc.Name, svc.Namespace, v2alpha1.BGPExternalIPAddr))
	policy, err := CreatePolicy(policyName, peerAddr, v4Prefixes, v6Prefixes, advert)
	if err != nil {
		return nil, fmt.Errorf("failed to create external IP route policy: %w", err)
	}

	return policy, nil
}

func (r *ServiceReconciler) getClusterIPRoutePolicies(p ReconcileParams, svc *slim_corev1.Service, ls sets.Set[resource.Key]) (RoutePolicyMap, error) {
	desiredSvcRoutePolicies := make(RoutePolicyMap)

	for peer, afAdverts := range r.getMetadata(p.BGPInstance).ServiceAdvertisements {
		for fam, adverts := range afAdverts {
			agentFamily := types.ToAgentFamily(fam)

			for _, advert := range adverts {
				policy, err := r.getClusterIPRoutePolicy(p, peer, agentFamily, svc, advert, ls)
				if err != nil {
					return nil, fmt.Errorf("failed to get desired cluster IP route policy: %w", err)
				}
				if policy != nil {
					desiredSvcRoutePolicies[policy.Name] = policy
				}
			}
		}
	}

	return desiredSvcRoutePolicies, nil
}

func (r *ServiceReconciler) getClusterIPRoutePolicy(p ReconcileParams, peer string, family types.Family, svc *slim_corev1.Service, advert v2alpha1.BGPAdvertisement, ls sets.Set[resource.Key]) (*types.RoutePolicy, error) {
	// get the peer address
	peerAddr, err := GetPeerAddressFromConfig(p.DesiredConfig, peer)
	if err != nil {
		return nil, fmt.Errorf("failed to get peer address: %w", err)
	}

	valid, err := checkServiceAdvertisement(advert, v2alpha1.BGPClusterIPAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to check service advertisement: %w", err)
	}

	if !valid {
		return nil, nil
	}

	labelSelector, err := slim_metav1.LabelSelectorAsSelector(advert.Selector)
	if err != nil {
		return nil, fmt.Errorf("failed constructing LabelSelector: %w", err)
	}

	if !labelSelector.Matches(serviceLabelSet(svc)) {
		return nil, nil
	}

	// Ignore internalTrafficPolicy == Local && no local EPs.
	if svc.Spec.InternalTrafficPolicy != nil && *svc.Spec.InternalTrafficPolicy == slim_corev1.ServiceInternalTrafficPolicyLocal &&
		!hasLocalEndpoints(svc, ls) {
		return nil, nil
	}

	var v4Prefixes, v6Prefixes types.PolicyPrefixMatchList

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

		if family.Afi == types.AfiIPv4 && addr.Is4() {
			v4Prefixes = append(v4Prefixes, &types.RoutePolicyPrefixMatch{CIDR: netip.PrefixFrom(addr, addr.BitLen()), PrefixLenMin: addr.BitLen(), PrefixLenMax: addr.BitLen()})
		}

		if family.Afi == types.AfiIPv6 && addr.Is6() {
			v6Prefixes = append(v6Prefixes, &types.RoutePolicyPrefixMatch{CIDR: netip.PrefixFrom(addr, addr.BitLen()), PrefixLenMin: addr.BitLen(), PrefixLenMax: addr.BitLen()})
		}
	}

	if len(v4Prefixes) == 0 && len(v6Prefixes) == 0 {
		return nil, nil
	}

	policyName := PolicyName(peer, family.Afi.String(), advert.AdvertisementType, fmt.Sprintf("%s-%s-%s", svc.Name, svc.Namespace, v2alpha1.BGPClusterIPAddr))
	policy, err := CreatePolicy(policyName, peerAddr, v4Prefixes, v6Prefixes, advert)
	if err != nil {
		return nil, fmt.Errorf("failed to create cluster IP route policy: %w", err)
	}

	return policy, nil
}

// checkServiceAdvertisement checks if the service advertisement is enabled in the advertisement.
func checkServiceAdvertisement(advert v2alpha1.BGPAdvertisement, advertServiceType v2alpha1.BGPServiceAddressType) (bool, error) {
	if advert.Service == nil {
		return false, fmt.Errorf("BUG: advertisement has no service options")
	}

	// If selector is nil, we do not use this advertisement.
	if advert.Selector == nil {
		return false, nil
	}

	// check service type is enabled in advertisement
	svcTypeEnabled := false
	for _, serviceType := range advert.Service.Addresses {
		if serviceType == advertServiceType {
			svcTypeEnabled = true
			break
		}
	}
	if !svcTypeEnabled {
		return false, nil
	}

	return true, nil
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
