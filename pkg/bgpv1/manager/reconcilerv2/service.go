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

	Logger       logrus.FieldLogger
	PeerAdvert   *CiliumPeerAdvertisement
	SvcDiffStore store.DiffStore[*slim_corev1.Service]
	EPDiffStore  store.DiffStore[*k8s.Endpoints]
}

type ServiceReconciler struct {
	logger       logrus.FieldLogger
	peerAdvert   *CiliumPeerAdvertisement
	svcDiffStore store.DiffStore[*slim_corev1.Service]
	epDiffStore  store.DiffStore[*k8s.Endpoints]
}

func NewServiceReconciler(in ServiceReconcilerIn) ServiceReconcilerOut {
	if in.SvcDiffStore == nil || in.EPDiffStore == nil {
		in.Logger.Warn("ServiceReconciler: DiffStore is nil, skipping ServiceReconciler")
		return ServiceReconcilerOut{}
	}

	return ServiceReconcilerOut{
		Reconciler: &ServiceReconciler{
			logger:       in.Logger,
			peerAdvert:   in.PeerAdvert,
			svcDiffStore: in.SvcDiffStore,
			epDiffStore:  in.EPDiffStore,
		},
	}
}

// ServiceAFPathsMap holds the service prefixes per address family.
type ServiceAFPathsMap map[resource.Key]AFPathsMap

// ServiceReconcilerMetadata holds any announced service CIDRs per address family.
type ServiceReconcilerMetadata struct {
	ServicePaths          ServiceAFPathsMap
	ServiceAdvertisements PeerAdvertisements
}

func (r *ServiceReconciler) getMetadata(i *instance.BGPInstance) ServiceReconcilerMetadata {
	if _, found := i.Metadata[r.Name()]; !found {
		i.Metadata[r.Name()] = ServiceReconcilerMetadata{
			ServicePaths:          make(ServiceAFPathsMap),
			ServiceAdvertisements: make(PeerAdvertisements),
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

	var desiredSvcPaths ServiceAFPathsMap
	if r.modifiedServiceAdvertisements(p, desiredPeerAdverts) {
		// BGP configuration for service advertisement changed, we should reconcile all services.
		desiredSvcPaths, err = r.fullReconciliation(p, ls)
		if err != nil {
			return err
		}
	} else {
		// BGP configuration is unchanged, only reconcile modified services.
		desiredSvcPaths, err = r.svcDiffReconciliation(p, ls)
		if err != nil {
			return err
		}
	}

	var allErr error
	for svc, desiredAFPaths := range desiredSvcPaths {
		metadata := r.getMetadata(p.BGPInstance)

		// check if service exists
		currentAFPaths, exists := metadata.ServicePaths[svc]
		if !exists && len(desiredAFPaths) == 0 {
			// service does not exist in our local state, and there is nothing to advertise
			continue
		}

		// reconcile service paths
		updatedAFPaths, err := ReconcileAFPaths(&ReconcileAFPathsParams{
			Logger:       r.logger.WithField(types.InstanceLogField, p.DesiredConfig.Name),
			Ctx:          ctx,
			Instance:     p.BGPInstance,
			DesiredPaths: desiredAFPaths,
			CurrentPaths: currentAFPaths,
		})

		if err == nil && len(desiredAFPaths) == 0 {
			// no error is reported and desiredAFPaths is empty, we should delete the service
			delete(metadata.ServicePaths, svc)
		} else {
			// update service paths with returned updatedAFPaths even if there was an error.
			metadata.ServicePaths[svc] = updatedAFPaths
		}

		r.setMetadata(p.BGPInstance, metadata)
		allErr = errors.Join(allErr, err)
	}

	return allErr
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
			if be.NodeName == localNodeName {
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

// fullReconciliation reconciles all services, this is a heavy operation due to the potential amount of services and
// thus should be avoided if partial reconciliation is an option.
func (r *ServiceReconciler) fullReconciliation(p ReconcileParams, ls sets.Set[resource.Key]) (ServiceAFPathsMap, error) {
	r.logger.Debug("performing all services reconciliation")

	desiredServiceAFPaths := make(ServiceAFPathsMap)

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

		afPaths, err := r.getServiceDesiredAFPaths(p, svc, ls)
		if err != nil {
			return nil, err
		}

		desiredServiceAFPaths[svcKey] = afPaths
	}

	return desiredServiceAFPaths, nil
}

// svcDiffReconciliation performs reconciliation, only on services which have been created, updated or deleted since
// the last diff reconciliation. This is a lighter operation compared to full reconciliation.
func (r *ServiceReconciler) svcDiffReconciliation(p ReconcileParams, ls sets.Set[resource.Key]) (ServiceAFPathsMap, error) {
	r.logger.Debug("performing modified services reconciliation")

	desiredServiceAFPaths := make(ServiceAFPathsMap)
	toReconcile, toWithdraw, err := r.diffReconciliationServiceList()
	if err != nil {
		return nil, err
	}

	for _, svc := range toReconcile {
		svcKey := resource.Key{
			Name:      svc.GetName(),
			Namespace: svc.GetNamespace(),
		}

		afPaths, err := r.getServiceDesiredAFPaths(p, svc, ls)
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

func (r *ServiceReconciler) getServiceDesiredAFPaths(p ReconcileParams, svc *slim_corev1.Service, ls sets.Set[resource.Key]) (AFPathsMap, error) {
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
			desiredRoutes = append(desiredRoutes, r.lbSvcDesiredRoutes(svc, ls)...)
		case v2alpha1.BGPClusterIPAddr:
			desiredRoutes = append(desiredRoutes, r.clusterIPDesiredRoutes(svc, ls)...)
		case v2alpha1.BGPExternalIPAddr:
			desiredRoutes = append(desiredRoutes, r.externalIPDesiredRoutes(svc, ls)...)
		}
	}

	return desiredRoutes, nil
}

func (r *ServiceReconciler) externalIPDesiredRoutes(svc *slim_corev1.Service, ls sets.Set[resource.Key]) []netip.Prefix {
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

func (r *ServiceReconciler) clusterIPDesiredRoutes(svc *slim_corev1.Service, ls sets.Set[resource.Key]) []netip.Prefix {
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

func (r *ServiceReconciler) lbSvcDesiredRoutes(svc *slim_corev1.Service, ls sets.Set[resource.Key]) []netip.Prefix {
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

func serviceLabelSet(svc *slim_corev1.Service) labels.Labels {
	svcLabels := maps.Clone(svc.Labels)
	if svcLabels == nil {
		svcLabels = make(map[string]string)
	}
	svcLabels["io.kubernetes.service.name"] = svc.Name
	svcLabels["io.kubernetes.service.namespace"] = svc.Namespace
	return labels.Set(svcLabels)
}
