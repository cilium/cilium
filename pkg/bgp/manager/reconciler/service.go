// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/bgp/agent/signaler"
	"github.com/cilium/cilium/pkg/bgp/manager/instance"
	"github.com/cilium/cilium/pkg/bgp/option"
	"github.com/cilium/cilium/pkg/bgp/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slimmetav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/loadbalancer"
	ciliumoption "github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/svcrouteconfig"
	"github.com/cilium/cilium/pkg/time"
)

type ServiceReconcilerOut struct {
	cell.Out

	Reconciler ConfigReconciler `group:"bgp-config-reconciler"`
}

type ServiceReconcilerIn struct {
	cell.In
	Logger   *slog.Logger
	JobGroup job.Group

	PeerAdvert   *CiliumPeerAdvertisement
	Config       option.BGPConfig
	DaemonConfig *ciliumoption.DaemonConfig
	Signaler     *signaler.BGPCPSignaler

	DB           *statedb.DB
	Frontends    statedb.Table[*loadbalancer.Frontend]
	RoutesConfig svcrouteconfig.RoutesConfig
}

type ServiceReconciler struct {
	logger                       *slog.Logger
	peerAdvert                   *CiliumPeerAdvertisement
	legacyOriginAttributeEnabled bool
	signaler                     *signaler.BGPCPSignaler
	db                           *statedb.DB
	frontends                    statedb.Table[*loadbalancer.Frontend]
	metadata                     map[string]ServiceReconcilerMetadata
	routesConfig                 svcrouteconfig.RoutesConfig
}

// ServiceReconcilerMetadata holds per-instance reconciler state.
type ServiceReconcilerMetadata struct {
	ServicePaths               ResourceAFPathsMap
	ServiceAdvertisements      PeerAdvertisements
	ServiceRoutePolicies       ResourceRoutePolicyMap
	FrontendChanges            statedb.ChangeIterator[*loadbalancer.Frontend]
	FrontendChangesInitialized bool
}

func NewServiceReconciler(in ServiceReconcilerIn) ServiceReconcilerOut {
	if !in.DaemonConfig.BGPControlPlaneEnabled() {
		return ServiceReconcilerOut{}
	}
	r := &ServiceReconciler{
		logger:                       in.Logger,
		peerAdvert:                   in.PeerAdvert,
		legacyOriginAttributeEnabled: in.Config.EnableBGPLegacyOriginAttribute,
		signaler:                     in.Signaler,
		db:                           in.DB,
		frontends:                    in.Frontends,
		metadata:                     make(map[string]ServiceReconcilerMetadata),
		routesConfig:                 in.RoutesConfig,
	}
	in.JobGroup.Add(
		job.OneShot("frontend-events", r.processFrontendEvents),
	)
	return ServiceReconcilerOut{Reconciler: r}
}

// processFrontendEvents triggers BGP reconciliation upon frontend events (including changes in their backends)
func (r *ServiceReconciler) processFrontendEvents(ctx context.Context, _ cell.Health) error {
	// rate-limit reconciliation triggers to 100 milliseconds
	limiter := rate.NewLimiter(100*time.Millisecond, 1)
	defer limiter.Stop()

	// wait for frontends table initialization
	_, watch := r.frontends.Initialized(r.db.ReadTxn())
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-watch:
	}

	// emit initial signal
	r.signaler.Event(struct{}{})

	// watch for changes in the frontends table
	_, watch = r.frontends.AllWatch(r.db.ReadTxn())
	for {
		select {
		case <-watch:
			// re-start the watch and emit reconciliation event
			_, watch = r.frontends.AllWatch(r.db.ReadTxn())
			r.signaler.Event(struct{}{})
		case <-ctx.Done():
			return ctx.Err()
		}
		if err := limiter.Wait(ctx); err != nil {
			return err
		}
	}
}

func (r *ServiceReconciler) getMetadata(i *instance.BGPInstance) ServiceReconcilerMetadata {
	return r.metadata[i.Name]
}

func (r *ServiceReconciler) setMetadata(i *instance.BGPInstance, metadata ServiceReconcilerMetadata) {
	r.metadata[i.Name] = metadata
}

func (r *ServiceReconciler) Name() string {
	return ServiceReconcilerName
}

func (r *ServiceReconciler) Priority() int {
	return ServiceReconcilerPriority
}

func (r *ServiceReconciler) Init(i *instance.BGPInstance) error {
	if i == nil {
		return fmt.Errorf("BUG: service reconciler initialization with nil BGPInstance")
	}

	r.metadata[i.Name] = ServiceReconcilerMetadata{
		ServicePaths:          make(ResourceAFPathsMap),
		ServiceAdvertisements: make(PeerAdvertisements),
		ServiceRoutePolicies:  make(ResourceRoutePolicyMap),
	}
	return nil
}

func (r *ServiceReconciler) Cleanup(i *instance.BGPInstance) {
	if i != nil {
		delete(r.metadata, i.Name)
	}
}

func (r *ServiceReconciler) Reconcile(ctx context.Context, p ReconcileParams) error {
	if err := p.ValidateParams(); err != nil {
		return err
	}

	desiredPeerAdverts, err := r.peerAdvert.GetConfiguredAdvertisements(p.DesiredConfig, v2.BGPServiceAdvert)
	if err != nil {
		return err
	}

	reqFullReconcile := r.modifiedServiceAdvertisements(p, desiredPeerAdverts)

	// if frontend changes iterator has not been initialized yet (first reconcile), perform full reconciliation
	if !r.getMetadata(p.BGPInstance).FrontendChangesInitialized {
		reqFullReconcile = true
	}

	err = r.reconcileServices(ctx, p, desiredPeerAdverts, reqFullReconcile)

	if err == nil && reqFullReconcile {
		// update svc advertisements in metadata only if the reconciliation was successful
		r.updateServiceAdvertisementsMetadata(p, desiredPeerAdverts)
	}
	return err
}

func (r *ServiceReconciler) reconcileServices(ctx context.Context, p ReconcileParams, desiredPeerAdverts PeerAdvertisements, fullReconcile bool) error {
	var (
		toReconcile []*loadbalancer.Service
		toWithdraw  []loadbalancer.ServiceName

		desiredSvcRoutePolicies ResourceRoutePolicyMap
		desiredSvcPaths         ResourceAFPathsMap

		rx  statedb.ReadTxn
		err error
	)

	if fullReconcile {
		r.logger.Debug("performing all services reconciliation")

		// get all services to reconcile and to withdraw.
		toReconcile, toWithdraw, rx, err = r.fullReconciliationServiceList(p)
		if err != nil {
			return err
		}
	} else {
		r.logger.Debug("performing modified services reconciliation")

		// get modified services to reconcile and to withdraw.
		// Note: we should call svc diff only once in a reconcile loop.
		toReconcile, rx, err = r.diffReconciliationServiceList(p)
		if err != nil {
			return err
		}
	}

	// get desired service route policies
	desiredSvcRoutePolicies, err = r.getDesiredRoutePolicies(p, desiredPeerAdverts, toReconcile, toWithdraw, rx)
	if err != nil {
		return err
	}

	// reconcile service route policies
	err = r.reconcileSvcRoutePolicies(ctx, p, desiredSvcRoutePolicies)
	if err != nil {
		return fmt.Errorf("failed to reconcile service route policies: %w", err)
	}

	// get desired service paths
	desiredSvcPaths, err = r.getDesiredPaths(p, desiredPeerAdverts, toReconcile, toWithdraw, rx)
	if err != nil {
		return err
	}

	// reconcile service paths
	err = r.reconcilePaths(ctx, p, desiredSvcPaths)
	if err != nil {
		return fmt.Errorf("failed to reconcile service paths: %w", err)
	}

	return nil
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
			Logger:          r.logger.With(types.InstanceLogField, p.DesiredConfig.Name),
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

func (r *ServiceReconciler) getDesiredRoutePolicies(p ReconcileParams, desiredPeerAdverts PeerAdvertisements, toUpdate []*loadbalancer.Service, toRemove []loadbalancer.ServiceName, rx statedb.ReadTxn) (ResourceRoutePolicyMap, error) {
	desiredSvcRoutePolicies := make(ResourceRoutePolicyMap)

	for _, svc := range toUpdate {
		key := resource.Key{Name: svc.Name.Name(), Namespace: svc.Name.Namespace()}

		// get desired route policies for the service
		svcRoutePolicies, err := r.getDesiredSvcRoutePolicies(p, desiredPeerAdverts, svc, rx)
		if err != nil {
			return nil, err
		}

		desiredSvcRoutePolicies[key] = svcRoutePolicies
	}

	for _, svcName := range toRemove {
		// for withdrawn services, we need to set route policies to nil.
		key := resource.Key{Name: svcName.Name(), Namespace: svcName.Namespace()}
		desiredSvcRoutePolicies[key] = nil
	}

	return desiredSvcRoutePolicies, nil
}

func (r *ServiceReconciler) getDesiredSvcRoutePolicies(p ReconcileParams, desiredPeerAdverts PeerAdvertisements, svc *loadbalancer.Service, rx statedb.ReadTxn) (RoutePolicyMap, error) {
	desiredSvcRoutePolicies := make(RoutePolicyMap)

	for peer, afAdverts := range desiredPeerAdverts {
		for fam, adverts := range afAdverts {
			agentFamily := types.ToAgentFamily(fam)

			for _, advert := range adverts {
				// get prefixes for the service
				typedPrefixes, err := r.getServicePrefixes(p, svc, advert, rx)
				if err != nil {
					return nil, err
				}
				for advertType, prefixes := range typedPrefixes {
					if len(prefixes) == 0 {
						continue
					}
					prefixesArr := prefixes.UnsortedList()
					slices.SortFunc(prefixesArr, func(a, b netip.Prefix) int {
						return a.Addr().Compare(b.Addr()) // NOTE: Compare for netip.Prefix us unexported as of Go 1.22 (see go.dev/issue/61642), address compare is good enough here
					})
					policy, err := r.getServiceRoutePolicy(peer, agentFamily, svc, prefixesArr, advert, advertType)
					if err != nil {
						return nil, fmt.Errorf("failed to get desired %s route policy: %w", advertType, err)
					}
					if policy != nil {
						existingPolicy := desiredSvcRoutePolicies[policy.Name]
						if existingPolicy != nil {
							policy, err = MergeRoutePolicies(existingPolicy, policy)
							if err != nil {
								return nil, fmt.Errorf("failed to merge %s route policies: %w", advertType, err)
							}
						}
						desiredSvcRoutePolicies[policy.Name] = policy
					}
				}
			}
		}
	}

	return desiredSvcRoutePolicies, nil
}

func (r *ServiceReconciler) reconcilePaths(ctx context.Context, p ReconcileParams, desiredSvcPaths ResourceAFPathsMap) error {
	var err error
	metadata := r.getMetadata(p.BGPInstance)

	metadata.ServicePaths, err = ReconcileResourceAFPaths(ReconcileResourceAFPathsParams{
		Logger:                 r.logger.With(types.InstanceLogField, p.DesiredConfig.Name),
		Ctx:                    ctx,
		Router:                 p.BGPInstance.Router,
		DesiredResourceAFPaths: desiredSvcPaths,
		CurrentResourceAFPaths: metadata.ServicePaths,
	})

	r.setMetadata(p.BGPInstance, metadata)
	return err
}

// modifiedServiceAdvertisements compares local advertisement state with desiredPeerAdverts, if they differ,
// returns true signaling that full reconciliation is required.
func (r *ServiceReconciler) modifiedServiceAdvertisements(p ReconcileParams, desiredPeerAdverts PeerAdvertisements) bool {
	// current metadata
	serviceMetadata := r.getMetadata(p.BGPInstance)

	// check if BGP advertisement configuration modified
	modified := !PeerAdvertisementsEqual(serviceMetadata.ServiceAdvertisements, desiredPeerAdverts)

	return modified
}

// updateServiceAdvertisementsMetadata updates the provided ServiceAdvertisements in the reconciler metadata.
func (r *ServiceReconciler) updateServiceAdvertisementsMetadata(p ReconcileParams, peerAdverts PeerAdvertisements) {
	// current metadata
	serviceMetadata := r.getMetadata(p.BGPInstance)

	serviceMetadata.ServiceAdvertisements = peerAdverts

	// update ServiceAdvertisements in the metadata
	r.setMetadata(p.BGPInstance, serviceMetadata)
}

// hasBackends loops through Frontend backends and returns:
// 1) true, false - backends > 0, no local backend
// 2) true, true - backends > 0, at least 1 local backend
// 3) false, false - no backends, no local backend
func hasBackends(p ReconcileParams, fe *loadbalancer.Frontend) (hasBackends, hasLocalBackends bool) {
	for backend := range fe.Backends {
		hasBackends = true
		if backend.NodeName == p.CiliumNode.Name && backend.State == loadbalancer.BackendStateActive {
			hasLocalBackends = true
			return
		}
	}
	return
}

func (r *ServiceReconciler) fullReconciliationServiceList(p ReconcileParams) (toReconcile []*loadbalancer.Service, toWithdraw []loadbalancer.ServiceName, rx statedb.ReadTxn, err error) {
	metadata := r.getMetadata(p.BGPInstance)

	// re-init changes interator, so that it contains changes since the last full reconciliation
	tx := r.db.WriteTxn(r.frontends)
	metadata.FrontendChanges, err = r.frontends.Changes(tx)
	if err != nil {
		tx.Abort()
		return nil, nil, nil, fmt.Errorf("error subscribing to frontends changes: %w", err)
	}
	rx = tx.Commit()
	metadata.FrontendChangesInitialized = true
	r.setMetadata(p.BGPInstance, metadata)

	// the initial set of changes emits all existing frontends
	events, _ := metadata.FrontendChanges.Next(rx)

	svcMap := make(map[loadbalancer.ServiceName]*loadbalancer.Service)
	for frontendEvent := range events {
		frontend := frontendEvent.Object
		svcMap[frontend.Service.Name] = frontend.Service
	}
	toReconcile = slices.Collect(maps.Values(svcMap))

	// check for services which are no longer present
	serviceAFPaths := metadata.ServicePaths
	for svcKey := range serviceAFPaths {
		svcName := loadbalancer.NewServiceName(svcKey.Namespace, svcKey.Name)
		// if the service no longer exists, withdraw it
		if _, exists := svcMap[svcName]; !exists {
			toWithdraw = append(toWithdraw, svcName)
		}
	}
	return
}

// diffReconciliationServiceList returns a list of services to reconcile and to withdraw when
// performing partial (diff) service reconciliation.
func (r *ServiceReconciler) diffReconciliationServiceList(p ReconcileParams) (toReconcile []*loadbalancer.Service, rx statedb.ReadTxn, err error) {
	metadata := r.getMetadata(p.BGPInstance)
	rx = r.db.ReadTxn()

	// list frontends which changed since the last reconciliation (includes frontends with just backend changed)
	if !metadata.FrontendChangesInitialized {
		return nil, rx, fmt.Errorf("BUG: frontend changes tracker not initialized, cannot perform diff reconciliation")
	}
	events, _ := metadata.FrontendChanges.Next(rx)

	svcMap := make(map[loadbalancer.ServiceName]*loadbalancer.Service)
	for frontendEvent := range events {
		frontend := frontendEvent.Object
		// even if the frontend was deleted, we still don't know whether whole service was deleted,
		// so we need to perform its reconciliation instead of just withdrawal
		svcMap[frontend.Service.Name] = frontend.Service
	}
	toReconcile = slices.Collect(maps.Values(svcMap))
	return
}

func (r *ServiceReconciler) getDesiredPaths(p ReconcileParams, desiredPeerAdverts PeerAdvertisements, toReconcile []*loadbalancer.Service, toWithdraw []loadbalancer.ServiceName, rx statedb.ReadTxn) (ResourceAFPathsMap, error) {
	desiredServiceAFPaths := make(ResourceAFPathsMap)
	for _, svc := range toReconcile {
		key := resource.Key{Name: svc.Name.Name(), Namespace: svc.Name.Namespace()}

		afPaths, err := r.getServiceAFPaths(p, desiredPeerAdverts, svc, rx)
		if err != nil {
			return nil, err
		}

		desiredServiceAFPaths[key] = afPaths
	}

	for _, svcName := range toWithdraw {
		// for withdrawn services, we need to set paths to nil.
		key := resource.Key{Name: svcName.Name(), Namespace: svcName.Namespace()}
		desiredServiceAFPaths[key] = nil
	}

	return desiredServiceAFPaths, nil
}

func (r *ServiceReconciler) getServiceAFPaths(p ReconcileParams, desiredPeerAdverts PeerAdvertisements, svc *loadbalancer.Service, rx statedb.ReadTxn) (AFPathsMap, error) {
	desiredFamilyAdverts := make(AFPathsMap)

	for _, peerFamilyAdverts := range desiredPeerAdverts {
		for family, familyAdverts := range peerFamilyAdverts {
			agentFamily := types.ToAgentFamily(family)

			for _, advert := range familyAdverts {
				// get prefixes for the service
				typedPrefixes, err := r.getServicePrefixes(p, svc, advert, rx)
				if err != nil {
					return nil, err
				}
				for advertType, prefixes := range typedPrefixes {
					for _, prefix := range prefixes.UnsortedList() {
						// we only add path corresponding to the family of the prefix.
						if agentFamily.Afi == types.AfiIPv4 && prefix.Addr().Is4() {
							path := types.NewPathForPrefix(prefix)
							// For LoadBalancer IP prefixes, set origin to INCOMPLETE for legacy compatibility.
							if r.legacyOriginAttributeEnabled && advertType == v2.BGPLoadBalancerIPAddr {
								path = types.SetPathOriginAttrIncomplete(path)
							}
							path.Family = agentFamily
							addPathToAFPathsMap(desiredFamilyAdverts, agentFamily, path)
						}
						if agentFamily.Afi == types.AfiIPv6 && prefix.Addr().Is6() {
							path := types.NewPathForPrefix(prefix)
							// For LoadBalancer IP prefixes, set origin to INCOMPLETE for legacy compatibility.
							if r.legacyOriginAttributeEnabled && advertType == v2.BGPLoadBalancerIPAddr {
								path = types.SetPathOriginAttrIncomplete(path)
							}
							path.Family = agentFamily
							addPathToAFPathsMap(desiredFamilyAdverts, agentFamily, path)
						}
					}
				}
			}
		}
	}
	return desiredFamilyAdverts, nil
}

func (r *ServiceReconciler) getServicePrefixes(p ReconcileParams, svc *loadbalancer.Service, advert v2.BGPAdvertisement, rx statedb.ReadTxn) (map[v2.BGPServiceAddressType]sets.Set[netip.Prefix], error) {
	if advert.AdvertisementType != v2.BGPServiceAdvert {
		return nil, fmt.Errorf("unexpected advertisement type: %s", advert.AdvertisementType)
	}
	if advert.Selector == nil || advert.Service == nil {
		// advertisement has no selector or no service options, default behavior is not to match any service.
		return nil, nil
	}

	// Ignore non-matching services
	svcSelector, err := slimmetav1.LabelSelectorAsSelector(advert.Selector)
	if err != nil {
		return nil, fmt.Errorf("labelSelectorAsSelector: %w", err)
	}
	if !svcSelector.Matches(serviceLabelSet(svc)) {
		return nil, nil
	}

	// Lookup service frontends
	frontends := slices.Collect(statedb.ToSeq(r.frontends.List(rx, loadbalancer.FrontendByServiceName(svc.Name))))

	// Loop over the service adverts and determine the desired routes
	res := make(map[v2.BGPServiceAddressType]sets.Set[netip.Prefix])
	for _, svcAdv := range advert.Service.Addresses {
		switch svcAdv {
		case v2.BGPLoadBalancerIPAddr:
			res[svcAdv] = r.getLoadBalancerIPPaths(p, svc, frontends, advert)
		case v2.BGPClusterIPAddr:
			res[svcAdv] = r.getClusterIPPaths(p, frontends, advert)
		case v2.BGPExternalIPAddr:
			res[svcAdv] = r.getExternalIPPaths(p, frontends, advert)
		}
	}
	return res, nil
}

func (r *ServiceReconciler) getExternalIPPaths(p ReconcileParams, frontends []*loadbalancer.Frontend, advert v2.BGPAdvertisement) sets.Set[netip.Prefix] {
	desiredRoutes := sets.New[netip.Prefix]()

	for _, fe := range frontends {
		if fe.Type != loadbalancer.SVCTypeExternalIPs {
			continue
		}

		hasBackends, hasLocalBackends := hasBackends(p, fe)
		// Ignore externalTrafficPolicy == Local && no local EPs or ignore when there are no backends and EnableNoServiceEndpointsRoutable == false.
		if (fe.Service.ExtTrafficPolicy == loadbalancer.SVCTrafficPolicyLocal && !hasLocalBackends) || (!r.routesConfig.EnableNoServiceEndpointsRoutable && !hasBackends) {
			continue
		}

		addr := fe.Address.Addr()
		prefix, err := addr.Prefix(getServicePrefixLength(fe, advert, v2.BGPExternalIPAddr))
		if err != nil {
			continue
		}
		desiredRoutes.Insert(prefix)
	}

	return desiredRoutes
}

func (r *ServiceReconciler) getClusterIPPaths(p ReconcileParams, frontends []*loadbalancer.Frontend, advert v2.BGPAdvertisement) sets.Set[netip.Prefix] {
	desiredRoutes := sets.New[netip.Prefix]()

	for _, fe := range frontends {
		if fe.Type != loadbalancer.SVCTypeClusterIP {
			continue
		}

		hasBackends, hasLocalBackends := hasBackends(p, fe)
		// Ignore internalTrafficPolicy == Local && no local EPs or ignore when there are no backends and EnableNoServiceEndpointsRoutable == false.
		if fe.Service.IntTrafficPolicy == loadbalancer.SVCTrafficPolicyLocal && !hasLocalBackends || (!r.routesConfig.EnableNoServiceEndpointsRoutable && !hasBackends) {
			continue
		}

		addr := fe.Address.Addr()
		prefix, err := addr.Prefix(getServicePrefixLength(fe, advert, v2.BGPClusterIPAddr))
		if err != nil {
			continue
		}
		desiredRoutes.Insert(prefix)
	}

	return desiredRoutes
}

func (r *ServiceReconciler) getLoadBalancerIPPaths(p ReconcileParams, svc *loadbalancer.Service, frontends []*loadbalancer.Frontend, advert v2.BGPAdvertisement) sets.Set[netip.Prefix] {
	desiredRoutes := sets.New[netip.Prefix]()

	// Ignore service managed by an unsupported LB class.
	if svc.LoadBalancerClass != nil && *svc.LoadBalancerClass != v2.BGPLoadBalancerClass {
		return desiredRoutes
	}

	// Check if this service has a local proxy (Envoy) handling its traffic.
	// ProxyRedirect is non-nil when the local Envoy proxy is running and configured
	// to handle this service (e.g., Gateway API or Ingress services).
	// This handles deployments where cilium-envoy has a nodeSelector that excludes some nodes.
	hasLocalProxy := svc.ProxyRedirect != nil

	for _, fe := range frontends {
		if fe.Type != loadbalancer.SVCTypeLoadBalancer {
			continue
		}

		hasBackends, hasLocalBackends := hasBackends(p, fe)

		// For services with real backends, respect externalTrafficPolicy: Local by skipping
		// advertisement when there are no local endpoints.
		// For proxy-redirected services (Gateway API/Ingress), advertise if the local
		// proxy is handling traffic, since backends are managed by the proxy.
		if fe.Service.ExtTrafficPolicy == loadbalancer.SVCTrafficPolicyLocal && !hasLocalBackends {
			if !hasLocalProxy {
				continue
			}
		}

		// Respect EnableNoServiceEndpointsRoutable for services with zero backends.
		// However, proxy-redirected services should be advertised even with zero
		// backends, as traffic is handled by the local proxy.
		if !r.routesConfig.EnableNoServiceEndpointsRoutable && !hasBackends {
			if !hasLocalProxy {
				continue
			}
		}

		addr := fe.Address.Addr()
		prefix, err := addr.Prefix(getServicePrefixLength(fe, advert, v2.BGPLoadBalancerIPAddr))
		if err != nil {
			continue
		}
		desiredRoutes.Insert(prefix)
	}

	return desiredRoutes
}

func (r *ServiceReconciler) getServiceRoutePolicy(peer PeerID, family types.Family, svc *loadbalancer.Service, svcPrefixes []netip.Prefix, advert v2.BGPAdvertisement, advertType v2.BGPServiceAddressType) (*types.RoutePolicy, error) {
	if peer.Address == "" {
		return nil, nil
	}
	peerAddr, err := netip.ParseAddr(peer.Address)
	if err != nil {
		return nil, fmt.Errorf("failed to parse peer address: %w", err)
	}

	// check service type is enabled in advertisement
	if !slices.Contains(advert.Service.Addresses, advertType) {
		return nil, nil
	}

	var v4Prefixes, v6Prefixes types.PolicyPrefixList
	for _, prefix := range svcPrefixes {
		if family.Afi == types.AfiIPv4 && prefix.Addr().Is4() {
			v4Prefixes = append(v4Prefixes, types.RoutePolicyPrefix{CIDR: prefix, PrefixLenMin: prefix.Bits(), PrefixLenMax: prefix.Bits()})
		}
		if family.Afi == types.AfiIPv6 && prefix.Addr().Is6() {
			v6Prefixes = append(v6Prefixes, types.RoutePolicyPrefix{CIDR: prefix, PrefixLenMin: prefix.Bits(), PrefixLenMax: prefix.Bits()})
		}
	}
	if len(v4Prefixes) == 0 && len(v6Prefixes) == 0 {
		return nil, nil
	}

	policyName := PolicyName(peer.Name, family.Afi.String(), advert.AdvertisementType, fmt.Sprintf("%s-%s-%s", svc.Name.Name(), svc.Name.Namespace(), advertType))
	policy, err := CreatePolicy(policyName, peerAddr, v4Prefixes, v6Prefixes, advert)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s IP route policy: %w", advertType, err)
	}

	return policy, nil
}

func serviceLabelSet(svc *loadbalancer.Service) labels.Labels {
	svcLabels := maps.Clone(svc.Labels.K8sStringMap())
	if svcLabels == nil {
		svcLabels = make(map[string]string)
	}
	svcLabels["io.kubernetes.service.name"] = svc.Name.Name()
	svcLabels["io.kubernetes.service.namespace"] = svc.Name.Namespace()
	return labels.Set(svcLabels)
}

func getServicePrefixLength(fe *loadbalancer.Frontend, advert v2.BGPAdvertisement, addrType v2.BGPServiceAddressType) int {
	addr := fe.Address.Addr()
	length := addr.BitLen()

	if addrType == v2.BGPClusterIPAddr {
		// for iTP=Local, we always use the full prefix length
		if fe.Service.IntTrafficPolicy == loadbalancer.SVCTrafficPolicyLocal {
			return length
		}
	} else {
		// for eTP=Local, we always use the full prefix length
		if fe.Service.ExtTrafficPolicy == loadbalancer.SVCTrafficPolicyLocal {
			return length
		}
	}

	if addr.Is4() && advert.Service.AggregationLengthIPv4 != nil {
		length = int(*advert.Service.AggregationLengthIPv4)
	}

	if addr.Is6() && advert.Service.AggregationLengthIPv6 != nil {
		length = int(*advert.Service.AggregationLengthIPv6)
	}
	return length
}
