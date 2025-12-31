// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package raw

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/identity"
	identityCache "github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	k8sLabels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/crap"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
)

// Cell provides a [Manager] for consumption with hive.
var Cell = cell.Module(
	"crap",
	"Cilium Raw Acquisition of Packets",
	// cell.Provide(newCrapManager),
	cell.Provide(k8s.ServiceResource),
	cell.Invoke(registerCrapManager),
)

type CrapParams struct {
	cell.In

	JobGroup          job.Group
	Services          resource.Resource[*slim_corev1.Service]
	Endpoints         resource.Resource[*k8sTypes.CiliumEndpoint]
	Logger            *slog.Logger
	IdentityAllocator identityCache.IdentityAllocator
	EndpointManager   endpointmanager.EndpointManager
	LocalNodeStore    *node.LocalNodeStore
	BpfMap            *crap.CrapMap
}

type endpointMetadata struct {
	labels  map[string]string
	id      endpointID
	ip      netip.Addr
	nodeIP  string
	ifindex int
}

type serviceMetadata struct {
	labels map[string]string
	id     serviceID
	vip    []netip.Addr
}

type endpointID = types.UID
type serviceID = types.UID

type diff struct {
	serviceDiff map[serviceID]*serviceMetadata
	serviceSync bool

	epDiff map[endpointID]*endpointMetadata
	epSync bool
}

func newDiff() *diff {
	return &diff{
		epDiff:      make(map[endpointID]*endpointMetadata),
		epSync:      false,
		serviceDiff: make(map[serviceID]*serviceMetadata),
		serviceSync: false,
	}
}

type CrapManager struct {
	trigger           job.Trigger
	logger            *slog.Logger
	ch                chan *diff
	identityAllocator identityCache.IdentityAllocator
	bpfmap            *crap.CrapMap
	endpointManager   endpointmanager.EndpointManager
	localNodeStore    *node.LocalNodeStore
}

func newCrapManager(params CrapParams) *CrapManager {
	return &CrapManager{
		logger:            params.Logger,
		identityAllocator: params.IdentityAllocator,
		ch:                make(chan *diff, 64),
		bpfmap:            params.BpfMap,
		endpointManager:   params.EndpointManager,
		localNodeStore:    params.LocalNodeStore,
	}
}

func (cm *CrapManager) getEndpointMetadata(endpoint *k8sTypes.CiliumEndpoint, identityLabels labels.Labels) (*endpointMetadata, error) {
	var addr netip.Addr
	var ifindex int

	if endpoint.UID == "" {
		// this can happen when CiliumEndpointSlices are in use - which is not supported in the EGW yet
		return nil, fmt.Errorf("endpoint has empty UID")
	}

	if endpoint.Networking == nil {
		return nil, fmt.Errorf("endpoint has no networking metadata")
	}

	if len(endpoint.Networking.Addressing) == 0 {
		return nil, fmt.Errorf("failed to get valid endpoint IPs")
	}

	ln, err := cm.localNodeStore.Get(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve local node")
	}

	nodeIP := node.GetCiliumEndpointNodeIP(ln)

	for _, pair := range endpoint.Networking.Addressing {
		if pair.IPV4 != "" {
			a, err := netip.ParseAddr(pair.IPV4)

			if err != nil {
				continue
			}

			if endpoint.Networking.NodeIP == nodeIP {
				if ep := cm.endpointManager.LookupIP(addr); ep != nil {
					ifindex = ep.GetIfIndex()
				}
			}

			addr = a
			break
		}
	}

	data := &endpointMetadata{
		ip:      addr,
		labels:  identityLabels.K8sStringMap(),
		id:      endpoint.UID,
		nodeIP:  endpoint.Networking.NodeIP,
		ifindex: ifindex,
	}

	return data, nil
}

func getServiceMetadata(svc *slim_corev1.Service) (*serviceMetadata, error) {
	var addrs []netip.Addr

	for _, pair := range svc.Spec.ExternalIPs {
		addr, err := netip.ParseAddr(pair)
		if err != nil {
			continue
		}
		addrs = append(addrs, addr)
	}

	data := &serviceMetadata{
		vip:    addrs,
		labels: svc.Spec.Selector,
		id:     svc.UID,
	}

	return data, nil
}

func (cm *CrapManager) addService(ctx context.Context, svc *slim_corev1.Service, diff *diff) error {
	var svcData *serviceMetadata
	var err error

	log := cm.logger.With(
		logfields.ID, svc.UID,
		logfields.K8sNamespace, svc.Namespace,
		logfields.Name, svc.Name,
		logfields.Labels, svc.Labels,
	)

	if _, ok := annotation.Get(svc, annotation.ServiceRaw); !ok {
		log.DebugContext(ctx, "Skip services w/o RAW annotation")
		return nil
	}

	log.InfoContext(ctx, "Adding new service")

	if svcData, err = getServiceMetadata(svc); err != nil {
		log.WarnContext(ctx, "Failed to get valid service metadata", logfields.Error, err)
		return nil
	}

	log.DebugContext(ctx, "Service accepted for adding/updating")
	diff.serviceDiff[svcData.id] = svcData

	return nil
}

func (cm *CrapManager) delService(ctx context.Context, svc *slim_corev1.Service, diff *diff) error {
	log := cm.logger.With(
		logfields.ID, svc.UID,
		logfields.K8sNamespace, svc.Namespace,
		logfields.Name, svc.Name,
		logfields.Labels, svc.Labels,
	)

	log.InfoContext(ctx, "Removing service")
	diff.serviceDiff[svc.UID] = nil

	return nil
}

func (cm *CrapManager) handleSvcEvent(ctx context.Context, event resource.Event[*slim_corev1.Service]) error {
	var err error = nil

	diff := newDiff()
	svc := event.Object

	switch event.Kind {
	case resource.Sync:
		diff.serviceSync = true
	case resource.Upsert:
		cm.addService(ctx, svc, diff)
	case resource.Delete:
		cm.delService(ctx, svc, diff)
	}

	event.Done(err)
	cm.ch <- diff

	return err
}

func (manager *CrapManager) getIdentityLabels(securityIdentity uint32) (labels.Labels, error) {
	if err := manager.identityAllocator.WaitForInitialGlobalIdentities(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to wait for initial global identities: %w", err)
	}

	identity := manager.identityAllocator.LookupIdentityByID(context.Background(), identity.NumericIdentity(securityIdentity))
	if identity == nil {
		return nil, fmt.Errorf("identity %d not found", securityIdentity)
	}
	return identity.Labels, nil
}

func (cm *CrapManager) addEndpoint(ctx context.Context, ep *k8sTypes.CiliumEndpoint, diff *diff) error {
	var epData *endpointMetadata
	var err error
	var identityLabels labels.Labels

	log := cm.logger.With(
		logfields.K8sNamespace, ep.Namespace,
		logfields.Name, ep.Name,
		logfields.Labels, ep.Labels,
	)

	log.DebugContext(ctx, "Adding new endpoint")

	if ep.Identity == nil {
		log.Warn("Endpoint is missing identity metadata, skipping update to raw rules")
		return nil
	}

	if identityLabels, err = cm.getIdentityLabels(uint32(ep.Identity.ID)); err != nil {
		log.WarnContext(ctx, "Failed to get identity labels for endpoint", logfields.Error, err)
		return err
	}

	if epData, err = cm.getEndpointMetadata(ep, identityLabels); err != nil {
		log.ErrorContext(ctx, "Failed to get valid endpoint metadata, skipping update to raw rules", logfields.Error, err)
		return nil
	}

	log.DebugContext(ctx, "CiliumEndpoint accepted for adding/updating")
	diff.epDiff[epData.id] = epData

	return nil
}

func (cm *CrapManager) delEndpoint(ctx context.Context, ep *k8sTypes.CiliumEndpoint, diff *diff) error {
	log := cm.logger.With(
		logfields.K8sNamespace, ep.Namespace,
		logfields.Name, ep.Name,
		logfields.Labels, ep.Labels,
	)

	log.InfoContext(ctx, "Removing endpoint")
	diff.epDiff[ep.UID] = nil

	return nil
}

func (cm *CrapManager) handleEndpointEvent(ctx context.Context, event resource.Event[*k8sTypes.CiliumEndpoint]) error {
	var err error = nil

	diff := newDiff()
	ep := event.Object

	switch event.Kind {
	case resource.Sync:
		diff.epSync = true
	case resource.Upsert:
		cm.addEndpoint(ctx, ep, diff)
	case resource.Delete:
		cm.delEndpoint(ctx, ep, diff)
	}

	event.Done(err)
	cm.ch <- diff

	return err
}

func (config *serviceMetadata) matchesPodLabels(epLabels map[string]string) bool {
	if len(config.labels) == 0 {
		return false
	}

	selector := k8sLabels.SelectorFromSet(config.labels)
	toMatch := k8sLabels.Set(epLabels)
	return selector.Matches(toMatch)
}

func buildRules(eps map[endpointID]*endpointMetadata, svcs map[serviceID]*serviceMetadata) map[crap.CrapKey]crap.CrapVal {
	ret := make(map[crap.CrapKey]crap.CrapVal)

	for _, svc := range svcs {
		var targetEp *endpointMetadata = nil

		for _, ep := range eps {
			if svc.matchesPodLabels(ep.labels) {
				targetEp = ep
				break
			}
		}

		if targetEp == nil {
			continue
		}

		for _, ip := range svc.vip {
			key := crap.NewKey(ip)
			val := crap.NewVal(targetEp.ip)

			ret[key] = val
		}
	}

	return ret
}

func (cm *CrapManager) updateRawRules(desired map[crap.CrapKey]crap.CrapVal) {
	if cm.bpfmap == nil {
		cm.logger.Error("bpf map is nil")
		return
	}

	existing := make(map[crap.CrapKey]crap.CrapVal)
	cm.bpfmap.IterateWithCallback(
		func(key *crap.CrapKey, val *crap.CrapVal) {
			existing[*key] = *val
		})

	// Start with the assumption that all the entries currently present in the
	// BPF map are stale. Then as we walk the entries below and discover which
	// entries are actually still needed, shrink this set down.
	stale := sets.KeySet(existing)

	for key, val := range desired {
		logger := cm.logger.With(
			logfields.DestinationIP, key.DestIP,
		)

		stale.Delete(key)

		if err := cm.bpfmap.Update(key, val); err != nil {
			logger.Error("Error applying raw rule", logfields.Error, err)
		} else {
			logger.Debug("rule was updated")
		}

	}

	// Remove all the entries marked as stale.
	for key := range stale {
		logger := cm.logger.With(
			logfields.DestinationIP, key.DestIP,
		)

		if err := cm.bpfmap.Delete(&key); err != nil {
			logger.Error("Error removing raw rule", logfields.Error, err)
		} else {
			logger.Debug("Raw rule was removed")
		}
	}
}

func (cm *CrapManager) reconcile(ctx context.Context, health cell.Health) error {
	epDataStore := make(map[endpointID]*endpointMetadata)
	svcDataStore := make(map[serviceID]*serviceMetadata)
	sync, syncEps, syncSvcs := false, false, false

	for {
		select {
		case d := <-cm.ch:
			for id, endpoint := range d.epDiff {
				if endpoint == nil {
					cm.logger.InfoContext(ctx, "removed an endpoint", logfields.ID, id)
					delete(epDataStore, id)
				} else {
					cm.logger.InfoContext(ctx, "stored an endpoint", logfields.ID, id)
					epDataStore[endpoint.id] = endpoint
				}
			}

			for id, svc := range d.serviceDiff {
				if svc == nil {
					cm.logger.InfoContext(ctx, "removed a service", logfields.ID, id)
					delete(svcDataStore, id)
				} else {
					cm.logger.InfoContext(ctx, "stored a service", logfields.ID, id)
					svcDataStore[svc.id] = svc
				}
			}

			if !sync {
				if d.epSync && !syncEps {
					cm.logger.InfoContext(ctx, "Endpoints were synced")
					syncEps = d.epSync
				}

				if d.serviceSync && !syncSvcs {
					cm.logger.InfoContext(ctx, "Services were synced")
					syncSvcs = d.serviceSync
				}

				sync = syncEps && syncSvcs
			}

			if !sync {
				continue
			}

			desired := buildRules(epDataStore, svcDataStore)
			cm.updateRawRules(desired)

		case <-ctx.Done():
			return nil
		}
	}
}

func registerCrapManager(params CrapParams) {
	mgr := newCrapManager(params)
	mgr.trigger = job.NewTrigger()

	// --- observers: signal only ---
	params.JobGroup.Add(job.Observer(
		"raw-service-observer",
		mgr.handleSvcEvent,
		params.Services,
	))

	params.JobGroup.Add(job.Observer(
		"raw-endpoint-observer",
		mgr.handleEndpointEvent,
		params.Endpoints,
	))

	params.JobGroup.Add(job.OneShot(
		"raw-reconciler",
		mgr.reconcile,
	))
}
