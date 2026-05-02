// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbipam

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math/big"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"go4.org/netipx"
	"k8s.io/apimachinery/pkg/api/meta"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/ipalloc"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_meta "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/api/meta"
	slim_meta_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	client_typed_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned/typed/core/v1"
	"github.com/cilium/cilium/pkg/lbipamconfig"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// The condition added to services to indicate if a request for IPs could be satisfied or not
	ciliumSvcRequestSatisfiedCondition = "cilium.io/IPAMRequestSatisfied"

	ciliumPoolIPsTotalCondition     = "cilium.io/IPsTotal"
	ciliumPoolIPsAvailableCondition = "cilium.io/IPsAvailable"
	ciliumPoolIPsUsedCondition      = "cilium.io/IPsUsed"
	ciliumPoolConflict              = "cilium.io/PoolConflict"

	ciliumSvcLBISKCNWildward = "*"

	// The string used in the FieldManager field on update options
	ciliumFieldManager = "cilium-operator-lb-ipam"

	serviceNamespaceLabel = "io.kubernetes.service.namespace"
	serviceNameLabel      = "io.kubernetes.service.name"
)

var (
	// eventsOpts are the options used with resource's Events()
	eventsOpts = resource.WithRateLimiter(
		// This rate limiter will retry in the following pattern
		// 250ms, 500ms, 1s, 2s, 4s, 8s, 16s, 32s, .... max 5m
		workqueue.NewTypedItemExponentialFailureRateLimiter[resource.WorkItem](250*time.Millisecond, 5*time.Minute),
	)
)

type poolClient interface {
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts meta_v1.PatchOptions, subresources ...string) (result *cilium_api_v2.CiliumLoadBalancerIPPool, err error)
}

type lbIPAMParams struct {
	logger *slog.Logger

	lbClasses   []string
	ipv4Enabled bool
	ipv6Enabled bool

	poolClient poolClient
	svcClient  client_typed_v1.ServicesGetter

	poolResource resource.Resource[*cilium_api_v2.CiliumLoadBalancerIPPool]
	svcResource  resource.Resource[*slim_core_v1.Service]

	jobGroup job.Group

	metrics *ipamMetrics

	config      lbipamconfig.Config
	defaultIPAM bool

	testCounters *testCounters
}

func newLBIPAM(params lbIPAMParams) *LBIPAM {
	lbIPAM := &LBIPAM{
		lbIPAMParams: params,
		pools:        newPoolStore(),
		sharingIndex: newSharingIndex(),
		serviceStore: NewServiceStore(),
	}
	return lbIPAM
}

// LBIPAM is the loadbalancer IP address manager, controller which allocates and assigns IP addresses
// to LoadBalancer services from the configured set of LoadBalancerIPPools in the cluster.
type LBIPAM struct {
	lbIPAMParams

	pools        poolStore
	sharingIndex sharingIndex
	serviceStore serviceStore
}

func (ipam *LBIPAM) restart() {
	ipam.logger.Info("Restarting LB IPAM")
	if ipam.testCounters != nil {
		ipam.testCounters.restarted.Add(1)
	}

	// Reset all stored state
	ipam.pools = newPoolStore()
	ipam.sharingIndex = newSharingIndex()
	ipam.serviceStore = NewServiceStore()

	// Re-start the main goroutine
	ipam.jobGroup.Add(
		job.OneShot("lbipam-main", func(ctx context.Context, health cell.Health) error {
			ipam.Run(ctx, health)
			return nil
		}),
	)
}

func (ipam *LBIPAM) Run(ctx context.Context, health cell.Health) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	poolChan := ipam.poolResource.Events(ctx, eventsOpts)

	ipam.logger.InfoContext(ctx, "LB-IPAM initializing")
	if ipam.testCounters != nil {
		ipam.testCounters.initializing.Add(1)
	}
	svcChan := ipam.initialize(ctx, poolChan)

	// Initialization was cancelled by a shutdown
	if svcChan == nil {
		return
	}
	ipam.logger.InfoContext(ctx, "LB-IPAM done initializing")
	if ipam.testCounters != nil {
		ipam.testCounters.initialized.Add(1)
	}

	for {
		select {
		case <-ctx.Done():
			return

		case event, ok := <-poolChan:
			if !ok {
				poolChan = nil
				continue
			}
			ipam.handlePoolEvent(ctx, event)

			// This controller must go back into a dormant state when the last pool has been removed
			if len(ipam.pools) == 0 {
				// Upon return, restart the controller, which will start in pre-init state
				defer ipam.restart()
				return
			}

		case event, ok := <-svcChan:
			if !ok {
				svcChan = nil
				continue
			}
			ipam.handleServiceEvent(ctx, event, false)
		}
	}
}

func (ipam *LBIPAM) initialize(
	ctx context.Context,
	poolChan <-chan resource.Event[*cilium_api_v2.CiliumLoadBalancerIPPool],
) <-chan resource.Event[*slim_core_v1.Service] {
	// Synchronize pools first as we need them before we can satisfy
	// the services. This will also wait for the first pool to appear
	// before we start processing the services, which will save us from
	// unnecessary work when LB-IPAM is not used.
	poolsSynced := false
	for {

		event, ok := <-poolChan
		// channel has been closed, we're shutting down. Don't try to update services
		if !ok {
			return nil
		}
		if event.Kind == resource.Sync {
			err := ipam.settleConflicts(ctx)
			if err != nil {
				ipam.logger.ErrorContext(ctx, "Error while settling pool conflicts", logfields.Error, err)
				// Keep retrying the handling of the sync event until we succeed.
				// During this time we may receive further updates and deletes.
				event.Done(err)
				continue
			}
			poolsSynced = true
			event.Done(nil)
		} else {
			ipam.handlePoolEvent(ctx, event)
		}

		// Pools have been synchronized and we've got more than
		// one pool, continue initialization.
		if poolsSynced && len(ipam.pools) > 0 {
			break
		}
	}

	svcChan := ipam.svcResource.Events(ctx, eventsOpts)
	for event := range svcChan {
		if event.Kind == resource.Sync {
			if err := ipam.revalidateAllServices(ctx); err != nil {
				ipam.logger.ErrorContext(ctx, "Error while revalidating services", logfields.Error, err)
				// Keep retrying the handling of the sync event until we succeed.
				event.Done(err)
				continue
			}
			if err := ipam.updateAllPoolCounts(ctx); err != nil {
				ipam.logger.ErrorContext(ctx, "Error while updating pool counts", logfields.Error, err)
				event.Done(err)
				continue
			}
			event.Done(nil)
			break
		} else {
			ipam.handleServiceEvent(ctx, event, true)
		}
	}

	return svcChan
}

func (ipam *LBIPAM) handlePoolEvent(ctx context.Context, event resource.Event[*cilium_api_v2.CiliumLoadBalancerIPPool]) {
	if ipam.testCounters != nil {
		defer func() {
			ipam.testCounters.poolEvents.Add(1)
		}()
	}

	var err error
	switch event.Kind {
	case resource.Upsert:
		err = ipam.poolOnUpsert(ctx, event.Object)
		if err != nil {
			ipam.logger.ErrorContext(ctx, "pool upsert failed", logfields.Error, err)
			err = fmt.Errorf("poolOnUpsert: %w", err)
		}
	case resource.Delete:
		err = ipam.poolOnDelete(ctx, event.Object)
		if err != nil {
			ipam.logger.ErrorContext(ctx, "pool delete failed", logfields.Error, err)
			err = fmt.Errorf("poolOnDelete: %w", err)
		}
	}
	event.Done(err)
}

func (ipam *LBIPAM) handleServiceEvent(ctx context.Context, event resource.Event[*slim_core_v1.Service], init bool) {
	if ipam.testCounters != nil {
		defer func() {
			ipam.testCounters.serviceEvents.Add(1)
		}()
	}

	var err error
	switch event.Kind {
	case resource.Upsert:
		err = ipam.svcOnUpsert(ctx, event.Object, init)
		if err != nil {
			ipam.logger.ErrorContext(ctx, "service upsert failed", logfields.Error, err)
			err = fmt.Errorf("svcOnUpsert: %w", err)
		}
	case resource.Delete:
		err = ipam.svcOnDelete(ctx, event.Object, init)
		if err != nil {
			ipam.logger.ErrorContext(ctx, "service delete failed", logfields.Error, err)
			err = fmt.Errorf("svcOnDelete: %w", err)
		}
	}
	event.Done(err)
}

func (ipam *LBIPAM) poolOnUpsert(ctx context.Context, pool *cilium_api_v2.CiliumLoadBalancerIPPool) error {
	if ipam.metrics.EventProcessingTime.IsEnabled() {
		defer func(start time.Time) {
			ipam.metrics.EventProcessingTime.WithLabelValues("upsert", "pool").Observe(time.Since(start).Seconds())
		}(time.Now())
	}

	// Deep copy so we get a version we are allowed to update the status
	pool = pool.DeepCopy()

	var err error
	if existingPool, exists := ipam.pools[pool.GetName()]; exists {
		// Spec hasn't changed, nothing to do
		if existingPool.k8s.Spec.DeepEqual(&pool.Spec) {
			return nil
		} else {
			ipam.logger.Info("Updated Pool spec",
				logfields.PoolName, pool.GetName(),
				logfields.PoolOldSpec, existingPool.k8s.Spec,
				logfields.PoolNewSpec, pool.Spec)
		}

		err = ipam.handlePoolModified(ctx, existingPool, pool)
		if err != nil {
			return fmt.Errorf("handlePoolModified: %w", err)
		}
	} else {
		err = ipam.handleNewPool(ctx, pool)
		if err != nil {
			return fmt.Errorf("handleNewPool: %w", err)
		}
	}
	if err != nil {
		return err
	}

	err = ipam.settleConflicts(ctx)
	if err != nil {
		return fmt.Errorf("settleConflicts: %w", err)
	}

	err = ipam.satisfyAndUpdateCounts(ctx)
	if err != nil {
		return fmt.Errorf("satisfyAndUpdateCounts: %w", err)
	}

	return nil
}

func (ipam *LBIPAM) poolOnDelete(ctx context.Context, pool *cilium_api_v2.CiliumLoadBalancerIPPool) error {
	if ipam.metrics.EventProcessingTime.IsEnabled() {
		defer func(start time.Time) {
			ipam.metrics.EventProcessingTime.WithLabelValues("delete", "pool").Observe(time.Since(start).Seconds())
		}(time.Now())
	}

	err := ipam.handlePoolDeleted(ctx, pool)
	if err != nil {
		return fmt.Errorf("handlePoolDeleted: %w", err)
	}

	err = ipam.settleConflicts(ctx)
	if err != nil {
		return fmt.Errorf("settleConflicts: %w", err)
	}

	err = ipam.satisfyAndUpdateCounts(ctx)
	if err != nil {
		return fmt.Errorf("satisfyAndUpdateCounts: %w", err)
	}

	return nil
}

func (ipam *LBIPAM) svcOnUpsert(ctx context.Context, svc *slim_core_v1.Service, init bool) error {
	if ipam.metrics.EventProcessingTime.IsEnabled() {
		defer func(start time.Time) {
			ipam.metrics.EventProcessingTime.WithLabelValues("upsert", "service").Observe(time.Since(start).Seconds())
		}(time.Now())
	}

	err := ipam.handleUpsertService(ctx, svc, init)
	if err != nil {
		return fmt.Errorf("handleUpsertService: %w", err)
	}

	if init {
		// No need to satisfy or update on init,
		// it will happen later after full sync
		return nil
	}

	err = ipam.satisfyAndUpdateCounts(ctx)
	if err != nil {
		return fmt.Errorf("satisfyAndUpdateCounts: %w", err)
	}

	return nil
}

func (ipam *LBIPAM) svcOnDelete(ctx context.Context, svc *slim_core_v1.Service, init bool) error {
	if ipam.metrics.EventProcessingTime.IsEnabled() {
		defer func(start time.Time) {
			ipam.metrics.EventProcessingTime.WithLabelValues("delete", "service").Observe(time.Since(start).Seconds())
		}(time.Now())
	}

	ipam.logger.DebugContext(ctx, fmt.Sprintf("Deleted service '%s/%s'", svc.GetNamespace(), svc.GetName()))

	ipam.handleDeletedService(svc)

	if init {
		// No need to satisfy or update on init,
		// it will happen later after full sync
		return nil
	}
	err := ipam.satisfyAndUpdateCounts(ctx)
	if err != nil {
		return fmt.Errorf("satisfyAndUpdateCounts: %w", err)
	}

	return nil
}

func (ipam *LBIPAM) satisfyAndUpdateCounts(ctx context.Context) error {
	err := ipam.satisfyServices(ctx)
	if err != nil {
		return fmt.Errorf("satisfyServices: %w", err)
	}

	err = ipam.updateAllPoolCounts(ctx)
	if err != nil {
		return fmt.Errorf("updateAllPoolCounts: %w", err)
	}

	return nil
}

// handleUpsertService updates the service view in the service store, it removes any allocation and ingress that
// do not belong on the service and will move the service to the satisfied or unsatisfied service view store depending
// on if the service requests are satisfied or not.
func (ipam *LBIPAM) handleUpsertService(ctx context.Context, svc *slim_core_v1.Service, init bool) error {
	key := resource.NewKey(svc)

	// Ignore services which are not meant for us
	if !ipam.isResponsibleForSVC(svc) {
		sv, found, _ := ipam.serviceStore.GetService(key)
		if !found {
			// We were not responsible for this service before, so nothing to do
			return nil
		}

		// we were responsible before, but not anymore

		// Release allocations and other references as if the service was deleted
		if err := ipam.svcOnDelete(ctx, svc, init); err != nil {
			return fmt.Errorf("svcOnDelete: %w", err)
		}

		// Remove all ingress IPs and conditions, cleaning up the service for reuse by another controller
		ipam.logger.Info("Removing all Ingress IPs and conditions", logfields.ServiceName, sv.Key)
		sv.Status.LoadBalancer.Ingress = nil
		slim_meta.RemoveStatusCondition(&sv.Status.Conditions, ciliumSvcRequestSatisfiedCondition)

		err := ipam.patchSvcStatus(ctx, sv)
		if err != nil {
			return fmt.Errorf("patchSvcStatus: %w", err)
		}

		return nil
	}

	// We are responsible for this service.

	sv := ipam.serviceViewFromService(key, svc)

	if init {
		// No need to satisfy or update on init,
		// it will happen later after full sync
		ipam.serviceStore.Upsert(sv)
		return nil
	}

	// Remove any allocation that are no longer valid due to a change in the service spec
	err := ipam.stripInvalidAllocations(sv)
	if err != nil {
		return fmt.Errorf("stripInvalidAllocations: %w", err)
	}

	// Check for each ingress, if its IP has been allocated by us. If it isn't check if we can allocate that IP.
	// If we can't, strip the ingress from the service.
	svModifiedStatus, err := ipam.stripOrImportIngresses(sv)
	if err != nil {
		return fmt.Errorf("stripOrImportIngresses: %w", err)
	}

	// Attempt to satisfy this service in particular now. We do this now instead of relying on
	// ipam.satisfyServices to avoid updating the service twice in quick succession.
	if !sv.isSatisfied() {
		modified, err := ipam.satisfyService(sv)
		if err != nil {
			return fmt.Errorf("satisfyService: %w", err)
		}
		if modified {
			svModifiedStatus = true
		}
	}

	// If any of the steps above changed the service object, update the object.
	if svModifiedStatus {
		err := ipam.patchSvcStatus(ctx, sv)
		if err != nil {
			return fmt.Errorf("patchSvcStatus: %w", err)
		}
	}

	ipam.serviceStore.Upsert(sv)

	return nil
}

func (ipam *LBIPAM) serviceViewFromService(key resource.Key, svc *slim_core_v1.Service) *ServiceView {
	sv, found, _ := ipam.serviceStore.GetService(key)
	if !found {
		sv = &ServiceView{
			Key: key,
		}
	}

	// Update the service view
	sv.Generation = svc.Generation
	sv.Labels = svcLabels(svc)
	sv.RequestedFamilies.IPv4, sv.RequestedFamilies.IPv6 = ipam.serviceIPFamilyRequest(svc)
	sv.RequestedIPs = getSVCRequestedIPs(ipam.logger, svc)
	sv.SharingKey = getSVCSharingKey(svc)
	sv.SharingCrossNamespace = getSVCSharingCrossNamespace(svc)
	sv.ExternalTrafficPolicy = svc.Spec.ExternalTrafficPolicy
	sv.Ports = make([]slim_core_v1.ServicePort, len(svc.Spec.Ports))
	copy(sv.Ports, svc.Spec.Ports)
	sv.Namespace = svc.Namespace
	sv.Selector = make(map[string]string)
	maps.Copy(sv.Selector, svc.Spec.Selector)
	sv.Status = svc.Status.DeepCopy()

	return sv
}

func (ipam *LBIPAM) stripInvalidAllocations(sv *ServiceView) error {
	var errs error
	// Remove bad allocations which are no longer valid
	for allocIdx := len(sv.AllocatedIPs) - 1; allocIdx >= 0; allocIdx-- {
		alloc := sv.AllocatedIPs[allocIdx]
		cluster, _ := alloc.Origin.alloc.Get(alloc.IP)

		releaseAllocIP := func() {
			ipam.logger.Debug(fmt.Sprintf("removing allocation '%s' from '%s'", alloc.IP, sv.Key))
			if empty := cluster.Remove(sv); empty {
				alloc.Origin.alloc.Free(alloc.IP)
			}
			sv.AllocatedIPs = slices.Delete(sv.AllocatedIPs, allocIdx, allocIdx+1)
		}

		// If origin pool no longer exists, remove allocation
		pool, found := ipam.pools[alloc.Origin.originPool]
		if !found {
			releaseAllocIP()
			continue
		}

		// If service no longer matches the pool selector, remove allocation
		if pool.k8s.Spec.ServiceSelector != nil {
			selector, err := slim_meta_v1.LabelSelectorAsSelector(pool.k8s.Spec.ServiceSelector)
			if err != nil {
				errs = errors.Join(errs, fmt.Errorf("making selector from pool '%s' label selector", pool.k8s.Name))
				continue
			}

			if !selector.Matches(sv.Labels) {
				releaseAllocIP()
				continue
			}
		}

		// Check if the service is still compatible with the cluster sharing this IP. If it isn't, remove the allocation
		if compatible, _ := cluster.IsCompatible(sv); !compatible {
			releaseAllocIP()
			continue
		}

		// If the service is requesting specific IPs
		if len(sv.RequestedIPs) > 0 {
			found := false
			for _, reqIP := range sv.RequestedIPs {
				if reqIP.Compare(alloc.IP) == 0 {
					found = true
					break
				}
			}
			// If allocated IP has not been requested, remove it
			if !found {
				releaseAllocIP()
				continue
			}
		} else {
			// No specific requests have been made, check if we have ingresses from un-requested families.

			if alloc.IP.Is6() {
				// Service has an IPv6 address, but its spec doesn't request it anymore, so take it away
				if !sv.RequestedFamilies.IPv6 {
					releaseAllocIP()
					continue
				}
			} else {
				// Service has an IPv4 address, but its spec doesn't request it anymore, so take it away
				if !sv.RequestedFamilies.IPv4 {
					releaseAllocIP()
					continue
				}
			}
		}
	}

	return errs
}

func (ipam *LBIPAM) stripOrImportIngresses(sv *ServiceView) (statusModified bool, err error) {
	var newIngresses []slim_core_v1.LoadBalancerIngress

	// Only keep valid ingresses.
	for _, ingress := range sv.Status.LoadBalancer.Ingress {
		if ingress.IP == "" {
			continue
		}

		ip, err := netip.ParseAddr(ingress.IP)
		if err != nil {
			continue
		}

		// Remove any ingress which is no longer allocated
		var viewIP *ServiceViewIP
		for i, vip := range sv.AllocatedIPs {
			if vip.IP.Compare(ip) == 0 {
				viewIP = &sv.AllocatedIPs[i]
				break
			}
		}
		if viewIP == nil {
			// The ingress is not allocated by LB IPAM, check if we can "import it"

			// If the service has requested IP, the ingress must match one of them.
			if len(sv.RequestedIPs) > 0 {
				found := false
				for _, reqIP := range sv.RequestedIPs {
					if reqIP.Compare(ip) == 0 {
						found = true
						break
					}
				}
				if !found {
					// Don't keep ingress
					continue
				}
			}

			if ip.Is6() {
				if !sv.RequestedFamilies.IPv6 {
					continue
				}
			} else {
				if !sv.RequestedFamilies.IPv4 {
					continue
				}
			}

			lbRange, _, err := ipam.findRangeOfIP(sv, ip)
			if err != nil {
				return statusModified, fmt.Errorf("findRangeOfIP: %w", err)
			}
			if lbRange == nil {
				ipam.logger.Warn(
					"Current IP does not belong to any matching range, deferring to regular allocation logic",
					logfields.IPAddr, ip,
					logfields.ServiceName, sv.Key,
				)
				continue
			}

			sharingCluster := &sharingCluster{Services: []*ServiceView{sv}, SVIP: ServiceViewIP{IP: ip, Origin: lbRange}}
			err = lbRange.alloc.Alloc(ip, sharingCluster)
			if err != nil {
				if errors.Is(err, ipalloc.ErrInUse) {
					ipam.logger.Warn(
						"Current IP is already allocated by another service, deferring to regular allocation logic",
						logfields.IPAddr, ingress.IP,
						logfields.ServiceName, sv.Key,
					)
					// The IP is already allocated, defer to regular allocation logic to determine
					// if this service can share the allocation.
					continue
				}

				return statusModified, fmt.Errorf("error while attempting to allocate IP '%s'", ingress.IP)
			}
			sv.AllocatedIPs = append(sv.AllocatedIPs, sharingCluster.SVIP)
			if sv.SharingKey != "" {
				ipam.sharingIndex.Add(sv.SharingKey, sharingCluster)
			}
		}

		newIngresses = append(newIngresses, ingress)
	}

	// Deduplicate ingress IPs (condition can be created externally before we adopted the service)
	newIngresses = slices.CompactFunc(newIngresses, func(a, b slim_core_v1.LoadBalancerIngress) bool {
		return a.IP == b.IP
	})

	// Check if we have removed any ingresses
	if len(sv.Status.LoadBalancer.Ingress) != len(newIngresses) {
		removedIPs := map[string]struct{}{}
		for _, lbi := range sv.Status.LoadBalancer.Ingress {
			removedIPs[lbi.IP] = struct{}{}
		}
		for _, lbi := range newIngresses {
			delete(removedIPs, lbi.IP)
		}
		ipam.logger.Info("Removing Ingress IPs",
			logfields.ServiceName, sv.Key,
			logfields.IPAddrs, slices.Collect(maps.Keys(removedIPs)),
		)
		statusModified = true
	}

	sv.Status.LoadBalancer.Ingress = newIngresses

	return statusModified, nil
}

func getSVCRequestedIPs(log *slog.Logger, svc *slim_core_v1.Service) []netip.Addr {
	var ips []netip.Addr
	if svc.Spec.LoadBalancerIP != "" {
		ip, err := netip.ParseAddr(svc.Spec.LoadBalancerIP)
		if err == nil {
			ips = append(ips, ip)
		} else {
			log.Error("Unable to parse service.spec.LoadBalancerIP", logfields.Error, err)
		}
	}

	if value, _ := annotation.Get(svc, annotation.LBIPAMIPsKey, annotation.LBIPAMIPKeyAlias); value != "" {
		for ipStr := range strings.SplitSeq(value, ",") {
			ip, err := netip.ParseAddr(strings.TrimSpace(ipStr))
			if err == nil {
				ips = append(ips, ip)
			} else {
				log.Error("Unable to parse service.spec.LoadBalancerIP", logfields.Error, err)
			}
		}
	}

	return slices.CompactFunc(ips, func(a, b netip.Addr) bool {
		return a.Compare(b) == 0
	})
}

func getSVCSharingKey(svc *slim_core_v1.Service) sharingKey {
	if val, _ := annotation.Get(svc, annotation.LBIPAMSharingKey, annotation.LBIPAMSharingKeyAlias); val != "" {
		return sharingKey(val)
	}
	return ""
}

func getSVCSharingCrossNamespace(svc *slim_core_v1.Service) []string {
	if val, _ := annotation.Get(svc, annotation.LBIPAMSharingAcrossNamespace, annotation.LBIPAMSharingAcrossNamespaceAlias); val != "" {
		return strings.Split(val, ",")
	}
	return []string{}
}

func (ipam *LBIPAM) handleDeletedService(svc *slim_core_v1.Service) {
	key := resource.NewKey(svc)
	sv, found, _ := ipam.serviceStore.GetService(key)
	if !found {
		return
	}

	// Remove all allocations for this service
	for _, alloc := range sv.AllocatedIPs {
		// Even if a service doesn't have a sharing key, each allocation is a sharing cluster
		cluster, found := alloc.Origin.alloc.Get(alloc.IP)
		if !found {
			continue
		}

		// Remove this IP from the sharing cluster
		i := slices.Index(cluster.Services, sv)
		if i != -1 {
			cluster.Services = slices.Delete(cluster.Services, i, i+1)
		}

		// If all services have been removed from the sharing cluster, free the IP.
		if len(cluster.Services) == 0 {
			alloc.Origin.alloc.Free(alloc.IP)
			// The `ServiceView` has a sharing key, remove the IP from the sharing index
			if sv.SharingKey != "" {
				ipam.sharingIndex.Remove(sv.SharingKey, cluster)
			}
		}

	}

	ipam.serviceStore.Delete(key)
}

// satisfyServices attempts to satisfy all unsatisfied services by allocating and assigning IP addresses
func (ipam *LBIPAM) satisfyServices(ctx context.Context) error {
	for _, sv := range ipam.serviceStore.unsatisfied {
		statusModified, err := ipam.satisfyService(sv)
		if err != nil {
			return fmt.Errorf("satisfyService: %w", err)
		}

		// If the services status has been modified, update the service.
		if statusModified {
			err := ipam.patchSvcStatus(ctx, sv)
			if err != nil {
				return fmt.Errorf("patchSvcStatus: %w", err)
			}
		}

		ipam.serviceStore.Upsert(sv)
	}

	return nil
}

func (ipam *LBIPAM) satisfyService(sv *ServiceView) (statusModified bool, err error) {
	if len(sv.RequestedIPs) > 0 {
		statusModified, err = ipam.satisfySpecificIPRequests(sv)
		if err != nil {
			return statusModified, fmt.Errorf("satisfySpecificIPRequests: %w", err)
		}
	} else {
		statusModified, err = ipam.satisfyGenericIPRequests(sv)
		if err != nil {
			return statusModified, fmt.Errorf("satisfyGenericIPRequests: %w", err)
		}
	}

	// Sync allocated IPs back to the service
	for _, alloc := range sv.AllocatedIPs {
		// If the allocated IP isn't found in the assigned list, assign it
		if slices.IndexFunc(sv.Status.LoadBalancer.Ingress, func(in slim_core_v1.LoadBalancerIngress) bool {
			addr, err := netip.ParseAddr(in.IP)
			if err != nil {
				return false
			}

			return addr.Compare(alloc.IP) == 0
		}) == -1 {
			// We allocated a new IP, add it to the ingress list
			ipam.logger.Info("Assigning Ingress IP",
				logfields.ServiceName, sv.Key,
				logfields.IPAddr, alloc.IP,
			)
			sv.Status.LoadBalancer.Ingress = append(sv.Status.LoadBalancer.Ingress, slim_core_v1.LoadBalancerIngress{
				IP: alloc.IP.String(),
			})
			statusModified = true
		}
	}

	if sv.isSatisfied() {
		if ipam.setSVCSatisfiedCondition(sv, true, "satisfied", "") {
			statusModified = true
		}
	}

	ipam.serviceStore.Upsert(sv)

	return statusModified, err
}

func (ipam *LBIPAM) satisfySpecificIPRequests(sv *ServiceView) (statusModified bool, err error) {
	// The service requests specific IPs
	for _, reqIP := range sv.RequestedIPs {
		// If the requests IP is already allocated, to this service, skip it
		if slices.IndexFunc(sv.AllocatedIPs, func(sv ServiceViewIP) bool {
			return reqIP.Compare(sv.IP) == 0
		}) != -1 {
			continue
		}

		lbRange, foundPool, err := ipam.findRangeOfIP(sv, reqIP)
		if err != nil {
			return statusModified, fmt.Errorf("findRangeOfIP: %w", err)
		}
		if lbRange == nil {
			msg := fmt.Sprintf("No pool exists with a CIDR containing '%s'", reqIP)
			reason := "no_pool"
			if foundPool {
				msg = fmt.Sprintf("The pool with the CIDR containing '%s', doesn't select this service", reqIP)
				reason = "pool_selector_mismatch"
			}
			if ipam.setSVCSatisfiedCondition(sv, false, reason, msg) {
				statusModified = true
			}

			continue
		}

		if cluster, exists := lbRange.alloc.Get(reqIP); exists {
			// The IP is already assigned to another service, if we have a sharing key we might be able to share it.
			if sv.SharingKey == "" {
				msg := fmt.Sprintf("The IP '%s' is already allocated to another service", reqIP)
				reason := "already_allocated"
				if ipam.setSVCSatisfiedCondition(sv, false, reason, msg) {
					statusModified = true
				}
				continue
			}

			// Check if the service is compatible with the services sharing the IP.
			if compatible, reason := cluster.IsCompatible(sv); !compatible {
				// The IP was requested and a sharing key was provided, but the service isn't compatible with one of the services sharing the IP.
				msg := fmt.Sprintf("The IP '%s' is already allocated to an incompatible service. Reason: %s", reqIP, reason)
				reason := "already_allocated_incompatible_service"
				if ipam.setSVCSatisfiedCondition(sv, false, reason, msg) {
					statusModified = true
				}
				continue
			}
			cluster.Services = append(cluster.Services, sv)
		} else {
			ipam.logger.Debug(fmt.Sprintf("Allocate '%s' for '%s'", reqIP, sv.Key))
			sharingCluster := &sharingCluster{
				SVIP:     ServiceViewIP{IP: reqIP, Origin: lbRange},
				Services: []*ServiceView{sv},
			}
			err = lbRange.alloc.Alloc(reqIP, sharingCluster)
			if err != nil {
				if errors.Is(err, ipalloc.ErrInUse) {
					return statusModified, fmt.Errorf("ipalloc.Alloc: %w", err)
				}

				ipam.logger.Error("Unable to allocate IP", logfields.Error, err)
				continue
			}

			if sv.SharingKey != "" {
				ipam.sharingIndex.Add(sv.SharingKey, sharingCluster)
			}
		}

		sv.AllocatedIPs = append(sv.AllocatedIPs, ServiceViewIP{
			IP:     reqIP,
			Origin: lbRange,
		})
	}

	return statusModified, nil
}

func (ipam *LBIPAM) satisfyGenericIPRequests(sv *ServiceView) (statusModified bool, err error) {
	hasIPv4 := false
	hasIPv6 := false
	for _, allocated := range sv.AllocatedIPs {
		if allocated.IP.Is6() {
			hasIPv6 = true
		} else {
			hasIPv4 = true
		}
	}

	// Missing an IPv4 address, lets attempt to allocate an address
	if sv.RequestedFamilies.IPv4 && !hasIPv4 {
		statusModified, err = ipam.satisfyGenericRequest(sv, IPv4Family)
		if err != nil {
			return statusModified, fmt.Errorf("satisfyGenericRequest: %w", err)
		}
	}

	// Missing an IPv6 address, lets attempt to allocate an address
	if sv.RequestedFamilies.IPv6 && !hasIPv6 {
		statusModified, err = ipam.satisfyGenericRequest(sv, IPv6Family)
		if err != nil {
			return statusModified, fmt.Errorf("satisfyGenericRequest: %w", err)
		}
	}

	return statusModified, nil
}

func (ipam *LBIPAM) satisfyGenericRequest(sv *ServiceView, family AddressFamily) (statusModified bool, err error) {
	if sv.SharingKey != "" {
		// Check if we can share an already allocated IP in the same sharing group.
		for _, sharingCluster := range ipam.sharingIndex.Get(sv.SharingKey) {
			// Only attempt to share IPs of the same address family
			if addressFamilyOfIP(sharingCluster.SVIP.IP) != family {
				continue
			}

			// if it is, add the service view to the list, and satisfy the IP
			if compatible, _ := sharingCluster.IsCompatible(sv); compatible {
				sv.AllocatedIPs = append(sv.AllocatedIPs, sharingCluster.SVIP)
				sharingCluster.Add(sv)
				return statusModified, nil
			}
		}
	}

	// Unable to share an already allocated IP, so lets allocate a new one
	newSharingCluster, err := ipam.allocateIPAddress(sv, family)
	if err != nil && !errors.Is(err, ipalloc.ErrFull) {
		return statusModified, fmt.Errorf("allocateIPAddress: %w", err)
	}
	if newSharingCluster != nil {
		sv.AllocatedIPs = append(sv.AllocatedIPs, newSharingCluster.SVIP)
		if sv.SharingKey != "" {
			ipam.sharingIndex.Add(sv.SharingKey, newSharingCluster)
		}
	} else {
		reason := "no_pool"
		message := "There are no enabled CiliumLoadBalancerIPPools that match this service"
		if errors.Is(err, ipalloc.ErrFull) {
			reason = "out_of_ips"
			message = "All enabled CiliumLoadBalancerIPPools that match this service ran out of allocatable IPs"
		}

		if ipam.setSVCSatisfiedCondition(sv, false, reason, message) {
			statusModified = true
		}
	}

	return statusModified, nil
}

func (ipam *LBIPAM) setSVCSatisfiedCondition(
	sv *ServiceView,
	satisfied bool,
	reason, message string,
) (statusModified bool) {
	status := slim_meta_v1.ConditionFalse
	if satisfied {
		status = slim_meta_v1.ConditionTrue
	}

	if cond := slim_meta.FindStatusCondition(sv.Status.Conditions, ciliumSvcRequestSatisfiedCondition); cond != nil &&
		cond.Status == status &&
		cond.ObservedGeneration == sv.Generation &&
		cond.Reason == reason &&
		cond.Message == message {
		return false
	}

	slim_meta.SetStatusCondition(&sv.Status.Conditions, slim_meta_v1.Condition{
		Type:               ciliumSvcRequestSatisfiedCondition,
		Status:             status,
		ObservedGeneration: sv.Generation,
		LastTransitionTime: slim_meta_v1.Now(),
		Reason:             reason,
		Message:            message,
	})
	return true
}

func (ipam *LBIPAM) findRangeOfIP(sv *ServiceView, ip netip.Addr) (lbRange *LBRange, foundPool bool, err error) {
	for r := range ipam.pools.Ranges() {
		if r.Disabled() {
			continue
		}

		from, to := r.alloc.Range()
		if ip.Compare(from) < 0 || ip.Compare(to) > 0 {
			continue
		}

		pool, found := ipam.pools[r.originPool]
		if !found {
			continue
		}

		foundPool = true

		if pool.k8s.Spec.ServiceSelector != nil {
			selector, err := slim_meta_v1.LabelSelectorAsSelector(pool.k8s.Spec.ServiceSelector)
			if err != nil {
				return nil, false, fmt.Errorf("making selector from pool '%s' label selector: %w", pool.k8s.Name, err)
			}

			if !selector.Matches(sv.Labels) {
				continue
			}
		}

		return r, false, nil
	}

	return nil, foundPool, nil
}

// isResponsibleForSVC checks if LB IPAM should allocate and assign IPs or some other controller
func (ipam *LBIPAM) isResponsibleForSVC(svc *slim_core_v1.Service) bool {
	// Ignore non-lb services
	if svc.Spec.Type != slim_core_v1.ServiceTypeLoadBalancer {
		return false
	}

	if svc.Spec.LoadBalancerClass == nil {
		return ipam.lbIPAMParams.defaultIPAM
	}

	if !slices.Contains(ipam.lbClasses, *svc.Spec.LoadBalancerClass) {
		return false
	}

	return true
}

type AddressFamily string

const (
	IPv4Family AddressFamily = "IPv4"
	IPv6Family AddressFamily = "IPv6"
)

func addressFamilyOfIP(ip netip.Addr) AddressFamily {
	if ip.Is6() {
		return IPv6Family
	}
	return IPv4Family
}

func (ipam *LBIPAM) allocateIPAddress(
	sv *ServiceView,
	family AddressFamily,
) (*sharingCluster, error) {
	full := false
	for lbRange := range ipam.pools.Ranges() {
		// If the range is disabled we can't allocate new IPs from it.
		if lbRange.Disabled() {
			continue
		}

		// Skip this range if it doesn't match the requested address family
		if _, to := lbRange.alloc.Range(); to.Is6() {
			if family == IPv4Family {
				continue
			}
		} else {
			if family == IPv6Family {
				continue
			}
		}

		pool, found := ipam.pools[lbRange.originPool]
		if !found {
			ipam.logger.Warn(fmt.Sprintf("Bad state detected, store contains lbRange for pool '%s' but missing the pool", lbRange.originPool),
				logfields.PoolName, lbRange.originPool)
			continue
		}

		// If there is no selector, all services match
		if pool.k8s.Spec.ServiceSelector != nil {
			selector, err := slim_meta_v1.LabelSelectorAsSelector(pool.k8s.Spec.ServiceSelector)
			if err != nil {
				return nil, fmt.Errorf("making selector from pool '%s' label selector: %w", pool.k8s.Name, err)
			}

			if !selector.Matches(sv.Labels) {
				continue
			}
		}

		// Attempt to allocate the next IP from this range.
		sharingCluster := &sharingCluster{Services: []*ServiceView{sv}}
		newIp, err := lbRange.alloc.AllocAny(sharingCluster)
		if err != nil {
			// If the range is full, mark it.
			if errors.Is(err, ipalloc.ErrFull) {
				full = true
				continue
			}

			ipam.logger.Error("Allocate next IP from lb range", logfields.Error, err)
			continue
		}
		sharingCluster.SVIP = ServiceViewIP{
			IP:     newIp,
			Origin: lbRange,
		}

		return sharingCluster, nil
	}

	if full {
		return nil, ipalloc.ErrFull
	}

	return nil, nil
}

// serviceIPFamilyRequest checks which families of IP addresses are requested
func (ipam *LBIPAM) serviceIPFamilyRequest(svc *slim_core_v1.Service) (IPv4Requested, IPv6Requested bool) {
	if svc.Spec.IPFamilyPolicy != nil {
		switch *svc.Spec.IPFamilyPolicy {
		case slim_core_v1.IPFamilyPolicySingleStack:
			if len(svc.Spec.IPFamilies) > 0 {
				if svc.Spec.IPFamilies[0] == slim_core_v1.IPFamily(IPv4Family) {
					IPv4Requested = true
				} else {
					IPv6Requested = true
				}
			} else {
				if ipam.ipv4Enabled {
					IPv4Requested = true
				} else if ipam.ipv6Enabled {
					IPv6Requested = true
				}
			}

		case slim_core_v1.IPFamilyPolicyPreferDualStack:
			if len(svc.Spec.IPFamilies) > 0 {
				for _, family := range svc.Spec.IPFamilies {
					if family == slim_core_v1.IPFamily(IPv4Family) {
						IPv4Requested = ipam.ipv4Enabled
					}
					if family == slim_core_v1.IPFamily(IPv6Family) {
						IPv6Requested = ipam.ipv6Enabled
					}
				}
			} else {
				// If no IPFamilies are specified

				IPv4Requested = ipam.ipv4Enabled
				IPv6Requested = ipam.ipv6Enabled
			}

		case slim_core_v1.IPFamilyPolicyRequireDualStack:
			IPv4Requested = ipam.ipv4Enabled
			IPv6Requested = ipam.ipv6Enabled
		}
	} else {
		if len(svc.Spec.IPFamilies) > 0 {
			if svc.Spec.IPFamilies[0] == slim_core_v1.IPFamily(IPv4Family) {
				IPv4Requested = true
			} else {
				IPv6Requested = true
			}
		} else {
			if ipam.ipv4Enabled {
				IPv4Requested = true
			} else if ipam.ipv6Enabled {
				IPv6Requested = true
			}
		}
	}

	return IPv4Requested, IPv6Requested
}

// Handle the addition of a new IPPool
func (ipam *LBIPAM) handleNewPool(ctx context.Context, k8sPool *cilium_api_v2.CiliumLoadBalancerIPPool) error {
	// Sanity check that we do not yet know about this pool.
	if _, found := ipam.pools[k8sPool.GetName()]; found {
		ipam.logger.WarnContext(ctx,
			fmt.Sprintf("LB IPPool '%s' has been created, but a LB IP Pool with the same name already exists", k8sPool.GetName()),
			logfields.PoolName, k8sPool.GetName())
		return nil
	}

	pool := &LBPool{k8s: k8sPool}
	for _, ipBlock := range k8sPool.Spec.Blocks {
		from, to, fromCidr, err := ipRangeFromBlock(ipBlock)
		if err != nil {
			return fmt.Errorf("error parsing ip block: %w", err)
		}

		lbRange, err := NewLBRange(from, to, k8sPool)
		if err != nil {
			return fmt.Errorf("error making LB Range for '%s': %w", ipBlock.Cidr, err)
		}

		// If AllowFirstLastIPs is no, mark the first and last IP as allocated upon range creation.
		if fromCidr && k8sPool.Spec.AllowFirstLastIPs == cilium_api_v2.AllowFirstLastIPNo {
			from, to := lbRange.alloc.Range()

			// If the first and last IPs are the same or adjacent, we would reserve the entire range.
			// Only reserve first and last IPs for ranges /30 or /126 and larger.
			if !(from.Compare(to) == 0 || from.Next().Compare(to) == 0) {
				lbRange.alloc.Alloc(from, nil)
				lbRange.alloc.Alloc(to, nil)
			}
		}

		pool.ranges = append(pool.ranges, lbRange)
	}

	ipam.pools[pool.GetName()] = pool

	// Unmark new pools so they get a conflict: False condition set, otherwise kubectl will report a blank field.
	ipam.unmarkPool(ctx, pool)

	return nil
}

func ipRangeFromBlock(block cilium_api_v2.CiliumLoadBalancerIPPoolIPBlock) (to, from netip.Addr, fromCidr bool, err error) {
	if string(block.Cidr) != "" {
		prefix, err := netip.ParsePrefix(string(block.Cidr))
		if err != nil {
			return netip.Addr{}, netip.Addr{}, false, fmt.Errorf("error parsing cidr '%s': %w", block.Cidr, err)
		}

		to, from = RangeFromPrefix(prefix)
		return to, from, true, nil
	}

	from, err = netip.ParseAddr(block.Start)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, false, fmt.Errorf("error parsing start ip '%s': %w", block.Start, err)
	}
	if block.Stop == "" {
		return from, from, false, nil
	}

	to, err = netip.ParseAddr(block.Stop)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, false, fmt.Errorf("error parsing stop ip '%s': %w", block.Stop, err)
	}

	return from, to, false, nil
}

func (ipam *LBIPAM) handlePoolModified(ctx context.Context, existingPool *LBPool, newK8sPool *cilium_api_v2.CiliumLoadBalancerIPPool) error {
	changedAllowFirstLastIPs := (existingPool.k8s.Spec.AllowFirstLastIPs == cilium_api_v2.AllowFirstLastIPNo) !=
		(newK8sPool.Spec.AllowFirstLastIPs == cilium_api_v2.AllowFirstLastIPNo)

	existingPool.k8s = newK8sPool

	type rng struct {
		from, to netip.Addr
		fromCidr bool
	}
	var newRanges []rng
	for _, newBlock := range newK8sPool.Spec.Blocks {
		from, to, fromCidr, err := ipRangeFromBlock(newBlock)
		if err != nil {
			return fmt.Errorf("error parsing ip block: %w", err)
		}

		newRanges = append(newRanges, rng{
			from:     from,
			to:       to,
			fromCidr: fromCidr,
		})
	}

	// Remove existing ranges that no longer exist
	for i := len(existingPool.ranges) - 1; i >= 0; i-- {
		extRange := existingPool.ranges[i]
		found := false
		fromCidr := false
		for _, newRange := range newRanges {
			if extRange.EqualCIDR(newRange.from, newRange.to) {
				found = true
				fromCidr = newRange.fromCidr
				break
			}
		}

		if found {
			// If the AllowFirstLastIPs state changed
			if fromCidr && changedAllowFirstLastIPs {
				if newK8sPool.Spec.AllowFirstLastIPs != cilium_api_v2.AllowFirstLastIPNo {
					// If we are allowing first and last IPs again, free them for allocation
					from, to := extRange.alloc.Range()

					if !(from.Compare(to) == 0 || from.Next().Compare(to) == 0) {
						extRange.alloc.Free(from)
						extRange.alloc.Free(to)
					}
				} else {
					// If we are disallowing first and last IPs, alloc the first and last IP if they are not already allocated.
					// Note: This will not revoke IPs that are already allocated to services.
					from, to := extRange.alloc.Range()

					// If the first and last IPs are the same or adjacent, we would reserve the entire range.
					// Only reserve first and last IPs for ranges /30 or /126 and larger.
					if !(from.Compare(to) == 0 || from.Next().Compare(to) == 0) {
						extRange.alloc.Alloc(from, nil)
						extRange.alloc.Alloc(to, nil)
					}
				}
			}

			continue
		}

		// Remove allocations from services if the ranges no longer exist
		existingPool.ranges = slices.Delete(existingPool.ranges, i, i+1)
		ipam.deleteRangeAllocations(extRange)
	}
	// no need to reconcile services now after ranges deletion, we are gonna reconcile
	// them later in revalidateAllServices after inserting the new ranges.

	// Add new ranges that were added
	for _, newRange := range newRanges {
		found := false
		for _, extRange := range existingPool.ranges {
			if extRange.EqualCIDR(newRange.from, newRange.to) {
				found = true
				break
			}
		}

		if found {
			continue
		}

		newLBRange, err := NewLBRange(newRange.from, newRange.to, newK8sPool)
		if err != nil {
			return fmt.Errorf("error while making new LB range for range '%s - %s': %w", newRange.from, newRange.to, err)
		}

		// If AllowFirstLastIPs is no, mark the first and last IP as allocated upon range creation.
		if newRange.fromCidr && newK8sPool.Spec.AllowFirstLastIPs == cilium_api_v2.AllowFirstLastIPNo {
			from, to := newLBRange.alloc.Range()

			// If the first and last IPs are the same or adjacent, we would reserve the entire range.
			// Only reserve first and last IPs for ranges /30 or /126 and larger.
			if !(from.Compare(to) == 0 || from.Next().Compare(to) == 0) {
				newLBRange.alloc.Alloc(from, nil)
				newLBRange.alloc.Alloc(to, nil)
			}
		}

		existingPool.ranges = append(existingPool.ranges, newLBRange)
	}

	for _, extRange := range existingPool.ranges {
		extRange.externallyDisabled = newK8sPool.Spec.Disabled
	}

	// This is a heavy operation, but pool modification should happen rarely
	err := ipam.revalidateAllServices(ctx)
	if err != nil {
		return fmt.Errorf("revalidateAllServices: %w", err)
	}

	return nil
}

func (ipam *LBIPAM) revalidateAllServices(ctx context.Context) error {
	serviceViews := make([]*ServiceView, 0, len(ipam.serviceStore.satisfied)+len(ipam.serviceStore.unsatisfied))

	// We want to first revalidate all satisfied services.
	// This helps in case when pool's CIDR was widened
	// and we have unsatisfied services that match this pool.
	// In this case, we want to revalidate satisfied services first,
	// so that we can reallocate the same IPs from the newly widened CIDR.
	for _, sv := range ipam.serviceStore.satisfied {
		serviceViews = append(serviceViews, sv)
	}

	for _, sv := range ipam.serviceStore.unsatisfied {
		serviceViews = append(serviceViews, sv)
	}

	statusModified := make(map[*ServiceView]bool, len(serviceViews))

	// Re-import any still-valid ingresses for all services before allocating fresh IPs.
	// This prevents services with removed IPs from stealing addresses that are still valid
	// for other services during pool shrink or similar range updates.
	for _, sv := range serviceViews {
		err := ipam.stripInvalidAllocations(sv)
		if err != nil {
			return fmt.Errorf("revalidate: stripInvalidAllocations: %w", err)
		}

		modified, err := ipam.stripOrImportIngresses(sv)
		if err != nil {
			return fmt.Errorf("revalidate: stripOrImportIngresses: %w", err)
		}
		if modified {
			statusModified[sv] = true
		}

		ipam.serviceStore.Upsert(sv)
	}

	for _, sv := range serviceViews {
		if !sv.isSatisfied() {
			modified, err := ipam.satisfyService(sv)
			if err != nil {
				return fmt.Errorf("revalidate: satisfyService: %w", err)
			}
			if modified {
				statusModified[sv] = true
			}
		}

		if statusModified[sv] {
			err := ipam.patchSvcStatus(ctx, sv)
			if err != nil {
				return fmt.Errorf("revalidate: patchSvcStatus: %w", err)
			}
		}

		ipam.serviceStore.Upsert(sv)
	}

	return nil
}

func (ipam *LBIPAM) updateAllPoolCounts(ctx context.Context) error {
	ipam.logger.DebugContext(ctx, "Updating pool counts")
	for _, pool := range ipam.pools {
		if ipam.updatePoolCounts(pool) {
			ipam.logger.DebugContext(ctx, fmt.Sprintf("Pool counts of '%s' changed, patching", pool.GetName()))
			err := ipam.patchPoolStatus(ctx, pool.k8s)
			if err != nil {
				return fmt.Errorf("patchPoolStatus: %w", err)
			}
		}
	}

	ipam.metrics.MatchingServices.Set(float64(len(ipam.serviceStore.satisfied) + len(ipam.serviceStore.unsatisfied)))
	ipam.metrics.UnsatisfiedServices.Set(float64(len(ipam.serviceStore.unsatisfied)))

	return nil
}

func (ipam *LBIPAM) updatePoolCounts(pool *LBPool) (modifiedPoolStatus bool) {
	type IPCounts struct {
		// Total is the total amount of allocatable IPs
		Total *big.Int
		// Available is the amount of IPs which can still be allocated
		Available *big.Int
		// Used is the amount of IPs that are currently allocated
		Used uint64
	}

	totalCounts := IPCounts{
		Total:     big.NewInt(0),
		Available: big.NewInt(0),
	}
	for _, lbRange := range pool.ranges {
		used, available := lbRange.alloc.Stats()

		totalCounts.Total = totalCounts.Total.Add(totalCounts.Total, available)

		// big.NewInt wants a int64, we have a uint64, converting like int64(used) could cause overflow
		// to negative numbers. So shift down by 1 bit so the sign bit is always 0, then convert to bigint.
		// Multiply by two once a bigint to reverse the bitshift and possibly add 1 if the last bit is 1.
		// This should give a loss-less conversion.
		half := int64(used >> 1)
		bigUsed := big.NewInt(0).Mul(big.NewInt(half), big.NewInt(2))
		if used%2 == 1 {
			bigUsed.Add(bigUsed, big.NewInt(1))
		}
		totalCounts.Total = totalCounts.Total.Add(totalCounts.Total, bigUsed)

		totalCounts.Available = totalCounts.Available.Add(totalCounts.Available, available)
		totalCounts.Used += used
	}

	totalChanged := ipam.setPoolCondition(pool.k8s, ciliumPoolIPsTotalCondition, meta_v1.ConditionUnknown, "noreason", totalCounts.Total.String())
	availableChanged := ipam.setPoolCondition(pool.k8s, ciliumPoolIPsAvailableCondition, meta_v1.ConditionUnknown, "noreason", totalCounts.Available.String())
	usedChanged := ipam.setPoolCondition(pool.k8s, ciliumPoolIPsUsedCondition, meta_v1.ConditionUnknown, "noreason", strconv.FormatUint(totalCounts.Used, 10))

	available, _ := new(big.Float).SetInt(totalCounts.Available).Float64()
	ipam.metrics.AvailableIPs.WithLabelValues(pool.GetName()).Set(available)
	ipam.metrics.UsedIPs.WithLabelValues(pool.GetName()).Set(float64(totalCounts.Used))

	return totalChanged || availableChanged || usedChanged
}

func (ipam *LBIPAM) setPoolCondition(
	pool *cilium_api_v2.CiliumLoadBalancerIPPool,
	condType string,
	status meta_v1.ConditionStatus,
	reason, message string,
) (statusModified bool) {
	// Don't trigger an update if the condition is already applied

	if cond := meta.FindStatusCondition(pool.Status.Conditions, condType); cond != nil &&
		cond.Status == status &&
		cond.ObservedGeneration == pool.Generation &&
		cond.Reason == reason &&
		cond.Message == message {
		return false
	}

	meta.SetStatusCondition(&pool.Status.Conditions, meta_v1.Condition{
		Type:               condType,
		Status:             status,
		ObservedGeneration: pool.Generation,
		LastTransitionTime: meta_v1.Now(),
		Reason:             reason,
		Message:            message,
	})
	return true
}

// deleteRangeAllocations removes allocations from services
func (ipam *LBIPAM) deleteRangeAllocations(delRange *LBRange) []*ServiceView {
	delAllocs := func(sv *ServiceView) bool {
		svModified := false
		for i := len(sv.AllocatedIPs) - 1; i >= 0; i-- {
			alloc := sv.AllocatedIPs[i]

			if alloc.Origin == delRange {
				sv.AllocatedIPs = slices.Delete(sv.AllocatedIPs, i, i+1)
				svModified = true
			}
		}

		return svModified
	}

	var svsModified []*ServiceView
	for _, sv := range ipam.serviceStore.unsatisfied {
		if modified := delAllocs(sv); modified {
			svsModified = append(svsModified, sv)
		}
	}
	for _, sv := range ipam.serviceStore.satisfied {
		if modified := delAllocs(sv); modified {
			svsModified = append(svsModified, sv)
		}
	}

	return svsModified
}

// reconcileServicesAfterRangeDeletion upsert services that have been modified after a call
// to deleteRangeAllocations, that is, all services from which an allocated IP has been removed
// after the ranges deletion.
// Before upserting the new status, reconcileServicesAfterRangeDeletion checks if the service
// needs to be satisfied with a new allocation and in that case it tries to do so before the
// upsertion. This is done in order to avoid multiple updates in a row.
func (ipam *LBIPAM) reconcileServicesAfterRangeDeletion(ctx context.Context, svcViews ...*ServiceView) error {
	var errs []error
	for _, sv := range svcViews {
		// Check for each ingress, if its IP has been allocated by us. If it isn't check if we can allocate that IP.
		// If we can't, strip the ingress from the service.
		svModifiedStatus, err := ipam.stripOrImportIngresses(sv)
		if err != nil {
			errs = append(errs, fmt.Errorf("stripOrImportIngresses: %w", err))
			continue
		}

		// Attempt to satisfy this service in particular now. We do this now instead of relying on
		// ipam.satisfyServices to avoid updating the service twice in quick succession.
		if !sv.isSatisfied() {
			statusModified, err := ipam.satisfyService(sv)
			if err != nil {
				errs = append(errs, fmt.Errorf("satisfyService: %w", err))
				continue
			}
			if statusModified {
				svModifiedStatus = true
			}
		}

		// If any of the steps above changed the service object, update the object.
		if svModifiedStatus {
			err := ipam.patchSvcStatus(ctx, sv)
			if err != nil {
				errs = append(errs, fmt.Errorf("patchSvcStatus: %w", err))
				continue
			}
		}

		ipam.serviceStore.Upsert(sv)
	}
	return errors.Join(errs...)
}

func (ipam *LBIPAM) handlePoolDeleted(ctx context.Context, k8sPool *cilium_api_v2.CiliumLoadBalancerIPPool) error {
	ipam.metrics.AvailableIPs.DeleteLabelValues(k8sPool.GetName())
	ipam.metrics.UsedIPs.DeleteLabelValues(k8sPool.GetName())

	pool := ipam.pools[k8sPool.GetName()]

	var svsModified []*ServiceView
	for _, poolRange := range pool.ranges {
		// Remove allocations from services if the ranges no longer exist
		svsModified = append(svsModified, ipam.deleteRangeAllocations(poolRange)...)
	}

	// delete the pool so that the subsequent reconciliation sees
	// an updated view of the available pools
	delete(ipam.pools, pool.GetName())

	// reconcile modified services
	return ipam.reconcileServicesAfterRangeDeletion(ctx, svsModified...)
}

func isPoolConflicting(pool *cilium_api_v2.CiliumLoadBalancerIPPool) bool {
	return meta.IsStatusConditionTrue(pool.Status.Conditions, ciliumPoolConflict)
}

// settleConflicts check if there exist any un-resolved conflicts between the ranges of IP pools and resolve them.
// secondly, it checks if any ranges that are marked as conflicting have been resolved.
// Any found conflicts are reflected in the IP Pool's status.
func (ipam *LBIPAM) settleConflicts(ctx context.Context) error {
	ipam.logger.DebugContext(ctx, "Settling pool conflicts")

	// Mark any pools that conflict as conflicting
	for _, poolOuter := range ipam.pools {
		if isPoolConflicting(poolOuter.k8s) {
			continue
		}

		if conflicting, rangeA, rangeB := areRangesInternallyConflicting(poolOuter.ranges); conflicting {
			err := ipam.markPoolConflicting(ctx, poolOuter, poolOuter, rangeA, rangeB)
			if err != nil {
				return fmt.Errorf("markPoolConflicting: %w", err)
			}
			continue
		}

		for _, poolInner := range ipam.pools {
			if poolOuter.GetName() == poolInner.GetName() {
				continue
			}

			if isPoolConflicting(poolInner.k8s) {
				continue
			}

			if conflicting, outerRange, innerRange := areRangesConflicting(poolOuter.ranges, poolInner.ranges); conflicting {
				// If two pools are conflicting, disable/mark the newest pool

				if poolOuter.k8s.CreationTimestamp.Before(&poolInner.k8s.CreationTimestamp) {
					err := ipam.markPoolConflicting(ctx, poolInner, poolOuter, innerRange, outerRange)
					if err != nil {
						return fmt.Errorf("markPoolConflicting: %w", err)
					}
					break
				}

				err := ipam.markPoolConflicting(ctx, poolOuter, poolInner, outerRange, innerRange)
				if err != nil {
					return fmt.Errorf("markPoolConflicting: %w", err)
				}
				break
			}
		}
	}

	// un-mark pools that no longer conflict
	for _, poolOuter := range ipam.pools {
		if !isPoolConflicting(poolOuter.k8s) {
			continue
		}

		// If the pool is still internally conflicting, don't un-mark
		if conflicting, _, _ := areRangesInternallyConflicting(poolOuter.ranges); conflicting {
			continue
		}

		poolConflict := false
		for _, poolInner := range ipam.pools {
			if poolOuter.GetName() == poolInner.GetName() {
				continue
			}

			if conflicting, _, _ := areRangesConflicting(poolOuter.ranges, poolInner.ranges); conflicting {
				poolConflict = true
				break
			}
		}

		// The outer pool, which is marked conflicting no longer conflicts
		if !poolConflict {
			err := ipam.unmarkPool(ctx, poolOuter)
			if err != nil {
				return fmt.Errorf("unmarkPool: %w", err)
			}
		}
	}

	// Count the number of conflicting pools and update the metric.
	var conflictingPools float64
	for _, pool := range ipam.pools {
		// When a pool is marked as conflicting, all of its lbRanges are
		// internally disabled. Therefore, checking a single lbRange
		// is sufficient to conclude that the pool is conflicting.
		if len(pool.ranges) > 0 && pool.ranges[0].internallyDisabled {
			conflictingPools++
		}
	}

	ipam.metrics.ConflictingPools.Set(conflictingPools)

	return nil
}

// markPoolConflicting marks the targetPool as "Conflicting" in its status and disables all of its ranges internally.
func (ipam *LBIPAM) markPoolConflicting(
	ctx context.Context,
	targetPool, collisionPool *LBPool,
	targetRange, collisionRange *LBRange,
) error {
	// If the target pool is already marked conflicting, than there is no need to re-add a condition
	if isPoolConflicting(targetPool.k8s) {
		return nil
	}

	ipam.logger.WarnContext(ctx,
		fmt.Sprintf("Pool '%s' conflicts since range '%s' overlaps range '%s' from IP Pool '%s'",
			targetPool.GetName(),
			ipNetStr(targetRange),
			ipNetStr(collisionRange),
			collisionPool.GetName()),
		logfields.PoolName1, targetPool.GetName(),
		logfields.PoolRange1, ipNetStr(targetRange),
		logfields.PoolName2, ipNetStr(collisionRange),
		logfields.PoolRange2, collisionPool.GetName(),
	)

	conflictMessage := fmt.Sprintf(
		"Pool conflicts since range '%s' overlaps range '%s' from IP Pool '%s'",
		ipNetStr(targetRange),
		ipNetStr(collisionRange),
		collisionPool.GetName(),
	)

	// Mark all ranges of the pool as internally disabled so we will not allocate from them.
	for _, poolRange := range targetPool.ranges {
		poolRange.internallyDisabled = true
	}

	if ipam.setPoolCondition(targetPool.k8s, ciliumPoolConflict, meta_v1.ConditionTrue, "cidr_overlap", conflictMessage) {
		err := ipam.patchPoolStatus(ctx, targetPool.k8s)
		if err != nil {
			return fmt.Errorf("patchPoolStatus: %w", err)
		}
	}

	return nil
}

// unmarkPool removes the "Conflicting" status from the pool and removes the internally disabled flag from its ranges
func (ipam *LBIPAM) unmarkPool(ctx context.Context, targetPool *LBPool) error {
	// Re-enabled all ranges
	for _, poolRange := range targetPool.ranges {
		poolRange.internallyDisabled = false
	}

	if ipam.setPoolCondition(targetPool.k8s, ciliumPoolConflict, meta_v1.ConditionFalse, "resolved", "") {
		err := ipam.patchPoolStatus(ctx, targetPool.k8s)
		if err != nil {
			return fmt.Errorf("patchPoolStatus: %w", err)
		}
	}

	return nil
}

func (ipam *LBIPAM) patchSvcStatus(ctx context.Context, sv *ServiceView) error {
	replaceSvcStatus := []k8s.JSONPatch{
		{
			OP:    "replace",
			Path:  "/status",
			Value: sv.Status,
		},
	}

	createStatusPatch, err := json.Marshal(replaceSvcStatus)
	if err != nil {
		return fmt.Errorf("json.Marshal(%v) failed: %w", replaceSvcStatus, err)
	}

	_, err = ipam.svcClient.Services(sv.Key.Namespace).Patch(ctx, sv.Key.Name,
		types.JSONPatchType, createStatusPatch, meta_v1.PatchOptions{
			FieldManager: ciliumFieldManager,
		}, "status")

	return err
}

func (ipam *LBIPAM) patchPoolStatus(ctx context.Context, pool *cilium_api_v2.CiliumLoadBalancerIPPool) error {
	replaceSvcStatus := []k8s.JSONPatch{
		{
			OP:    "replace",
			Path:  "/status",
			Value: pool.Status,
		},
	}

	createStatusPatch, err := json.Marshal(replaceSvcStatus)
	if err != nil {
		return fmt.Errorf("json.Marshal(%v) failed: %w", replaceSvcStatus, err)
	}

	_, err = ipam.poolClient.Patch(ctx, pool.Name,
		types.JSONPatchType, createStatusPatch, meta_v1.PatchOptions{
			FieldManager: ciliumFieldManager,
		}, "status")

	return err
}

func RangeFromPrefix(prefix netip.Prefix) (netip.Addr, netip.Addr) {
	prefix = prefix.Masked()
	return prefix.Addr(), netipx.PrefixLastIP(prefix)
}

// These counters are used to expose internal event counts during testing.
type testCounters struct {
	initializing  atomic.Int64
	initialized   atomic.Int64
	restarted     atomic.Int64
	poolEvents    atomic.Int64
	serviceEvents atomic.Int64
}
