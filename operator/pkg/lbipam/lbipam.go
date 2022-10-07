package lbipam

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"

	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/ipam/service/ipallocator"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	core_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	client_typed_v1 "k8s.io/client-go/kubernetes/typed/core/v1"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	cilium_client_v2alpha1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_labels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_meta_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/stream"
)

const (
	// The condition added to services to indicate if a request for IPs could be satisfied or not
	ciliumSvcRequestSatisfiedCondition = "io.cilium/lb-ipam-request-satisfied"

	// The annotation LB IPAM will look for when searching for requested IPs
	ciliumSvcLBIPSAnnotation = "io.cilium/lb-ipam-ips"

	// The string used in the FieldManager field on update options
	ciliumFieldManager = "cilium-operator-lb-ipam"

	serviceNamespaceLabel = "io.kubernetes.service.namespace"
	serviceNameLabel      = "io.kubernetes.service.name"
)

var Cell = cell.Module(
	"LB-IPAM",
	cell.Config(defaultLBIPAMConfig),
	// Provide LBIPAM so instances of it can be used while testing
	cell.Provide(registerLBIPAM),
	// Invoke an empty function which takes an LBIPAM to force its construction.
	cell.Invoke(func(*LBIPAM) {}),
)

var defaultLBIPAMConfig = LBIPAMConfig{
	EnableLBIPAM: false,
}

type LBIPAMConfig struct {
	EnableLBIPAM bool `mapstructure:"lb-ipam"`
}

func (cfg LBIPAMConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("lb-ipam", cfg.EnableLBIPAM, "Enables LB IPAM, which manages IPs for LoadBalancer services internally without cloud providers")
}

type LBIPAMInitDone chan struct{}

type LBIPAMParams struct {
	cell.In

	Logger       logrus.FieldLogger
	LC           hive.Lifecycle
	ClientSet    k8sClient.Clientset
	PoolResource resource.Resource[*cilium_api_v2alpha1.CiliumLoadBalancerIPPool]
	SvcResource  resource.Resource[*core_v1.Service]
	Config       LBIPAMConfig
	InitDone     LBIPAMInitDone `optional:"true"`
}

func registerLBIPAM(params LBIPAMParams) *LBIPAM {
	if !params.Config.EnableLBIPAM {
		return nil
	}

	var lbClasses []string
	if operatorOption.Config.BGPAnnounceLBIP {
		lbClasses = append(lbClasses, "io.cilium/bgp-control-plane")
	}

	lbIPAM := &LBIPAM{
		Logger:       params.Logger,
		PoolResource: params.PoolResource,
		SvcResource:  params.SvcResource,
		InitDone:     params.InitDone,
		PoolStore:    NewPoolStore(),
		RangesStore:  NewRangesStore(),
		ServiceStore: NewServiceStore(),
		LBClasses:    lbClasses,
		IPv4Enabled:  option.Config.IPv4Enabled(),
		IPv6Enabled:  option.Config.IPv6Enabled(),
	}

	// Make a new Ctx which we will use to manage the lifetime of LBIPAM.Run.
	ipamCtx, cancel := context.WithCancel(context.Background())
	ipamShutdown := make(chan struct{})

	params.LC.Append(hive.Hook{
		OnStart: func(ctx context.Context) error {
			params.Logger.Info("Starting LB IPAM")

			// Add the clients at start time since the client set doesn't have the clients available during
			// initialization just yet.
			lbIPAM.PoolClient = params.ClientSet.CiliumV2alpha1().CiliumLoadBalancerIPPools()
			lbIPAM.SvcClient = params.ClientSet.CoreV1()

			// Start go routine, we can't block in OnStart
			go func() {
				lbIPAM.Run(ipamCtx)
				close(ipamShutdown)
			}()

			return nil
		},
		OnStop: func(ctx context.Context) error {
			// Close the ipamCtx
			cancel()

			// Wait for LB IPAM shutdown to be complete or the Stop ctx to expire.
			select {
			case <-ipamShutdown:
			case <-ctx.Done():
			}

			return nil
		},
	})

	return lbIPAM
}

// LBIPAM is the loadbalancer IP address manager, watcher/controller which allocates and assigns IP addresses
// to LoadBalancer services from the configured set of LoadBalancerIPPools in the cluster.
type LBIPAM struct {
	Logger logrus.FieldLogger

	PoolClient cilium_client_v2alpha1.CiliumLoadBalancerIPPoolInterface
	SvcClient  client_typed_v1.ServicesGetter

	PoolResource resource.Resource[*cilium_api_v2alpha1.CiliumLoadBalancerIPPool]
	PoolSynced   bool

	SvcResource resource.Resource[*core_v1.Service]
	SvcSynced   bool

	PoolStore    PoolStore
	RangesStore  RangesStore
	ServiceStore ServiceStore

	LBClasses   []string
	IPv4Enabled bool
	IPv6Enabled bool

	// Only used during testing.
	InitDone LBIPAMInitDone
}

func (ipam *LBIPAM) Run(ctx context.Context) {
	//
	errChan := make(chan error, 2)

	poolChan := stream.ToChannel[resource.Event[*cilium_api_v2alpha1.CiliumLoadBalancerIPPool]](ctx, errChan, ipam.PoolResource)
	svcChan := stream.ToChannel[resource.Event[*core_v1.Service]](ctx, errChan, ipam.SvcResource)

	ipam.init(ctx, poolChan, svcChan)
	if ipam.InitDone != nil {
		close(ipam.InitDone)
	}

	// When the ctx expires, both streams will close, keep processing until both channels are closed to avoid blocking
	// the resources in case they are re-used after we shutdown.
	for poolChan != nil && svcChan != nil {
		select {
		case event, ok := <-poolChan:
			if !ok {
				poolChan = nil
				continue
			}

			event.Handle(
				nil,
				ipam.poolOnUpsert(ctx),
				ipam.poolOnDelete(ctx),
			)
		case event, ok := <-svcChan:
			if !ok {
				svcChan = nil
				continue
			}

			event.Handle(
				nil,
				ipam.svcOnUpsert(ctx),
				ipam.svcOnDelete(ctx),
			)
		case err := <-errChan:
			ipam.Logger.WithError(err).Error("Resource error")
		}
	}
}

func (ipam *LBIPAM) init(
	ctx context.Context,
	poolChan <-chan resource.Event[*cilium_api_v2alpha1.CiliumLoadBalancerIPPool],
	svcChan <-chan resource.Event[*core_v1.Service],
) {
	// First sync all pools
	poolSync := false
	for !poolSync {
		select {
		case event := <-poolChan:
			event.Handle(
				func(s resource.Store[*cilium_api_v2alpha1.CiliumLoadBalancerIPPool]) error {
					ipam.settleConflicts(ctx)
					poolSync = true
					return nil
				},
				func(k resource.Key, clbi *cilium_api_v2alpha1.CiliumLoadBalancerIPPool) error {
					ipam.handleNewPool(ctx, clbi)
					return nil
				},
				func(k resource.Key, clbi *cilium_api_v2alpha1.CiliumLoadBalancerIPPool) error {
					ipam.Logger.Error("Got a Pool deleted event while syncing")
					return nil
				},
			)
		}
	}

	// Then sync all services
	svcSync := false
	for !svcSync {
		select {
		case event := <-svcChan:
			event.Handle(
				func(s resource.Store[*core_v1.Service]) error {
					ipam.satisfyServices(ctx)
					ipam.updateAllPoolCounts(ctx)
					svcSync = true
					return nil
				},
				func(k resource.Key, svc *core_v1.Service) error {
					ipam.handleUpsertService(ctx, svc)
					return nil
				},
				func(k resource.Key, svc *core_v1.Service) error {
					ipam.Logger.Error("Got a Service deleted event while syncing")
					return nil
				},
			)
		}
	}
}

func (ipam *LBIPAM) poolOnUpsert(ctx context.Context) func(k resource.Key, pool *cilium_api_v2alpha1.CiliumLoadBalancerIPPool) error {
	return func(k resource.Key, pool *cilium_api_v2alpha1.CiliumLoadBalancerIPPool) error {
		// Deep copy so we get a version we are allowed to update
		pool = pool.DeepCopy()

		if _, exists := ipam.PoolStore.GetByUID(pool.GetUID()); exists {
			ipam.Logger.Debugf("Updating pool '%s'", pool.GetName())
			ipam.handlePoolModified(ctx, pool)
		} else {
			ipam.Logger.Debugf("Adding pool '%s'", pool.GetName())
			ipam.handleNewPool(ctx, pool)
		}

		ipam.settleConflicts(ctx)
		ipam.satisfyServices(ctx)
		ipam.updateAllPoolCounts(ctx)

		return nil
	}
}

func (ipam *LBIPAM) poolOnDelete(ctx context.Context) func(k resource.Key, pool *cilium_api_v2alpha1.CiliumLoadBalancerIPPool) error {
	return func(k resource.Key, pool *cilium_api_v2alpha1.CiliumLoadBalancerIPPool) error {
		ipam.handlePoolDeleted(ctx, pool)
		ipam.settleConflicts(ctx)
		ipam.satisfyServices(ctx)
		ipam.updateAllPoolCounts(ctx)
		return nil
	}
}

func (ipam *LBIPAM) svcOnUpsert(ctx context.Context) func(k resource.Key, svc *core_v1.Service) error {
	return func(k resource.Key, svc *core_v1.Service) error {
		// Deep copy so we get a version we are allowed to update
		svc = svc.DeepCopy()

		ipam.Logger.Debugf("Added/updated service '%s/%s'", svc.GetNamespace(), svc.GetName())

		ipam.handleUpsertService(ctx, svc)

		ipam.satisfyServices(ctx)
		ipam.updateAllPoolCounts(ctx)
		return nil
	}
}

func (ipam *LBIPAM) svcOnDelete(ctx context.Context) func(k resource.Key, svc *core_v1.Service) error {
	return func(k resource.Key, svc *core_v1.Service) error {
		// Deep copy so we get a version we are allowed to update
		svc = svc.DeepCopy()

		ipam.Logger.Debugf("Deleted service '%s/%s'", svc.GetNamespace(), svc.GetName())

		ipam.handleDeletedService(ctx, svc)

		// Removing a service might free up IPs which unsatisfied services are waiting for.
		ipam.satisfyServices(ctx)
		ipam.updateAllPoolCounts(ctx)

		return nil
	}
}

// handleUpsertService updates the service view in the service store, it removes any allocation and ingress that
// do not belong on the service and will move the service to the satisfied or unsatisfied service view store depending
// on if the service requests are satisfied or not.
func (ipam *LBIPAM) handleUpsertService(ctx context.Context, svc *core_v1.Service) {
	if svc.GetUID() == "" {
		// The code keys everything on UIDs, without one we can't function.
		// The APIServer should always assign one, but one tends to forget in tests
		ipam.Logger.Error("Service has no UID!")
		return
	}

	sv, found, _ := ipam.ServiceStore.GetService(svc.GetUID())
	if !found {
		sv = &ServiceView{
			UID: svc.GetUID(),
			Key: resource.NewKey(svc),
		}
	}

	// Ignore services which are not meant for us
	if !ipam.isResponsibleForSVC(svc) {
		if !found {
			return
		}

		// Release allocations
		for _, alloc := range sv.AllocatedIPs {
			alloc.Origin.allocRange.Release(alloc.IP)
		}
		ipam.ServiceStore.Delete(sv.UID)

		// Remove all ingress IPs
		sv.Status.LoadBalancer.Ingress = nil
		for i := len(sv.Status.Conditions) - 1; i >= 0; i-- {
			if sv.Status.Conditions[i].Type == ciliumSvcRequestSatisfiedCondition {
				sv.Status.Conditions = slices.Delete(sv.Status.Conditions, i, i+1)
			}
		}

		err := ipam.patchSvcStatus(ctx, sv)
		if err != nil {
			ipam.Logger.WithError(err).Error("Error while patching status (upsert clear)")
		}

		return
	}

	// We are responsible for this service.

	// Update the service view
	sv.Generation = svc.Generation
	sv.Labels = svcLabels(svc)
	sv.RequestedFamilies.IPv4, sv.RequestedFamilies.IPv6 = ipam.serviceIPFamilyRequest(svc)
	sv.RequestedIPs = getSVCRequestedIPs(svc)
	sv.Status = svc.Status.DeepCopy()

	// Remove any allocation that are no longer valid due to a change in the service spec
	ipam.stripInvalidAllocations(sv)

	// Check for each ingress, if its IP has been allocated by us. If it isn't check if we can allocate that IP.
	// If we can't, strip the ingress from the service.
	svModifiedStatus := ipam.stripOrImportIngresses(sv)

	// Attempt to satisfy this service in particular now. We do this now instread of relying on
	// ipam.satisfyServices to avoid updating the service twice in quick succession.
	if !sv.isSatisfied() {
		if ipam.satisfyService(sv) {
			svModifiedStatus = true
		}
	}

	// If any of the steps above changed the service object, update the object.
	if svModifiedStatus {
		err := ipam.patchSvcStatus(ctx, sv)
		if err != nil {
			ipam.Logger.WithError(err).Error("Error while patching status (upsert)")
		}
	}

	ipam.ServiceStore.Upsert(sv)
}

func (ipam *LBIPAM) stripInvalidAllocations(sv *ServiceView) {
	// Remove bad allocations which are no longer valid
	for allocIdx := len(sv.AllocatedIPs) - 1; allocIdx >= 0; allocIdx-- {
		alloc := sv.AllocatedIPs[allocIdx]

		releaseAllocIP := func() {
			ipam.Logger.Debugf("removing allocation '%s' from '%s'", alloc.IP.String(), sv.Key.String())
			err := alloc.Origin.allocRange.Release(alloc.IP)
			if err != nil {
				ipam.Logger.WithError(err).Errorf("Error while releasing '%s' from '%s'", alloc.IP, alloc.Origin.String())
			}

			sv.AllocatedIPs = slices.Delete(sv.AllocatedIPs, allocIdx, allocIdx+1)
		}

		// If origin pool no longer exists, remove allocation
		pool, found := ipam.PoolStore.GetByUID(alloc.Origin.originPool)
		if !found {
			releaseAllocIP()
			continue
		}

		// If service no longer matches the pool selector, remove allocation
		if pool.Spec.ServiceSelector != nil {
			selector, err := slim_meta_v1.LabelSelectorAsSelector(pool.Spec.ServiceSelector)
			if err != nil {
				ipam.Logger.WithError(err).Errorf("Making selector from pool '%s' label selector", pool.Name)
				continue
			}

			if !selector.Matches(sv.Labels) {
				releaseAllocIP()
				continue
			}
		}

		// If the service is requesting specific IPs
		if len(sv.RequestedIPs) > 0 {
			found := false
			for _, reqIP := range sv.RequestedIPs {
				if reqIP.Equal(alloc.IP) {
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

			if alloc.IP.To4() == nil {
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
}

func (ipam *LBIPAM) stripOrImportIngresses(sv *ServiceView) (statusModified bool) {
	var newIngresses []core_v1.LoadBalancerIngress

	// Only keep valid ingresses.
	for _, ingress := range sv.Status.LoadBalancer.Ingress {
		if ingress.IP == "" {
			continue
		}

		ip := net.ParseIP(ingress.IP)
		if ip == nil {
			continue
		}

		// Remove any ingress which is no longer allocated
		var viewIP *ServiceViewIP
		for i, vip := range sv.AllocatedIPs {
			if vip.IP.Equal(ip) {
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
					if reqIP.Equal(ip) {
						found = true
						break
					}
				}
				if !found {
					// Don't keep ingress
					continue
				}
			}

			if ip.To4() == nil {
				if !sv.RequestedFamilies.IPv6 {
					continue
				}
			} else {
				if !sv.RequestedFamilies.IPv4 {
					continue
				}
			}

			lbRange, _ := ipam.findRangeOfIP(sv, ip)
			if lbRange == nil {
				continue
			}

			err := lbRange.allocRange.Allocate(ip)
			if err != nil {
				if errors.Is(err, ipallocator.ErrAllocated) {
					ipam.Logger.Warningf(
						"Ingress IP '%s' is assigned to multiple services, removing from svc '%s'",
						ingress.IP,
						sv.UID,
					)

					continue
				}

				ipam.Logger.WithError(err).Errorf("Error while attempting to allocate IP '%s'", ingress.IP)
				continue
			}

			sv.AllocatedIPs = append(sv.AllocatedIPs, ServiceViewIP{
				IP:     ip,
				Origin: lbRange,
			})
		}

		newIngresses = append(newIngresses, ingress)
	}

	// Deduplicate ingress IPs (condition can be created externally before we adopted the service)
	newIngresses = slices.CompactFunc(newIngresses, func(a, b core_v1.LoadBalancerIngress) bool {
		return a.IP == b.IP
	})

	// Check if we have removed any ingresses
	if len(sv.Status.LoadBalancer.Ingress) != len(newIngresses) {
		statusModified = true
	}

	sv.Status.LoadBalancer.Ingress = newIngresses

	return statusModified
}

func getSVCRequestedIPs(svc *core_v1.Service) []net.IP {
	var ips []net.IP
	if svc.Spec.LoadBalancerIP != "" {
		ip := net.ParseIP(svc.Spec.LoadBalancerIP)
		if ip != nil {
			ips = append(ips, ip)
		}
	}

	if annotation := svc.Annotations[ciliumSvcLBIPSAnnotation]; annotation != "" {
		for _, ipStr := range strings.Split(annotation, ",") {
			ip := net.ParseIP(strings.TrimSpace(ipStr))
			if ip != nil {
				ips = append(ips, ip)
			}
		}
	}

	return slices.CompactFunc(ips, func(a, b net.IP) bool {
		return a.Equal(b)
	})
}

func (ipam *LBIPAM) handleDeletedService(ctx context.Context, svc *core_v1.Service) {
	sv, found, _ := ipam.ServiceStore.GetService(svc.GetUID())
	if !found {
		return
	}

	for _, alloc := range sv.AllocatedIPs {
		alloc.Origin.allocRange.Release(alloc.IP)
	}

	ipam.ServiceStore.Delete(svc.GetUID())
}

// satisfyServices attempts to satisfy all unsatisfied services by allocating and assigning IP addresses
func (ipam *LBIPAM) satisfyServices(ctx context.Context) {
	for _, sv := range ipam.ServiceStore.unsatisfied {
		statusModified := ipam.satisfyService(sv)

		// If the services status has been modified, update the service.
		if statusModified {
			err := ipam.patchSvcStatus(ctx, sv)
			if err != nil {
				ipam.Logger.WithError(err).Error("Error while updating status (satisfy)")
				continue
			}
		}

		ipam.ServiceStore.Upsert(sv)
	}
}

func (ipam *LBIPAM) satisfyService(sv *ServiceView) (statusModified bool) {
	if len(sv.RequestedIPs) > 0 {
		// The service requests specific IPs
		for _, reqIP := range sv.RequestedIPs {
			// if we are able to find the requested IP in the list of allocated IPs
			if slices.IndexFunc(sv.AllocatedIPs, func(sv ServiceViewIP) bool {
				return reqIP.Equal(sv.IP)
			}) != -1 {
				continue
			}

			lbRange, foundPool := ipam.findRangeOfIP(sv, reqIP)
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

			if lbRange.allocRange.Has(reqIP) {
				msg := fmt.Sprintf("IP '%s' has already been allocated to another service", reqIP)
				if ipam.setSVCSatisfiedCondition(sv, false, "already_allocated", msg) {
					statusModified = true
				}
				continue
			}

			ipam.Logger.Debugf("Allocate '%s' for '%s'", reqIP.String(), sv.Key.String())
			err := lbRange.allocRange.Allocate(reqIP)
			if err != nil {
				ipam.Logger.WithError(err).Error("Unable to allocate IP")
				continue
			}

			sv.AllocatedIPs = append(sv.AllocatedIPs, ServiceViewIP{
				IP:     reqIP,
				Origin: lbRange,
			})
		}

	} else {

		hasIPv4 := false
		hasIPv6 := false
		for _, allocated := range sv.AllocatedIPs {
			if allocated.IP.To4() == nil {
				hasIPv6 = true
			} else {
				hasIPv4 = true
			}
		}

		// Missing an IPv4 address, lets attempt to allocate an address
		if sv.RequestedFamilies.IPv4 && !hasIPv4 {
			newIP, lbRange, full := ipam.allocateIPAddress(sv, IPv4Family)
			if newIP != nil {
				sv.AllocatedIPs = append(sv.AllocatedIPs, ServiceViewIP{
					IP:     *newIP,
					Origin: lbRange,
				})
			} else {
				reason := "no_pool"
				message := "There are no enabled CiliumLoadBalancerIPPools that match this service"
				if full {
					reason = "out_of_ips"
					message = "All enabled CiliumLoadBalancerIPPools that match this service ran out of allocatable IPs"
				}

				if ipam.setSVCSatisfiedCondition(sv, false, reason, message) {
					statusModified = true
				}
			}
		}

		// Missing an IPv6 address, lets attempt to allocate an address
		if sv.RequestedFamilies.IPv6 && !hasIPv6 {
			newIP, lbRange, full := ipam.allocateIPAddress(sv, IPv6Family)
			if newIP != nil {
				sv.AllocatedIPs = append(sv.AllocatedIPs, ServiceViewIP{
					IP:     *newIP,
					Origin: lbRange,
				})
			} else {
				reason := "no_pool"
				message := "There are no enabled CiliumLoadBalancerIPPools that match this service"
				if full {
					reason = "out_of_ips"
					message = "All enabled CiliumLoadBalancerIPPools that match this service ran out of allocatable IPs"
				}

				if ipam.setSVCSatisfiedCondition(sv, false, reason, message) {
					statusModified = true
				}
			}
		}
	}

	// Sync allocated IPs back to the service
	for _, alloc := range sv.AllocatedIPs {
		// If the allocated IP isn't found in the assigned list, assign it
		if slices.IndexFunc(sv.Status.LoadBalancer.Ingress, func(in core_v1.LoadBalancerIngress) bool {
			return net.ParseIP(in.IP).Equal(alloc.IP)
		}) == -1 {
			sv.Status.LoadBalancer.Ingress = append(sv.Status.LoadBalancer.Ingress, core_v1.LoadBalancerIngress{
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

	ipam.ServiceStore.Upsert(sv)

	return statusModified
}

func (ipam *LBIPAM) setSVCSatisfiedCondition(
	sv *ServiceView,
	satisfied bool,
	reason, message string,
) (statusModified bool) {
	status := meta_v1.ConditionFalse
	if satisfied {
		status = meta_v1.ConditionTrue
	}

	for _, cond := range sv.Status.Conditions {
		if cond.Type == ciliumSvcRequestSatisfiedCondition &&
			cond.Status == status &&
			cond.ObservedGeneration == sv.Generation &&
			cond.Reason == reason &&
			cond.Message == message {
			return false
		}
	}

	sv.Status.Conditions = append(sv.Status.Conditions, meta_v1.Condition{
		Type:               ciliumSvcRequestSatisfiedCondition,
		Status:             status,
		ObservedGeneration: sv.Generation,
		LastTransitionTime: meta_v1.Now(),
		Reason:             reason,
		Message:            message,
	})
	return true
}

func (ipam *LBIPAM) findRangeOfIP(sv *ServiceView, ip net.IP) (lbRange *LBRange, foundPool bool) {
	for _, r := range ipam.RangesStore.ranges {
		if r.Disabled() {
			continue
		}

		cidr := r.allocRange.CIDR()
		if !cidr.Contains(ip) {
			continue
		}

		pool, found := ipam.PoolStore.GetByUID(r.originPool)
		if !found {
			continue
		}

		foundPool = true

		if pool.Spec.ServiceSelector != nil {
			selector, err := slim_meta_v1.LabelSelectorAsSelector(pool.Spec.ServiceSelector)
			if err != nil {
				ipam.Logger.WithError(err).Errorf("Making selector from pool '%s' label selector", pool.Name)
				continue
			}

			if !selector.Matches(sv.Labels) {
				continue
			}
		}

		return r, false
	}

	return nil, false
}

// isResponsibleForSVC checks if LB IPAM should allocate and assign IPs or some other controller
func (ipam *LBIPAM) isResponsibleForSVC(svc *core_v1.Service) bool {
	// Ignore non-lb services
	if svc.Spec.Type != core_v1.ServiceTypeLoadBalancer {
		return false
	}

	if svc.Spec.LoadBalancerClass == nil {
		// TODO if a cloud LB exists, it should assign, else we can assign
		// if ipam.CloudLBExists() { return }
	} else if !slices.Contains(ipam.LBClasses, *svc.Spec.LoadBalancerClass) {
		return false
	}

	return true
}

type AddressFamily string

const (
	IPv4Family AddressFamily = "IPv4"
	IPv6Family AddressFamily = "IPv6"
)

func (ipam *LBIPAM) allocateIPAddress(
	sv *ServiceView,
	family AddressFamily,
) (
	newIP *net.IP,
	chosenRange *LBRange,
	full bool,
) {
	for _, lbRange := range ipam.RangesStore.ranges {
		// If the range is disabled we can't allocate new IPs from it.
		if lbRange.Disabled() {
			continue
		}

		// Skip this range if it doesn't match the requested address family
		if lbRange.allocRange.CIDR().IP.To4() == nil {
			if family == IPv4Family {
				continue
			}
		} else {
			if family == IPv6Family {
				continue
			}
		}

		pool, found := ipam.PoolStore.GetByUID(lbRange.originPool)
		if !found {
			ipam.Logger.Warnf("Bad state detected, store contains lbRange for pool '%s' but missing the pool", lbRange.originPool)
			continue
		}

		// If there is no selector, all services match
		if pool.Spec.ServiceSelector != nil {
			selector, err := slim_meta_v1.LabelSelectorAsSelector(pool.Spec.ServiceSelector)
			if err != nil {
				ipam.Logger.WithError(err).Error("LB IP Pool service selector to selector conversion")
				continue
			}

			if !selector.Matches(sv.Labels) {
				continue
			}
		}

		// Attempt to allocate the next IP from this range.
		newIp, err := lbRange.allocRange.AllocateNext()
		if err != nil {
			// If the range is full, mark it.
			if errors.Is(err, ipallocator.ErrFull) {
				full = true
				continue
			}

			ipam.Logger.WithError(err).Error("Allocate next IP from lb range")
			continue
		}

		return &newIp, lbRange, false
	}

	return nil, nil, full
}

// serviceIPFamilyRequest checks which families of IP addresses are requested
func (ipam *LBIPAM) serviceIPFamilyRequest(svc *core_v1.Service) (IPv4Requested, IPv6Requested bool) {
	if svc.Spec.IPFamilyPolicy != nil {
		switch *svc.Spec.IPFamilyPolicy {
		case core_v1.IPFamilyPolicySingleStack:
			if len(svc.Spec.IPFamilies) > 0 {
				if svc.Spec.IPFamilies[0] == core_v1.IPFamily(IPv4Family) {
					IPv4Requested = true
				} else {
					IPv6Requested = true
				}
			} else {
				if ipam.IPv4Enabled {
					IPv4Requested = true
				} else if ipam.IPv6Enabled {
					IPv6Requested = true
				}
			}

		case core_v1.IPFamilyPolicyPreferDualStack:
			if len(svc.Spec.IPFamilies) > 0 {
				for _, family := range svc.Spec.IPFamilies {
					if family == core_v1.IPFamily(IPv4Family) {
						IPv4Requested = ipam.IPv4Enabled
					}
					if family == core_v1.IPFamily(IPv6Family) {
						IPv6Requested = ipam.IPv6Enabled
					}
				}
			} else {
				// If no IPFamilies are specified

				IPv4Requested = ipam.IPv4Enabled
				IPv6Requested = ipam.IPv6Enabled
			}

		case core_v1.IPFamilyPolicyRequireDualStack:
			IPv4Requested = ipam.IPv4Enabled
			IPv6Requested = ipam.IPv6Enabled
		}
	} else {
		if len(svc.Spec.IPFamilies) > 0 {
			if svc.Spec.IPFamilies[0] == core_v1.IPFamily(IPv4Family) {
				IPv4Requested = true
			} else {
				IPv6Requested = true
			}
		} else {
			if ipam.IPv4Enabled {
				IPv4Requested = true
			} else if ipam.IPv6Enabled {
				IPv6Requested = true
			}
		}
	}

	return IPv4Requested, IPv6Requested
}

// Handle the addition of a new IPPool
func (ipam *LBIPAM) handleNewPool(ctx context.Context, pool *cilium_api_v2alpha1.CiliumLoadBalancerIPPool) {
	// Sanity check that we do not yet know about this pool.
	if _, found := ipam.PoolStore.GetByUID(pool.GetUID()); found {
		ipam.Logger.Warnf("LB IPPool with uid '%s' has been created, but a LB IP Pool with the same uid already exists", pool.GetUID())
		return
	}

	ipam.PoolStore.Upsert(pool)
	for _, cidrBlock := range pool.Spec.Cidrs {
		_, cidr, err := net.ParseCIDR(string(cidrBlock.Cidr))
		if err != nil {
			ipam.Logger.WithError(err).Errorf("Error parsing cidr '%s'", cidrBlock.Cidr)
			continue
		}

		lbRange, err := NewLBRange(cidr, pool)
		if err != nil {
			ipam.Logger.WithError(err).Errorf("Error making LB Range for '%s'", cidrBlock.Cidr)
			continue
		}

		ipam.RangesStore.Add(lbRange)
	}
}

func (ipam *LBIPAM) handlePoolModified(ctx context.Context, pool *cilium_api_v2alpha1.CiliumLoadBalancerIPPool) {
	ipam.PoolStore.Upsert(pool)

	var newCIDRs []net.IPNet
	for _, newBlock := range pool.Spec.Cidrs {
		_, cidr, err := net.ParseCIDR(string(newBlock.Cidr))
		if err != nil {
			ipam.Logger.WithError(err).Errorf("Error parsing cidr '%s'", newBlock.Cidr)
			continue
		}
		newCIDRs = append(newCIDRs, *cidr)
	}

	existingRanges, _ := ipam.RangesStore.GetRangesForPool(pool.GetUID())

	// Remove existing ranges that no longer exist
	for _, extRange := range existingRanges {
		extCIDR := extRange.allocRange.CIDR()
		found := false
		for _, newCIDR := range newCIDRs {
			if newCIDR.IP.Equal(extCIDR.IP) && bytes.Equal(newCIDR.Mask, extCIDR.Mask) {
				found = true
				break
			}
		}

		if found {
			continue
		}

		// Remove allocations from services if the ranges no longer exist
		ipam.RangesStore.Delete(extRange)
		ipam.deleteRangeAllocations(ctx, extRange)
	}

	// Add new ranges that were added
	for _, newCIDR := range newCIDRs {
		found := false
		for _, extRange := range existingRanges {
			extCIDR := extRange.allocRange.CIDR()
			if newCIDR.IP.Equal(extCIDR.IP) && bytes.Equal(newCIDR.Mask, extCIDR.Mask) {
				found = true
				break
			}
		}

		if found {
			continue
		}

		newRange, err := NewLBRange(&newCIDR, pool)
		if err != nil {
			ipam.Logger.WithError(err).Errorf("Error while making new LB range for CIDR '%s'", newCIDR.String())
		}

		ipam.RangesStore.Add(newRange)
	}

	existingRanges, _ = ipam.RangesStore.GetRangesForPool(pool.GetUID())
	for _, extRange := range existingRanges {
		extRange.externallyDisabled = pool.Spec.Disabled
	}

	// This is a heavy operation, but pool modification should happen rarely
	ipam.revalidateAllServices(ctx)
}

func (ipam *LBIPAM) revalidateAllServices(ctx context.Context) {
	revalidate := func(sv *ServiceView) {
		ipam.stripInvalidAllocations(sv)

		// Check for each ingress, if its IP has been allocated by us. If it isn't check if we can allocate that IP.
		// If we can't, strip the ingress from the service.
		svModifiedStatus := ipam.stripOrImportIngresses(sv)

		// Attempt to satisfy this service in particular now. We do this now instread of relying on
		// ipam.satisfyServices to avoid updating the service twice in quick succession.
		if !sv.isSatisfied() {
			if ipam.satisfyService(sv) {
				svModifiedStatus = true
			}
		}

		// If any of the steps above changed the service object, update the object.
		if svModifiedStatus {
			err := ipam.patchSvcStatus(ctx, sv)
			if err != nil {
				ipam.Logger.WithError(err).Error("Error while patching status (del range)")
			}
		}

		ipam.ServiceStore.Upsert(sv)
	}
	for _, sv := range ipam.ServiceStore.unsatisfied {
		revalidate(sv)
	}

	for _, sv := range ipam.ServiceStore.satisfied {
		revalidate(sv)
	}
}

func (ipam *LBIPAM) updateAllPoolCounts(ctx context.Context) {
	ipam.Logger.Debug("Updating pool counts")
	for _, pool := range ipam.PoolStore.pools {
		if ipam.updatePoolCounts(pool) {
			ipam.Logger.Debugf("Pool counts of '%s' changed, patching", pool.Name)
			err := ipam.patchPoolStatus(ctx, pool)
			if err != nil {
				ipam.Logger.WithError(err).Error("Error while patching pool counts")
				continue
			}
		}
	}
}

func (ipam *LBIPAM) updatePoolCounts(pool *cilium_api_v2alpha1.CiliumLoadBalancerIPPool) (modifiedPoolStatus bool) {
	ranges, _ := ipam.RangesStore.GetRangesForPool(pool.GetUID())
	curCidrs := make(map[string]bool)
	for _, lbRange := range ranges {
		curCidrs[ipNetStr(lbRange.allocRange.CIDR())] = true
	}

	if pool.Status.CIDRCounts == nil {
		pool.Status.CIDRCounts = make(map[string]cilium_api_v2alpha1.CiliumLoadBalancerIPCounts)
	}

	for cidr := range pool.Status.CIDRCounts {
		if !curCidrs[cidr] {
			delete(pool.Status.CIDRCounts, cidr)
			modifiedPoolStatus = true
		}
	}

	var totalCounts cilium_api_v2alpha1.CiliumLoadBalancerIPCounts
	for _, lbRange := range ranges {
		cidr := ipNetStr(lbRange.allocRange.CIDR())
		cidrCount := pool.Status.CIDRCounts[cidr]

		free := lbRange.allocRange.Free()
		used := lbRange.allocRange.Used()
		newCidrCount := cilium_api_v2alpha1.CiliumLoadBalancerIPCounts{
			Total:     free + used,
			Available: free,
			Used:      used,
		}

		if cidrCount != newCidrCount {
			cidrCount = newCidrCount
			modifiedPoolStatus = true
			pool.Status.CIDRCounts[cidr] = cidrCount
		}

		totalCounts.Total += cidrCount.Total
		totalCounts.Available += cidrCount.Available
		totalCounts.Used += cidrCount.Used
	}

	if pool.Status.TotalCounts != totalCounts {
		modifiedPoolStatus = true
		pool.Status.TotalCounts = totalCounts
	}

	return modifiedPoolStatus
}

// deleteRangeAllocations removes allocations from
func (ipam *LBIPAM) deleteRangeAllocations(ctx context.Context, delRange *LBRange) {
	delAllocs := func(sv *ServiceView) {
		svModified := false
		for i := len(sv.AllocatedIPs) - 1; i >= 0; i-- {
			alloc := sv.AllocatedIPs[i]

			if alloc.Origin == delRange {
				sv.AllocatedIPs = slices.Delete(sv.AllocatedIPs, i, i+1)
				svModified = true
			}
		}

		if !svModified {
			return
		}

		// Check for each ingress, if its IP has been allocated by us. If it isn't check if we can allocate that IP.
		// If we can't, strip the ingress from the service.
		svModifiedStatus := ipam.stripOrImportIngresses(sv)

		// Attempt to satisfy this service in particular now. We do this now instread of relying on
		// ipam.satisfyServices to avoid updating the service twice in quick succession.
		if !sv.isSatisfied() {
			if ipam.satisfyService(sv) {
				svModifiedStatus = true
			}
		}

		// If any of the steps above changed the service object, update the object.
		if svModifiedStatus {
			err := ipam.patchSvcStatus(ctx, sv)
			if err != nil {
				ipam.Logger.WithError(err).Error("Error while patching status (del range)")
			}
		}

		ipam.ServiceStore.Upsert(sv)
	}
	for _, sv := range ipam.ServiceStore.unsatisfied {
		delAllocs(sv)
	}
	for _, sv := range ipam.ServiceStore.satisfied {
		delAllocs(sv)
	}
}

func (ipam *LBIPAM) handlePoolDeleted(ctx context.Context, pool *cilium_api_v2alpha1.CiliumLoadBalancerIPPool) {
	ipam.PoolStore.Delete(pool)

	poolRanges, _ := ipam.RangesStore.GetRangesForPool(pool.UID)
	for _, poolRange := range poolRanges {
		// Remove allocations from services if the ranges no longer exist
		ipam.RangesStore.Delete(poolRange)
		ipam.deleteRangeAllocations(ctx, poolRange)
	}
}

// settleConflicts check if there exist any un-resolved conflicts between the ranges of IP pools and resolve them.
// secondly, it checks if any ranges that are marked as conflicting have been resolved.
// Any found conflicts are reflected in the IP Pool's status.
func (ipam *LBIPAM) settleConflicts(ctx context.Context) {
	ipam.Logger.Debug("Settling pool conflicts")

	// Mark any pools that conflict as conflicting
	for _, poolOuter := range ipam.PoolStore.pools {
		if poolOuter.Status.Conflicting {
			continue
		}

		outerRanges, _ := ipam.RangesStore.GetRangesForPool(poolOuter.GetUID())

		if conflicting, rangeA, rangeB := ipam.areRangesInternallyConflicting(outerRanges); conflicting {
			ipam.markPoolConflicting(ctx, poolOuter, poolOuter, rangeA, rangeB)
			continue
		}

		for _, poolInner := range ipam.PoolStore.pools {
			if poolOuter.GetUID() == poolInner.GetUID() {
				continue
			}

			if poolInner.Status.Conflicting {
				continue
			}

			innerRanges, _ := ipam.RangesStore.GetRangesForPool(poolInner.GetUID())
			if conflicting, outerRange, innerRange := ipam.areRangesConflicting(outerRanges, innerRanges); conflicting {
				// If two pools are conflicting, disable/mark the newest pool

				if poolOuter.CreationTimestamp.Before(&poolInner.CreationTimestamp) {
					ipam.markPoolConflicting(ctx, poolInner, poolOuter, innerRange, outerRange)
					break
				}

				ipam.markPoolConflicting(ctx, poolOuter, poolInner, outerRange, innerRange)
				break
			}
		}
	}

	// un-mark pools that no longer conflict
	for _, poolOuter := range ipam.PoolStore.pools {
		if !poolOuter.Status.Conflicting {
			continue
		}

		outerRanges, _ := ipam.RangesStore.GetRangesForPool(poolOuter.GetUID())

		// If the pool is still internally conflicting, don't un-mark
		if conflicting, _, _ := ipam.areRangesInternallyConflicting(outerRanges); conflicting {
			continue
		}

		poolConflict := false
		for _, poolInner := range ipam.PoolStore.pools {
			if poolOuter.GetUID() == poolInner.GetUID() {
				continue
			}

			innerRanges, _ := ipam.RangesStore.GetRangesForPool(poolInner.GetUID())
			if conflicting, _, _ := ipam.areRangesConflicting(outerRanges, innerRanges); conflicting {
				poolConflict = true
				break
			}
		}

		// The outer pool, which is marked conflicting no longer conflicts
		if !poolConflict {
			ipam.unmarkPool(ctx, poolOuter)
		}
	}
}

// areRangesInternallyConflicting checks if any of the ranges within the same list conflict with each other.
func (ipam *LBIPAM) areRangesInternallyConflicting(ranges []*LBRange) (conflicting bool, rangeA, rangeB *LBRange) {
	for i, outer := range ranges {
		for ii, inner := range ranges {
			if i == ii {
				continue
			}

			if !intersect(outer.allocRange.CIDR(), inner.allocRange.CIDR()) {
				continue
			}

			return true, outer, inner
		}
	}

	return false, nil, nil
}

func (ipam *LBIPAM) areRangesConflicting(outerRanges, innerRanges []*LBRange) (conflicting bool, targetRange, conflictingRange *LBRange) {
	for _, outerRange := range outerRanges {
		for _, innerRange := range innerRanges {
			// IPs of dissimilar IP families can't overlap
			outerIsIpv4 := outerRange.allocRange.CIDR().IP.To4() != nil
			innerIsIpv4 := innerRange.allocRange.CIDR().IP.To4() != nil
			if innerIsIpv4 != outerIsIpv4 {
				continue
			}

			// no intersection, no conflict
			if !intersect(outerRange.allocRange.CIDR(), innerRange.allocRange.CIDR()) {
				continue
			}

			return true, outerRange, innerRange
		}
	}

	return false, nil, nil
}

func intersect(n1, n2 net.IPNet) bool {
	return n2.Contains(n1.IP) || n1.Contains(n2.IP)
}

// markPoolConflicting marks the targetPool as "Conflicting" in its status and disables all of its ranges internally.
func (ipam *LBIPAM) markPoolConflicting(
	ctx context.Context,
	targetPool, collisionPool *cilium_api_v2alpha1.CiliumLoadBalancerIPPool,
	targetRange, collisionRange *LBRange,
) {
	// If the target pool is already marked conflicting, than there is no need to re-add a condition
	if targetPool.Status.Conflicting {
		return
	}

	ipam.Logger.Warnf("Pool '%s' conflicts since CIDR '%s' overlaps CIDR '%s' from IP Pool '%s'",
		targetPool.Name,
		ipNetStr(targetRange.allocRange.CIDR()),
		ipNetStr(collisionRange.allocRange.CIDR()),
		collisionPool.Name,
	)
	targetPool.Status.Conflicting = true
	targetPool.Status.ConflictReason = fmt.Sprintf(
		"Pool conflicts since CIDR '%s' overlaps CIDR '%s' from IP Pool '%s'",
		ipNetStr(targetRange.allocRange.CIDR()),
		ipNetStr(collisionRange.allocRange.CIDR()),
		collisionPool.Name,
	)

	// Mark all ranges of the pool as internally disabled so we will not allocate from them.
	targetPoolRanges, _ := ipam.RangesStore.GetRangesForPool(targetPool.UID)
	for _, poolRange := range targetPoolRanges {
		poolRange.internallyDisabled = true
	}

	err := ipam.patchPoolStatus(ctx, targetPool)
	if err != nil {
		ipam.Logger.WithError(err).Error("Error while updating IP pool status (mark conflict)")
		return
	}
}

// unmarkPool removes the "Conflicting" status from the pool and removes the internally disabled flag from its ranges
func (ipam *LBIPAM) unmarkPool(ctx context.Context, targetPool *cilium_api_v2alpha1.CiliumLoadBalancerIPPool) {
	targetPool.Status.Conflicting = false
	targetPool.Status.ConflictReason = ""

	// Re-enabled all ranges
	targetPoolRanges, _ := ipam.RangesStore.GetRangesForPool(targetPool.UID)
	for _, poolRange := range targetPoolRanges {
		poolRange.internallyDisabled = false
	}

	err := ipam.patchPoolStatus(ctx, targetPool)
	if err != nil {
		ipam.Logger.WithError(err).Error("Error while updating IP pool status (unmark)")
		return
	}
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

	_, err = ipam.SvcClient.Services(sv.Key.Namespace).Patch(ctx, sv.Key.Name,
		types.JSONPatchType, createStatusPatch, meta_v1.PatchOptions{
			FieldManager: ciliumFieldManager,
		}, "status")

	return err
}

func (ipam *LBIPAM) patchPoolStatus(ctx context.Context, pool *cilium_api_v2alpha1.CiliumLoadBalancerIPPool) error {
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

	_, err = ipam.PoolClient.Patch(ctx, pool.Name,
		types.JSONPatchType, createStatusPatch, meta_v1.PatchOptions{
			FieldManager: ciliumFieldManager,
		}, "status")

	return err
}

// svcLabels clones the services labels and adds a number of internal labels which can be used to select
// specific services and/or namespaces using the label selectors.
func svcLabels(svc *core_v1.Service) slim_labels.Set {
	clone := maps.Clone(svc.Labels)
	clone[serviceNameLabel] = svc.Name
	clone[serviceNamespaceLabel] = svc.Namespace
	return clone
}

// PoolStore is a storage structure for IPPools
type PoolStore struct {
	// Map of all IP pools
	pools map[types.UID]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool
}

func NewPoolStore() PoolStore {
	return PoolStore{
		pools: make(map[types.UID]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool),
	}
}

func (ps *PoolStore) Upsert(pool *cilium_api_v2alpha1.CiliumLoadBalancerIPPool) {
	if pool == nil {
		return
	}
	ps.pools[pool.GetUID()] = pool
}

func (ps *PoolStore) Delete(pool *cilium_api_v2alpha1.CiliumLoadBalancerIPPool) {
	delete(ps.pools, pool.GetUID())
}

func (ps *PoolStore) GetByUID(uid types.UID) (*cilium_api_v2alpha1.CiliumLoadBalancerIPPool, bool) {
	pool, found := ps.pools[uid]
	return pool, found
}

type RangesStore struct {
	ranges       []*LBRange
	poolToRanges map[types.UID][]*LBRange
}

func NewRangesStore() RangesStore {
	return RangesStore{
		poolToRanges: make(map[types.UID][]*LBRange),
	}
}

func (rs *RangesStore) Delete(lbRange *LBRange) {
	idx := slices.Index(rs.ranges, lbRange)
	if idx != -1 {
		rs.ranges = slices.Delete(rs.ranges, idx, idx+1)
	}

	poolRanges := rs.poolToRanges[lbRange.originPool]

	idx = slices.Index(poolRanges, lbRange)
	if idx != -1 {
		poolRanges = slices.Delete(poolRanges, idx, idx+1)
	}

	if len(poolRanges) > 0 {
		rs.poolToRanges[lbRange.originPool] = poolRanges
	} else {
		delete(rs.poolToRanges, lbRange.originPool)
	}
}

func (rs *RangesStore) Add(lbRange *LBRange) {
	rs.ranges = append(rs.ranges, lbRange)
	poolRanges := rs.poolToRanges[lbRange.originPool]
	poolRanges = append(poolRanges, lbRange)
	rs.poolToRanges[lbRange.originPool] = poolRanges
}

func (rs *RangesStore) GetRangesForPool(uid types.UID) ([]*LBRange, bool) {
	ranges, found := rs.poolToRanges[uid]
	return ranges, found
}

type LBRange struct {
	// the actual data of which ips have been allocated or not
	allocRange *ipallocator.Range
	// If true, the LB range has been disabled via the CRD and thus no IPs should be allocated from this range
	externallyDisabled bool
	// If true, the LB range has been disabled by us, because it conflicts with other ranges for example.
	// This range should not be used for allocation.
	internallyDisabled bool
	// The UID of the pool that originated this LB range
	originPool types.UID
}

func NewLBRange(cidr *net.IPNet, pool *cilium_api_v2alpha1.CiliumLoadBalancerIPPool) (*LBRange, error) {
	allocRange, err := ipallocator.NewCIDRRange(cidr)
	if err != nil {
		return nil, fmt.Errorf("new cidr range: %w", err)
	}

	return &LBRange{
		allocRange:         allocRange,
		internallyDisabled: false,
		externallyDisabled: pool.Spec.Disabled,
		originPool:         pool.GetUID(),
	}, nil
}

func (lr *LBRange) Disabled() bool {
	return lr.internallyDisabled || lr.externallyDisabled
}

func (lr *LBRange) String() string {
	cidr := lr.allocRange.CIDR()
	return fmt.Sprintf(
		"%s (free: %d, used: %d, intDis: %v, extDis: %v) - origin %s",
		cidr.String(),
		lr.allocRange.Free(),
		lr.allocRange.Used(),
		lr.internallyDisabled,
		lr.externallyDisabled,
		lr.originPool,
	)
}

func ipNetStr(net net.IPNet) string {
	ptr := &net
	return ptr.String()
}

type ServiceStore struct {
	// List of services which have received all IPs they requested
	satisfied map[types.UID]*ServiceView
	// List of services which have one or more IPs which were requested but not allocated
	unsatisfied map[types.UID]*ServiceView
}

func NewServiceStore() ServiceStore {
	return ServiceStore{
		satisfied:   make(map[types.UID]*ServiceView),
		unsatisfied: make(map[types.UID]*ServiceView),
	}
}

func (ss *ServiceStore) GetService(uid types.UID) (serviceView *ServiceView, found, satisfied bool) {
	serviceView, found = ss.satisfied[uid]
	if found {
		return serviceView, true, true
	}

	serviceView, found = ss.unsatisfied[uid]
	if found {
		return serviceView, true, false
	}

	return nil, false, false
}

func (ss *ServiceStore) Upsert(serviceView *ServiceView) {
	if serviceView.isSatisfied() {
		delete(ss.unsatisfied, serviceView.UID)
		ss.satisfied[serviceView.UID] = serviceView
	} else {
		delete(ss.satisfied, serviceView.UID)
		ss.unsatisfied[serviceView.UID] = serviceView
	}
}

func (ss *ServiceStore) Delete(uid types.UID) {
	delete(ss.satisfied, uid)
	delete(ss.unsatisfied, uid)
}

// ServiceView is the LB IPAM's view of the service, the minimal amount of info we need about it.
type ServiceView struct {
	UID    types.UID
	Key    resource.Key
	Labels slim_labels.Set

	Generation int64
	Status     *core_v1.ServiceStatus

	// The specific IPs requested by the service
	RequestedIPs []net.IP
	// The IP families requested by the service
	RequestedFamilies struct {
		IPv4 bool
		IPv6 bool
	}
	// The IPs we have allocated for this IP
	AllocatedIPs []ServiceViewIP
}

func (sv *ServiceView) isSatisfied() bool {
	// If the service requests specific IPs
	if len(sv.RequestedIPs) > 0 {
		for _, reqIP := range sv.RequestedIPs {
			// If reqIP doesn't exist in the list of assigned IPs
			if slices.IndexFunc(sv.Status.LoadBalancer.Ingress, func(in core_v1.LoadBalancerIngress) bool {
				return net.ParseIP(in.IP).Equal(reqIP)
			}) == -1 {
				return false
			}
		}

		return true
	}

	// No specific requests are made, check that all requested families are assigned
	hasIPv4 := false
	hasIPv6 := false
	for _, assigned := range sv.Status.LoadBalancer.Ingress {
		if net.ParseIP(assigned.IP).To4() == nil {
			hasIPv6 = true
		} else {
			hasIPv4 = true
		}
	}

	// We are unsatisfied if we requested IPv4 and didn't get it or we requested IPv6 and didn't get it
	unsatisfied := (sv.RequestedFamilies.IPv4 && !hasIPv4) || (sv.RequestedFamilies.IPv6 && !hasIPv6)
	return !unsatisfied
}

// ServiceViewIP is the IP and from which range it was allocated
type ServiceViewIP struct {
	IP     net.IP
	Origin *LBRange
}
