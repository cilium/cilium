package servicemanager

import (
	"context"
	"strings"
	"sync"

	"github.com/cilium/cilium/pkg/annotation"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/counter"
	"github.com/cilium/cilium/pkg/hive"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"

	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/loadbalancer"
)

type serviceKey = resource.Key

var K8sHandlerCell = cell.Module(
	"service-k8s-handler",
	"Manages services from Kubernetes",

	cell.Provide(newK8sHandler),

	// FIXME: Would be nice to include "Invoke"'s in the
	// module dot graph. Then we don't need to have private objects
	// in the graph.
	cell.Invoke(func(*k8sHandler) {}),
)

type k8sHandlerParams struct {
	cell.In

	ServiceManager ServiceManager
	Log            logrus.FieldLogger
	Services       resource.Resource[*slim_corev1.Service]
	Endpoints      resource.Resource[*k8s.Endpoints]
}

type k8sServiceEntry struct {
	frontends []*Frontend
	backends  map[string][]*Backend // keyed by endpoint slice name
}

type k8sHandler struct {
	params k8sHandlerParams

	// serviceTracker tracks changes to the set of services referenced by
	// the endpoints.
	serviceTracker resource.ObjectTracker[*slim_corev1.Service]

	// serviceRefCount maintains count of how many endpoints reference
	// a specific service. Used to decide when to track and untrack services.
	serviceRefCount counter.Counter[serviceKey]

	// handle is the service manager handle for managing frontends and backends
	handle ServiceHandle

	entries map[serviceKey]*k8sServiceEntry
}

// UGH
func keyToServiceID(key resource.Key) k8s.ServiceID {
	return k8s.ServiceID{Name: key.Name, Namespace: key.Namespace}
}

func newK8sHandler(log logrus.FieldLogger, lc hive.Lifecycle, p k8sHandlerParams) *k8sHandler {
	if p.Services == nil {
		log.Info("K8s Services not available, not starting K8sHandler")
		return nil
	}

	handler := &k8sHandler{
		params:          p,
		handle:          p.ServiceManager.NewHandle("k8s-handler"),
		entries:         make(map[serviceKey]*k8sServiceEntry),
		serviceRefCount: make(counter.Counter[serviceKey]),
	}

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())

	handler.serviceTracker = p.Services.Tracker(ctx)

	lc.Append(
		hive.Hook{
			OnStart: func(hive.HookContext) error {
				wg.Add(1)
				go func() {
					defer wg.Done()
					handler.processLoop(ctx)
				}()
				return nil
			},
			OnStop: func(hive.HookContext) error {
				cancel()
				wg.Wait()
				return nil
			},
		})

	return handler
}

func (k *k8sHandler) processLoop(ctx context.Context) {
	services := k.serviceTracker.Events()
	endpoints := k.params.Endpoints.Events(ctx)

	for {
		select {
		case <-ctx.Done():
			return

		case ev := <-services:
			switch ev.Kind {
			case resource.Upsert:
				k.updateService(ev.Key, ev.Object)
			case resource.Delete:
				k.deleteService(ev.Key, ev.Object)
			}
			ev.Done(nil)

		case ev := <-endpoints:
			switch ev.Kind {
			case resource.Sync:
				// TODO. Endpoints have synced, but some of them might still
				// be waiting for the associated service to appear. Use a SWG
				// or some such to trigger the handle synchronized call when we've
				// 1) processed all endpoint events
				// 2) all endpoints have matched with a service
			case resource.Upsert:
				k.updateEndpoints(ev.Key, ev.Object)
			case resource.Delete:
				k.deleteEndpoints(ev.Key, ev.Object)
			}
			ev.Done(nil)
		}
	}
}

func (k *k8sHandler) updateService(key resource.Key, svc *slim_corev1.Service) {
	k.params.Log.Debugf("upsertService(%s)", key)

	if strings.ToLower(svc.Spec.ClusterIP) == "none" {
		// Headless services are ignored.
		k.params.Log.Debugf("Headless service, ignoring.")
		return
	}

	entry := k.getEntry(key)

	frontends, err := serviceToFrontends(svc)
	if err != nil {
		// TODO: Should we still keep the old entry?
		panic("TBD")
	}

	entry.frontends = frontends

	k.params.Log.Debugf("Updated frontends: %#v", entry.frontends)
	k.processEntry(key, entry)
}

func (k *k8sHandler) deleteService(key resource.Key, k8sSvc *slim_corev1.Service) {
	k.params.Log.Debugf("deleteService(%s) UNIMPLEMENTED", key)
}

func (k *k8sHandler) getEntry(key serviceKey) *k8sServiceEntry {
	entry := k.entries[key]
	if entry == nil {
		entry = &k8sServiceEntry{
			backends: make(map[string][]*Backend),
		}
		k.entries[key] = entry
	}
	return entry
}

func endpointsToServiceKey(eps *k8s.Endpoints) serviceKey {
	return resource.Key{Name: eps.ServiceID.Name, Namespace: eps.ServiceID.Namespace}
}

func (k *k8sHandler) updateEndpoints(key resource.Key, eps *k8s.Endpoints) {
	k.params.Log.Infof("updateEndpoints(%s): sliceId=%s, eps=%s", key, eps.EndpointSliceID, eps.String())

	serviceKey := endpointsToServiceKey(eps)
	entry := k.getEntry(serviceKey)

	// Start tracking changes to the service.
	if k.serviceRefCount.Add(serviceKey) {
		k.params.Log.Debugf("updateEndpoints(%s): starting to track %s", key, serviceKey)
		k.serviceTracker.Track(serviceKey)
	}

	entry.addBackends(eps)
	k.params.Log.Infof("updateEndpoints(%s): added backends: %#v", key, entry.backends)
	k.processEntry(serviceKey, entry)
}

func (k *k8sHandler) deleteEndpoints(key resource.Key, eps *k8s.Endpoints) {
	// Stop tracking the service.
	if k.serviceRefCount.Delete(key) {
		k.serviceTracker.Untrack(resource.Key{Name: eps.ServiceID.Name, Namespace: eps.ServiceID.Namespace})
	}

	// TODO remove the backends and process the updated entry.
}

func (k *k8sHandler) processEntry(key serviceKey, entry *k8sServiceEntry) {
	if len(entry.frontends) == 0 {
		// No frontends yet as we've not processed the event for the service
		// that the endpoints are referencing.
		return
	}
	id := ServiceName{
		Scope:     loadbalancer.ScopeSVC,
		Namespace: key.Namespace,
		Name:      key.Name,
	}
	k.handle.UpsertBackends(id, entry.allBackends()...)
	for _, fe := range entry.frontends {
		k.handle.UpsertFrontend(id, fe)
	}
}

func (e *k8sServiceEntry) addBackends(eps *k8s.Endpoints) {
	newBackends := []*Backend{}

	for addr, k8sBackend := range eps.Backends {
		bes := parseBackend(addr, k8sBackend)
		if len(bes) > 0 {
			newBackends = append(newBackends, bes...)
		}
	}
	e.backends[eps.EndpointSliceID.EndpointSliceName] = newBackends
}

func (e *k8sServiceEntry) allBackends() []*Backend {
	return flatten(maps.Values(e.backends))
}

func parseBackend(addr cmtypes.AddrCluster, be *k8s.Backend) []*Backend {
	backends := make([]*Backend, 0, len(be.Ports))

	for fePortName, fePort := range be.Ports {
		backendState := loadbalancer.BackendStateActive
		if be.Terminating {
			backendState = loadbalancer.BackendStateTerminating
		}
		backends = append(backends, &loadbalancer.Backend{
			FEPortName: fePortName,
			NodeName:   be.NodeName,
			L3n4Addr: loadbalancer.L3n4Addr{
				AddrCluster: addr,
				L4Addr:      *fePort,
			},
			State:     backendState,
			Preferred: loadbalancer.Preferred(be.Preferred),
			Weight:    loadbalancer.DefaultBackendWeight,
		})
	}
	return backends
}

// parseService parses the k8s Service object into individual load-balancer service.
func serviceToFrontends(svc *slim_corev1.Service) ([]*Frontend, error) {
	// Since the frontends share a lot of fields, parse the service
	// into a base prototype object.
	base, err := parseBaseFrontend(svc)
	if err != nil {
		// TODO: How do we report parse/validation errors towards the
		// operator? Should Service.Status be updated?
		return nil, err
	}

	builder := frontendsBuilder{base: base, svc: svc}

	{
		clusterIPs := svc.Spec.ClusterIPs
		if len(clusterIPs) == 0 {
			clusterIPs = []string{svc.Spec.ClusterIP}
		}
		builder.append(loadbalancer.SVCTypeClusterIP, clusterIPs)
	}

	builder.append(loadbalancer.SVCTypeExternalIPs, svc.Spec.ExternalIPs)

	{
		loadBalancerIPs := []string{}
		for _, ip := range svc.Status.LoadBalancer.Ingress {
			if ip.IP != "" {
				loadBalancerIPs = append(loadBalancerIPs, ip.IP)
			}
		}
		builder.append(loadbalancer.SVCTypeLoadBalancer, loadBalancerIPs)
	}

	if svc.Spec.Type == slim_corev1.ServiceTypeNodePort {
		builder.appendNodePort()
	}

	return builder.list, nil
}

type frontendsBuilder struct {
	base Frontend
	svc  *slim_corev1.Service

	list []*Frontend
}

// nodePortAddrCluster is a sentinel address. TODO ipv6?
var nodePortAddrCluster = cmtypes.MustParseAddrCluster("0.0.0.0")

func (b *frontendsBuilder) appendNodePort() {
	// NodePort is special as the frontends are all addresses of the
	// local node and thus an implementation detail of datapath.
	for _, port := range b.svc.Spec.Ports {
		l4 := loadbalancer.L4Addr{
			Protocol: loadbalancer.L4Type(port.Protocol),
			Port:     uint16(port.Port),
		}
		fe := b.base
		fe.Address = loadbalancer.L3n4Addr{
			AddrCluster: nodePortAddrCluster,
			L4Addr:      l4,
			Scope:       loadbalancer.ScopeExternal,
		}
		fe.Type = loadbalancer.SVCTypeNodePort
		b.list = append(b.list, &fe)
	}
}

func (b *frontendsBuilder) append(typ loadbalancer.SVCType, ips []string) {
	for _, ipstr := range ips {
		addr, err := cmtypes.ParseAddrCluster(ipstr)
		if err != nil {
			// FIXME handle bad ips? not done by original code
			continue
		}

		for _, port := range b.svc.Spec.Ports {
			l4 := loadbalancer.L4Addr{
				Protocol: loadbalancer.L4Type(port.Protocol),
				Port:     uint16(port.Port),
			}
			fe := b.base
			fe.Address = loadbalancer.L3n4Addr{
				AddrCluster: addr,
				L4Addr:      l4,
				Scope:       loadbalancer.ScopeExternal,
			}
			fe.Type = typ
			b.list = append(b.list, &fe)
		}
	}
}

const (
	serviceAffinityNone   = ""
	serviceAffinityLocal  = "local"
	serviceAffinityRemote = "remote"
)

func getAnnotationServiceAffinity(svc *slim_corev1.Service) string {
	if value, ok := svc.ObjectMeta.Annotations[annotation.ServiceAffinity]; ok {
		return strings.ToLower(value)
	}
	return serviceAffinityNone
}

func parseBaseFrontend(svc *slim_corev1.Service) (Frontend, error) {
	base := Frontend{}
	base.Name = loadbalancer.ServiceName{Scope: loadbalancer.ScopeSVC, Name: svc.Name, Namespace: svc.Namespace}
	base.Type = loadbalancer.SVCTypeNone

	switch svc.Spec.ExternalTrafficPolicy {
	case slim_corev1.ServiceExternalTrafficPolicyTypeLocal:
		base.TrafficPolicy = loadbalancer.SVCTrafficPolicyLocal
	default:
		base.TrafficPolicy = loadbalancer.SVCTrafficPolicyCluster
	}

	base.HealthCheckNodePort = uint16(svc.Spec.HealthCheckNodePort)

	// TODO service affinity. affects which backend is preferred
	// (clustermesh)

	if svc.Spec.SessionAffinity == slim_corev1.ServiceAffinityClientIP {
		base.SessionAffinity = true
		if cfg := svc.Spec.SessionAffinityConfig; cfg != nil && cfg.ClientIP != nil && cfg.ClientIP.TimeoutSeconds != nil {
			base.SessionAffinityTimeoutSec = uint32(*cfg.ClientIP.TimeoutSeconds)
		}
		if base.SessionAffinityTimeoutSec == 0 {
			base.SessionAffinityTimeoutSec = uint32(slim_corev1.DefaultClientIPServiceAffinitySeconds)
		}
	}

	/*if base.Type == loadbalancer.SVCTypeLoadBalancer {
		svcs[i].LoadBalancerSourceRanges = lbSrcRanges
	}*/

	return base, nil

}

func flatten[E any](xs [][]E) []E {
	out := []E{}
	for i := range xs {
		for j := range xs[i] {
			out = append(out, xs[i][j])
		}
	}
	return out
}

func drain[T any](ch <-chan T) {
	for range ch {
	}
}
