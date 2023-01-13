package servicemanager

import (
	"context"
	"strings"

	"github.com/cilium/workerpool"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/annotation"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/hive"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"

	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/resource"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
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

type k8sHandler struct {
	params k8sHandlerParams

	// handle is the service manager handle for managing frontends and backends
	handle ServiceHandle

	workerpool *workerpool.WorkerPool
}

func newK8sHandler(log logrus.FieldLogger, lc hive.Lifecycle, p k8sHandlerParams) *k8sHandler {
	if p.Services == nil {
		log.Info("K8s Services not available, not starting K8sHandler")
		return nil
	}

	handler := &k8sHandler{
		params:     p,
		handle:     p.ServiceManager.NewHandle("k8s-handler"),
		workerpool: workerpool.New(1),
	}
	lc.Append(handler)
	return handler
}

func (k *k8sHandler) Start(hive.HookContext) error {
	return k.workerpool.Submit("processLoop", k.processLoop)
}

func (k *k8sHandler) Stop(hive.HookContext) error {
	defer k.handle.Close()
	return k.workerpool.Close()
}

func (k *k8sHandler) processLoop(ctx context.Context) error {
	services := k.params.Services.Events(ctx)
	servicesSynced := false
	endpoints := k.params.Endpoints.Events(ctx)
	endpointsSynced := false

	for {
		select {
		case <-ctx.Done():
			return nil

		case ev, ok := <-services:
			if !ok {
				services = nil
			}
			switch ev.Kind {
			case resource.Sync:
				servicesSynced = true
				if servicesSynced && endpointsSynced {
					k.handle.Synchronized()
				}
			case resource.Upsert:
				k.updateService(ev.Key, ev.Object)
			case resource.Delete:
				k.deleteService(ev.Key, ev.Object)
			}
			ev.Done(nil)

		case ev, ok := <-endpoints:
			if !ok {
				endpoints = nil
			}
			switch ev.Kind {
			case resource.Sync:
				endpointsSynced = true
				if servicesSynced && endpointsSynced {
					k.handle.Synchronized()
				}
			case resource.Upsert:
				k.updateEndpoints(ev.Key, ev.Object)
			case resource.Delete:
				k.deleteEndpoints(ev.Key, ev.Object)
			}
			ev.Done(nil)
		}
	}
	return nil
}

func (k *k8sHandler) updateService(key resource.Key, svc *slim_corev1.Service) {
	k.params.Log.Debugf("upsertService(%s)", key)

	if strings.ToLower(svc.Spec.ClusterIP) == "none" {
		// Headless services are ignored.
		k.params.Log.Debugf("Headless service, ignoring.")
		return
	}

	for _, fe := range serviceToFrontends(svc) {
		k.handle.UpsertFrontend(fe)
	}
}

func (k *k8sHandler) deleteService(key resource.Key, svc *slim_corev1.Service) {
	if strings.ToLower(svc.Spec.ClusterIP) == "none" {
		// Headless services are ignored.
		k.params.Log.Debugf("Headless service, ignoring.")
		return
	}
	for _, fe := range serviceToFrontends(svc) {
		k.handle.DeleteFrontend(fe)
	}
}

func endpointsToServiceName(eps *k8s.Endpoints) lb.ServiceName {
	return lb.ServiceName{Authority: lb.AuthoritySVC, Name: eps.ServiceID.Name, Namespace: eps.ServiceID.Namespace}
}

func (k *k8sHandler) updateEndpoints(key resource.Key, eps *k8s.Endpoints) {
	k.params.Log.Infof("updateEndpoints(%s): sliceId=%s, eps=%s", key, eps.EndpointSliceID, eps.String())

	newBackends := make([]*lb.Backend, 0, len(eps.Backends))
	for addr, k8sBackend := range eps.Backends {
		bes := parseBackend(addr, k8sBackend)
		if len(bes) > 0 {
			newBackends = append(newBackends, bes...)
		}
	}
	name := endpointsToServiceName(eps)
	k.handle.UpsertBackends(name, newBackends...)
}

func (k *k8sHandler) deleteEndpoints(key resource.Key, eps *k8s.Endpoints) {
	panic("TODO deleteEndpoints")
}

func parseBackend(addr cmtypes.AddrCluster, be *k8s.Backend) []*lb.Backend {
	backends := make([]*lb.Backend, 0, len(be.Ports))

	for fePortName, fePort := range be.Ports {
		backendState := lb.BackendStateActive
		if be.Terminating {
			backendState = lb.BackendStateTerminating
		}
		backends = append(backends, &lb.Backend{
			FEPortName: fePortName,
			NodeName:   be.NodeName,
			L3n4Addr: lb.L3n4Addr{
				AddrCluster: addr,
				L4Addr:      *fePort,
			},
			State:     backendState,
			Preferred: lb.Preferred(be.Preferred),
			Weight:    lb.DefaultBackendWeight,
		})
	}
	return backends
}

// parseService parses the k8s Service object into individual load-balancer frontend.
func serviceToFrontends(svc *slim_corev1.Service) []lb.FE {
	name := lb.ServiceName{Authority: lb.AuthoritySVC, Name: svc.Name, Namespace: svc.Namespace}
	common := lb.CommonFE{
		Name: name,
	}
	switch svc.Spec.ExternalTrafficPolicy {
	case slim_corev1.ServiceExternalTrafficPolicyTypeLocal:
		common.ExtTrafficPolicy = lb.SVCTrafficPolicyLocal
	default:
		common.ExtTrafficPolicy = lb.SVCTrafficPolicyCluster
	}
	if svc.Spec.SessionAffinity == slim_corev1.ServiceAffinityClientIP {
		common.SessionAffinity = true
		if cfg := svc.Spec.SessionAffinityConfig; cfg != nil && cfg.ClientIP != nil && cfg.ClientIP.TimeoutSeconds != nil {
			common.SessionAffinityTimeoutSec = uint32(*cfg.ClientIP.TimeoutSeconds)
		}
		if common.SessionAffinityTimeoutSec == 0 {
			common.SessionAffinityTimeoutSec = uint32(slim_corev1.DefaultClientIPServiceAffinitySeconds)
		}
	}

	frontends := []lb.FE{}

	// ClusterIP
	clusterIPs := svc.Spec.ClusterIPs
	if len(clusterIPs) == 0 {
		clusterIPs = []string{svc.Spec.ClusterIP}
	}
	for _, ip := range clusterIPs {
		addr, err := cmtypes.ParseAddrCluster(ip)
		if err != nil {
			// TODO should patch Service.Status and report the bad IP?
			continue
		}
		for _, port := range svc.Spec.Ports {
			fe := &lb.FEClusterIP{
				CommonFE: common,
				L3n4Addr: lb.L3n4Addr{
					AddrCluster: addr,
					L4Addr:      lb.L4Addr{lb.L4Type(port.Protocol), uint16(port.Port)},
					Scope:       lb.ScopeExternal,
				},
			}
			frontends = append(frontends, fe)
		}
	}

	// ExternalIPs
	for _, ip := range svc.Spec.ExternalIPs {
		addr, err := cmtypes.ParseAddrCluster(ip)
		if err != nil {
			// TODO should patch Service.Status and report the bad IP?
			continue
		}
		for _, port := range svc.Spec.Ports {
			fe := &lb.FEExternalIPs{
				CommonFE: common,
				L3n4Addr: lb.L3n4Addr{
					AddrCluster: addr,
					L4Addr:      lb.L4Addr{lb.L4Type(port.Protocol), uint16(port.Port)},
					Scope:       lb.ScopeExternal,
				},
			}
			frontends = append(frontends, fe)
		}
	}

	// LoadBalancer
	for _, ip := range svc.Status.LoadBalancer.Ingress {
		addr, err := cmtypes.ParseAddrCluster(ip.IP)
		if err != nil {
			// TODO should patch Service.Status and report the bad IP?
			continue
		}

		// FIXME LoadBalancerSourceRanges
		for _, port := range svc.Spec.Ports {
			fe := &lb.FELoadBalancer{
				CommonFE: common,
				L3n4Addr: lb.L3n4Addr{
					AddrCluster: addr,
					L4Addr:      lb.L4Addr{lb.L4Type(port.Protocol), uint16(port.Port)},
					Scope:       lb.ScopeExternal,
				},
			}
			frontends = append(frontends, fe)
		}
	}

	// NodePort
	if svc.Spec.Type == slim_corev1.ServiceTypeNodePort {
		for _, port := range svc.Spec.Ports {
			fe := &lb.FENodePort{
				CommonFE:            common,
				L4Addr:              lb.L4Addr{lb.L4Type(port.Protocol), uint16(port.Port)},
				Scope:               lb.ScopeExternal,
				HealthCheckNodePort: uint16(svc.Spec.HealthCheckNodePort),
			}
			frontends = append(frontends, fe)
		}
	}

	return frontends
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
