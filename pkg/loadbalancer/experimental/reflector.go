// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package experimental

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"slices"
	"strings"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/stream"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"

	daemonK8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/cidr"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/container"
	"github.com/cilium/cilium/pkg/counter"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

// ReflectorCell reflects Kubernetes Service and EndpointSlice objects to the
// load-balancing tables.
//
// Note that this implementation uses Resource[*Service] and Resource[*Endpoints],
// which is not the desired end-game as we'll hold onto the same data multiple
// times. We should instead have a reflector that is built directly on the client-go
// reflector (k8s.RegisterReflector) and not populate an intermediate cache.Store.
// But as we're still experimenting it's easier to build on what already exists.
var ReflectorCell = cell.Module(
	"reflector",
	"Reflects load-balancing state from Kubernetes",

	cell.Invoke(registerK8sReflector),

	// Provide the 'HaveNetNSCookieSupport' function
	cell.Provide(netnsCookieSupportFunc),
)

type reflectorParams struct {
	cell.In

	DB                     *statedb.DB
	Log                    *slog.Logger
	Lifecycle              cell.Lifecycle
	JobGroup               job.Group
	ServicesResource       stream.Observable[resource.Event[*slim_corev1.Service]]
	EndpointsResource      stream.Observable[resource.Event[*k8s.Endpoints]]
	Pods                   statedb.Table[daemonK8s.LocalPod]
	Writer                 *Writer
	ExtConfig              ExternalConfig
	HaveNetNSCookieSupport HaveNetNSCookieSupport
}

func registerK8sReflector(p reflectorParams) {
	if !p.Writer.IsEnabled() || p.ServicesResource == nil {
		return
	}
	initComplete := p.Writer.RegisterInitializer("k8s")
	p.JobGroup.Add(job.OneShot("reflector", func(ctx context.Context, health cell.Health) error {
		return runResourceReflector(ctx, health, p, initComplete)
	}))
}

func runResourceReflector(ctx context.Context, health cell.Health, p reflectorParams, initComplete func(WriteTxn)) error {
	extConfig := p.ExtConfig

	const (
		bufferSize = 300
		waitTime   = 10 * time.Millisecond
	)

	// Buffer the events to commit in larger write transactions.
	svcEvents := stream.ToChannel(ctx,
		stream.Buffer(
			p.ServicesResource,
			bufferSize, waitTime,
			bufferEvent[*slim_corev1.Service],
		),
	)
	epEvents := stream.ToChannel(
		ctx,
		stream.Buffer(
			p.EndpointsResource,
			bufferSize, waitTime,
			bufferEvent[*k8s.Endpoints],
		),
	)
	podChanges := stream.ToChannel(
		ctx,
		stream.Buffer(
			statedb.Observable(p.DB, p.Pods),
			bufferSize, waitTime,
			bufferPod,
		),
	)
	_, podsInitialized := p.Pods.Initialized(p.DB.ReadTxn())

	// Keep track of currently existing backends by endpoint slice.
	currentBackends := map[string]sets.Set[loadbalancer.L3n4Addr]{}

	// Track which service has associated endpoints to avoid creating the service&frontends
	// when there are no endpoints for it yet. This is critical during restoration to avoid
	// going temporarily to zero backends on restart.
	endpointsByService := counter.Counter[loadbalancer.ServiceName]{}

	// Services that are waiting for backends to appear before they're committed.
	pendingServices := map[loadbalancer.ServiceName]*slim_corev1.Service{}

	remainingSyncs := 3
	markSync := func(txn WriteTxn) {
		remainingSyncs--
		if remainingSyncs == 0 {
			initComplete(txn)
		}
	}

	var prevProcessingError error
	processingErrors := map[string]error{}

	upsertService := func(txn WriteTxn, obj *slim_corev1.Service) {
		svc, fes := convertService(extConfig, obj)
		if svc == nil {
			return
		}
		if err := p.Writer.UpsertServiceAndFrontends(txn, svc, fes...); err != nil {
			processingErrors["svc:"+svc.Name.String()] = err
		} else {
			delete(processingErrors, "svc:"+svc.Name.String())
		}
	}

	for {
		select {
		case <-ctx.Done():
			// Drain & stop.
			for range svcEvents {
			}
			for range epEvents {
			}
			for range podChanges {
			}
			return nil
		case buf, ok := <-svcEvents:
			if !ok {
				continue
			}
			txn := p.Writer.WriteTxn()
			for _, ev := range buf {
				obj := ev.Object
				switch ev.Kind {
				case resource.Sync:
					markSync(txn)

				case resource.Upsert:
					name := loadbalancer.ServiceName{Namespace: obj.Namespace, Name: obj.Name}

					if endpointsByService[name] == 0 && !isHeadless(obj) {
						// We have not yet seen backends for this service. Postpone its handling
						// until they've been seen.
						pendingServices[name] = obj
						break
					}
					upsertService(txn, obj)

				case resource.Delete:
					name := loadbalancer.ServiceName{Namespace: obj.Namespace, Name: obj.Name}
					delete(pendingServices, name)

					// Delete any processing error we had. We shouldn't consider the error from delete
					// as that will stick forever, and delete errors are really unexpected.
					errName := "svc:" + name.String()
					delete(processingErrors, errName)

					err := p.Writer.DeleteServiceAndFrontends(txn, name)
					if err != nil && !errors.Is(err, statedb.ErrObjectNotFound) {
						p.Log.Error("BUG: Unexpected failure in DeleteServiceAndFrontends",
							logfields.Error, err)
					}
				}
			}
			txn.Commit()

		case buf, ok := <-epEvents:
			if !ok {
				continue
			}

			txn := p.Writer.WriteTxn()
			for _, ev := range buf {
				obj := ev.Object
				switch ev.Kind {
				case resource.Sync:
					markSync(txn)
				case resource.Upsert:
					name, backends := convertEndpoints(extConfig, obj)

					if len(backends) > 0 {
						err := p.Writer.UpsertBackends(
							txn,
							name,
							source.Kubernetes,
							backends...)
						if err != nil {
							processingErrors["ep:"+obj.EndpointSliceName] = err
						} else {
							delete(processingErrors, "ep:"+obj.EndpointSliceName)
						}
					}

					// Release orphaned backends
					newAddrs := sets.New[loadbalancer.L3n4Addr]()
					for _, be := range backends {
						newAddrs.Insert(be.L3n4Addr)
					}
					old := currentBackends[obj.EndpointSliceName]
					for orphan := range old.Difference(newAddrs) {
						p.Writer.ReleaseBackend(txn, name, orphan)
					}
					currentBackends[obj.EndpointSliceName] = newAddrs
					endpointsByService.Add(name)

					// See if there was a service waiting for the endpoints.
					if svc, found := pendingServices[name]; found {
						upsertService(txn, svc)
						delete(pendingServices, name)
					}

				case resource.Delete:
					// Release the backends created before.
					name := loadbalancer.ServiceName{
						Name:      obj.ServiceID.Name,
						Namespace: obj.ServiceID.Namespace,
					}
					endpointsByService.Delete(name)
					for be := range currentBackends[obj.EndpointSliceName] {
						p.Writer.ReleaseBackend(txn, name, be)
					}
				}
			}
			txn.Commit()

		case buf, ok := <-podChanges:
			if !ok {
				continue
			}

			txn := p.Writer.WriteTxn()
			for _, change := range buf {
				obj := change.Object.Pod
				errName := "hostport:" + obj.Namespace + "/" + obj.Name
				if change.Deleted {
					delete(processingErrors, errName)
					if err := deleteHostPort(p, txn, obj); err != nil {
						p.Log.Error("BUG: Unexpected failure in deleteHostPort",
							logfields.Error, err)
					}
				} else {
					switch obj.Status.Phase {
					case slim_corev1.PodFailed, slim_corev1.PodSucceeded:
						// Pod has been terminated. Clean up the HostPort already even before the Pod object
						// has been removed to free up the HostPort for other pods.
						delete(processingErrors, errName)
						if err := deleteHostPort(p, txn, obj); err != nil {
							p.Log.Error("BUG: Unexpected failure in deleteHostPort",
								logfields.Error, err)
						}
					case slim_corev1.PodRunning:
						if obj.ObjectMeta.DeletionTimestamp != nil {
							// The pod has been marked for deletion. Stop processing HostPort changes
							// for it.
							continue
						}

						if err := upsertHostPort(p.HaveNetNSCookieSupport, extConfig, p.Log, txn, p.Writer, obj); err != nil {
							processingErrors[errName] = err
						}
					}
				}
			}
			txn.Commit()

		case <-podsInitialized:
			txn := p.Writer.WriteTxn()
			markSync(txn)
			txn.Commit()
			podsInitialized = nil

		}

		// Update health.
		processingError := errors.Join(slices.Collect(maps.Values(processingErrors))...)
		if !errors.Is(processingError, prevProcessingError) {
			if processingError == nil {
				health.OK("Running")
				p.Log.Info("Recovered from errors", logfields.Error, prevProcessingError)
			} else {
				health.Degraded("Failures processing services and endpoints", processingError)
				p.Log.Warn("Failures processing services and endpoints", logfields.Error, processingError)
			}
		}
		prevProcessingError = processingError
	}
}

var (
	zeroV4 = cmtypes.MustParseAddrCluster("0.0.0.0")
	zeroV6 = cmtypes.MustParseAddrCluster("::")
)

func isHeadless(svc *slim_corev1.Service) bool {
	_, headless := svc.Labels[corev1.IsHeadlessService]
	if strings.ToLower(svc.Spec.ClusterIP) == "none" {
		headless = true
	}
	return headless
}

func convertService(cfg ExternalConfig, svc *slim_corev1.Service) (s *Service, fes []FrontendParams) {
	name := loadbalancer.ServiceName{Namespace: svc.Namespace, Name: svc.Name}
	s = &Service{
		Name:                name,
		Source:              source.Kubernetes,
		Labels:              labels.Map2Labels(svc.Labels, string(source.Kubernetes)),
		Selector:            svc.Spec.Selector,
		Annotations:         svc.Annotations,
		HealthCheckNodePort: uint16(svc.Spec.HealthCheckNodePort),
	}

	if len(svc.Spec.Ports) > 0 {
		s.PortNames = map[string]uint16{}
		for _, port := range svc.Spec.Ports {
			s.PortNames[port.Name] = uint16(port.Port)
		}
	}

	for _, srcRange := range svc.Spec.LoadBalancerSourceRanges {
		cidr, err := cidr.ParseCIDR(srcRange)
		if err != nil {
			continue
		}
		s.SourceRanges = append(s.SourceRanges, *cidr)
	}

	switch svc.Spec.ExternalTrafficPolicy {
	case slim_corev1.ServiceExternalTrafficPolicyLocal:
		s.ExtTrafficPolicy = loadbalancer.SVCTrafficPolicyLocal
	default:
		s.ExtTrafficPolicy = loadbalancer.SVCTrafficPolicyCluster
	}

	if svc.Spec.InternalTrafficPolicy != nil && *svc.Spec.InternalTrafficPolicy == slim_corev1.ServiceInternalTrafficPolicyLocal {
		s.IntTrafficPolicy = loadbalancer.SVCTrafficPolicyLocal
	} else {
		s.IntTrafficPolicy = loadbalancer.SVCTrafficPolicyCluster
	}
	// Scopes for NodePort and LoadBalancer. Either just external (policies are the same), or
	// both external and internal (when one policy is local)
	scopes := []uint8{loadbalancer.ScopeExternal}
	twoScopes := (s.ExtTrafficPolicy == loadbalancer.SVCTrafficPolicyLocal) != (s.IntTrafficPolicy == loadbalancer.SVCTrafficPolicyLocal)
	if twoScopes {
		scopes = append(scopes, loadbalancer.ScopeInternal)
	}

	// SessionAffinity
	if svc.Spec.SessionAffinity == slim_corev1.ServiceAffinityClientIP {
		s.SessionAffinity = true

		s.SessionAffinityTimeout = time.Duration(int(time.Second) * int(slim_corev1.DefaultClientIPServiceAffinitySeconds))
		if cfg := svc.Spec.SessionAffinityConfig; cfg != nil && cfg.ClientIP != nil && cfg.ClientIP.TimeoutSeconds != nil && *cfg.ClientIP.TimeoutSeconds != 0 {
			s.SessionAffinityTimeout = time.Duration(int(time.Second) * int(*cfg.ClientIP.TimeoutSeconds))
		}
	}

	// A service that is annotated as headless has no frontends, even if the service spec contains
	// ClusterIPs etc.
	if isHeadless(svc) {
		return
	}

	// ClusterIP
	clusterIPs := container.NewImmSet(svc.Spec.ClusterIPs...)
	if svc.Spec.ClusterIP != "" {
		clusterIPs = clusterIPs.Insert(svc.Spec.ClusterIP)
	}
	for _, ip := range clusterIPs.AsSlice() {
		addr, err := cmtypes.ParseAddrCluster(ip)
		if err != nil {
			continue
		}

		if (!cfg.EnableIPv6 && addr.Is6()) || (!cfg.EnableIPv4 && addr.Is4()) {
			continue
		}

		for _, port := range svc.Spec.Ports {
			p := loadbalancer.NewL4Addr(loadbalancer.L4Type(port.Protocol), uint16(port.Port))
			if p == nil {
				continue
			}
			fe := FrontendParams{
				Type:        loadbalancer.SVCTypeClusterIP,
				PortName:    loadbalancer.FEPortName(port.Name),
				ServiceName: name,
				ServicePort: uint16(port.Port),
			}
			fe.Address.AddrCluster = addr
			fe.Address.Scope = loadbalancer.ScopeExternal
			fe.Address.L4Addr = *p
			fes = append(fes, fe)
		}
	}

	// NOTE: We always want to do ClusterIP services even when full kube-proxy replacement is disabled.
	// See https://github.com/cilium/cilium/issues/16197 for context.

	if cfg.KubeProxyReplacement {
		// NodePort
		if svc.Spec.Type == slim_corev1.ServiceTypeNodePort || svc.Spec.Type == slim_corev1.ServiceTypeLoadBalancer {
			for _, scope := range scopes {
				for _, family := range getIPFamilies(svc) {
					if (!cfg.EnableIPv6 && family == slim_corev1.IPv6Protocol) ||
						(!cfg.EnableIPv4 && family == slim_corev1.IPv4Protocol) {
						continue
					}
					for _, port := range svc.Spec.Ports {
						if port.NodePort == 0 {
							continue
						}

						fe := FrontendParams{
							Type:        loadbalancer.SVCTypeNodePort,
							PortName:    loadbalancer.FEPortName(port.Name),
							ServiceName: name,
							ServicePort: uint16(port.Port),
						}

						switch family {
						case slim_corev1.IPv4Protocol:
							fe.Address.AddrCluster = zeroV4
						case slim_corev1.IPv6Protocol:
							fe.Address.AddrCluster = zeroV6
						default:
							continue
						}

						p := loadbalancer.NewL4Addr(loadbalancer.L4Type(port.Protocol), uint16(port.NodePort))
						if p == nil {
							continue
						}
						fe.Address.Scope = scope
						fe.Address.L4Addr = *p
						fes = append(fes, fe)
					}
				}
			}
		}

		// LoadBalancer
		if svc.Spec.Type == slim_corev1.ServiceTypeLoadBalancer {
			for _, ip := range svc.Status.LoadBalancer.Ingress {
				if ip.IP == "" {
					continue
				}

				addr, err := cmtypes.ParseAddrCluster(ip.IP)
				if err != nil {
					continue
				}
				if (!cfg.EnableIPv6 && addr.Is6()) || (!cfg.EnableIPv4 && addr.Is4()) {
					continue
				}

				for _, scope := range scopes {
					for _, port := range svc.Spec.Ports {
						fe := FrontendParams{
							Type:        loadbalancer.SVCTypeLoadBalancer,
							PortName:    loadbalancer.FEPortName(port.Name),
							ServiceName: name,
							ServicePort: uint16(port.Port),
						}

						p := loadbalancer.NewL4Addr(loadbalancer.L4Type(port.Protocol), uint16(port.Port))
						if p == nil {
							continue
						}
						fe.Address.AddrCluster = addr
						fe.Address.Scope = scope
						fe.Address.L4Addr = *p
						fes = append(fes, fe)
					}
				}

			}
		}

		// ExternalIP
		for _, ip := range svc.Spec.ExternalIPs {
			addr, err := cmtypes.ParseAddrCluster(ip)
			if err != nil {
				continue
			}
			if (!cfg.EnableIPv6 && addr.Is6()) || (!cfg.EnableIPv4 && addr.Is4()) {
				continue
			}

			for _, port := range svc.Spec.Ports {
				fe := FrontendParams{
					Type:        loadbalancer.SVCTypeExternalIPs,
					PortName:    loadbalancer.FEPortName(port.Name),
					ServiceName: name,
					ServicePort: uint16(port.Port),
				}

				p := loadbalancer.NewL4Addr(loadbalancer.L4Type(port.Protocol), uint16(port.Port))
				if p == nil {
					continue
				}

				fe.Address.AddrCluster = addr
				fe.Address.Scope = loadbalancer.ScopeExternal
				fe.Address.L4Addr = *p
				fes = append(fes, fe)
			}
		}
	}

	return
}

func getIPFamilies(svc *slim_corev1.Service) []slim_corev1.IPFamily {
	if len(svc.Spec.IPFamilies) == 0 {
		// No IP families specified, try to deduce them from the cluster IPs
		if len(svc.Spec.ClusterIP) == 0 || svc.Spec.ClusterIP == slim_corev1.ClusterIPNone {
			return nil
		}

		ipv4, ipv6 := false, false
		if len(svc.Spec.ClusterIPs) > 0 {
			for _, cip := range svc.Spec.ClusterIPs {
				if ip.IsIPv6(net.ParseIP(cip)) {
					ipv6 = true
				} else {
					ipv4 = true
				}
			}
		} else {
			ipv6 = ip.IsIPv6(net.ParseIP(svc.Spec.ClusterIP))
			ipv4 = !ipv6
		}
		families := make([]slim_corev1.IPFamily, 0, 2)
		if ipv4 {
			families = append(families, slim_corev1.IPv4Protocol)
		}
		if ipv6 {
			families = append(families, slim_corev1.IPv4Protocol)
		}
		return families
	}
	return svc.Spec.IPFamilies
}

func convertEndpoints(cfg ExternalConfig, ep *k8s.Endpoints) (name loadbalancer.ServiceName, out []BackendParams) {
	name = loadbalancer.ServiceName{
		Name:      ep.ServiceID.Name,
		Namespace: ep.ServiceID.Namespace,
	}

	// k8s.Endpoints may have the same backend address multiple times
	// with a different port name. Collapse them down into single
	// entry.
	type entry struct {
		portNames []string
		backend   *k8s.Backend
	}
	entries := map[loadbalancer.L3n4Addr]entry{}

	for addrCluster, be := range ep.Backends {
		if (!cfg.EnableIPv6 && addrCluster.Is6()) || (!cfg.EnableIPv4 && addrCluster.Is4()) {
			continue
		}
		for portName, l4Addr := range be.Ports {
			l3n4Addr := loadbalancer.L3n4Addr{
				AddrCluster: addrCluster,
				L4Addr:      *l4Addr,
			}
			portNames := entries[l3n4Addr].portNames
			if portName != "" {
				portNames = append(portNames, portName)
			}
			entries[l3n4Addr] = entry{
				portNames: portNames,
				backend:   be,
			}
		}
	}
	for l3n4Addr, entry := range entries {
		state := loadbalancer.BackendStateActive
		if entry.backend.Terminating {
			state = loadbalancer.BackendStateTerminating
		}
		be := BackendParams{
			L3n4Addr:  l3n4Addr,
			NodeName:  entry.backend.NodeName,
			PortNames: entry.portNames,
			Weight:    loadbalancer.DefaultBackendWeight,
			State:     state,
		}
		out = append(out, be)
	}
	return
}

// hostPortServiceNamePrefix returns the common prefix for synthetic HostPort services
// for the pod with the given name. This prefix is used as-is when cleaning up existing
// HostPort entries for a pod. This handles the pod recreation where name stays but UID
// changes, which we might see only as an update without any deletion.
func hostPortServiceNamePrefix(pod *slim_corev1.Pod) loadbalancer.ServiceName {
	return loadbalancer.ServiceName{
		Name:      fmt.Sprintf("%s:host-port:", pod.ObjectMeta.Name),
		Namespace: pod.ObjectMeta.Namespace,
	}
}

func upsertHostPort(netnsCookie HaveNetNSCookieSupport, extConfig ExternalConfig, log *slog.Logger, wtxn WriteTxn, writer *Writer, pod *slim_corev1.Pod) error {
	podIPs := k8sUtils.ValidIPs(pod.Status)
	containers := slices.Concat(pod.Spec.InitContainers, pod.Spec.Containers)
	serviceNamePrefix := hostPortServiceNamePrefix(pod)

	updatedServices := sets.New[loadbalancer.ServiceName]()
	for _, c := range containers {
		for _, p := range c.Ports {
			if p.HostPort <= 0 {
				continue
			}

			if uint16(p.HostPort) >= extConfig.NodePortMin &&
				uint16(p.HostPort) <= extConfig.NodePortMax {
				log.Warn("The requested hostPort is colliding with the configured NodePort range. Ignoring.",
					logfields.HostPort, p.HostPort,
					logfields.NodePortMin, extConfig.NodePortMin,
					logfields.NodePortMax, extConfig.NodePortMax,
				)
				continue
			}

			proto, err := loadbalancer.NewL4Type(string(p.Protocol))
			if err != nil {
				continue
			}

			// HostPort service names are of form:
			// <namespace>/<name>:host-port:<port>:<uid>.
			serviceName := serviceNamePrefix
			serviceName.Name += fmt.Sprintf("%d:%s",
				p.HostPort,
				pod.ObjectMeta.UID)

			var ipv4, ipv6 bool

			// Construct the backends from the pod IPs and container ports.
			var bes []BackendParams
			for _, podIP := range podIPs {
				addr, err := cmtypes.ParseAddrCluster(podIP)
				if err != nil {
					log.Warn("Invalid Pod IP address. Ignoring.", logfields.IPAddr, podIP)
					continue
				}
				if (!extConfig.EnableIPv6 && addr.Is6()) || (!extConfig.EnableIPv4 && addr.Is4()) {
					continue
				}
				ipv4 = ipv4 || addr.Is4()
				ipv6 = ipv6 || addr.Is6()

				bep := BackendParams{
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: addr,
						L4Addr: loadbalancer.L4Addr{
							Protocol: proto,
							Port:     uint16(p.ContainerPort),
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				}
				bes = append(bes, bep)
			}

			loopbackHostport := false

			feIP := net.ParseIP(p.HostIP)
			if feIP != nil && feIP.IsLoopback() && !netnsCookie() {
				log.Warn("The requested loopback address for hostIP is not supported for kernels which don't provide netns cookies. Ignoring.",
					logfields.HostIP, feIP)
				continue
			}

			feIPs := []net.IP{}

			// When HostIP is explicitly set, then we need to expose *only*
			// on this address but not via other addresses. When it's not set,
			// then expose via all local addresses. Same when the user provides
			// an unspecified address (0.0.0.0 / [::]).
			if feIP != nil && !feIP.IsUnspecified() {
				// Migrate the loopback address into a 0.0.0.0 / [::]
				// surrogate, thus internal datapath handling can be
				// streamlined. It's not exposed for traffic from outside.
				if feIP.IsLoopback() {
					if feIP.To4() != nil {
						feIP = net.IPv4zero
					} else {
						feIP = net.IPv6zero
					}
					loopbackHostport = true
				}
				feIPs = append(feIPs, feIP)
			} else if feIP == nil {
				if ipv4 {
					feIPs = append(feIPs, net.IPv4zero)
				}
				if ipv6 {
					feIPs = append(feIPs, net.IPv6zero)
				}
			}

			fes := make([]FrontendParams, 0, len(feIPs))

			for _, feIP := range feIPs {
				addr := cmtypes.MustAddrClusterFromIP(feIP)
				fe := FrontendParams{
					Type:        loadbalancer.SVCTypeHostPort,
					ServiceName: serviceName,
					Address: loadbalancer.L3n4Addr{
						AddrCluster: addr,
						L4Addr: loadbalancer.L4Addr{
							Protocol: proto,
							Port:     uint16(p.HostPort),
						},
						Scope: loadbalancer.ScopeExternal,
					},
					ServicePort: uint16(p.HostPort),
				}
				fes = append(fes, fe)
			}

			svc := &Service{
				ExtTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
				IntTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
				Name:             serviceName,
				LoopbackHostPort: loopbackHostport,
				Source:           source.Kubernetes,
			}

			err = writer.UpsertServiceAndFrontends(wtxn, svc, fes...)
			if err != nil {
				return fmt.Errorf("UpsertServiceAndFrontends: %w", err)
			}
			if err := writer.SetBackends(wtxn, serviceName, source.Kubernetes, bes...); err != nil {
				return fmt.Errorf("SetBackends: %w", err)
			}

			updatedServices.Insert(serviceName)
		}
	}

	// Find and remove orphaned HostPort services, frontends and backends
	// if 'HostPort' has changed or has been unset.
	for svc := range writer.Services().Prefix(wtxn, ServiceByName(serviceNamePrefix)) {
		if updatedServices.Has(svc.Name) {
			continue
		}

		err := writer.DeleteBackendsOfService(wtxn, svc.Name, source.Kubernetes)
		if err != nil {
			return fmt.Errorf("DeleteBackendsOfService: %w", err)
		}

		err = writer.DeleteServiceAndFrontends(wtxn, svc.Name)
		if err != nil {
			return fmt.Errorf("DeleteServiceAndFrontends: %w", err)
		}
	}

	return nil
}

func deleteHostPort(params reflectorParams, wtxn WriteTxn, pod *slim_corev1.Pod) error {
	serviceNamePrefix := hostPortServiceNamePrefix(pod)
	for svc := range params.Writer.Services().Prefix(wtxn, ServiceByName(serviceNamePrefix)) {
		err := params.Writer.DeleteBackendsOfService(wtxn, svc.Name, source.Kubernetes)
		if err != nil {
			return fmt.Errorf("DeleteBackendsOfService: %w", err)
		}
		err = params.Writer.DeleteServiceAndFrontends(wtxn, svc.Name)
		if err != nil {
			return fmt.Errorf("DeleteServiceAndFrontends: %w", err)
		}
	}
	return nil
}

func bufferEvent[Obj runtime.Object](buf map[resource.Key]resource.Event[Obj], ev resource.Event[Obj]) map[resource.Key]resource.Event[Obj] {
	if buf == nil {
		buf = map[resource.Key]resource.Event[Obj]{}
	}
	ev.Done(nil)
	buf[ev.Key] = ev
	return buf
}

func bufferPod(buf map[types.NamespacedName]statedb.Change[daemonK8s.LocalPod], change statedb.Change[daemonK8s.LocalPod]) map[types.NamespacedName]statedb.Change[daemonK8s.LocalPod] {
	if buf == nil {
		buf = map[types.NamespacedName]statedb.Change[daemonK8s.LocalPod]{}
	}
	pod := change.Object
	buf[types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}] = change
	return buf
}

type HaveNetNSCookieSupport func() bool

func netnsCookieSupportFunc() HaveNetNSCookieSupport {
	return sync.OnceValue(func() bool {
		_, err := netns.GetNetNSCookie()
		return !errors.Is(err, unix.ENOPROTOOPT)
	})
}
