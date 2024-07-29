// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package experimental

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"sort"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/stream"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

// ReflectorCell reflects Kubernetes Service and EndpointSlice objects to the
// load-balancing tables.
//
// Note that this implementation uses Resource[*Service] and Resource[*Endpoints],
// which is not the desired end-game as we'll hold onto the same data multiple
// times. We should instead have a reflector that is built directly on the client-go
// reflector and not populate an intermediate cache.Store. But as we're still experimenting
// it's easier to build on what already exists.
//
// FIXME: "Reflector" naming doesn't work so nicely. Switch to calling these "data sources"?
// Also should the "RegisterInitializer" be separate, or should we register a data source and
// get back a handle? E.g. is it too easy to miss that "RegisterInitializer" is required?
var ReflectorCell = cell.Module(
	"reflector",
	"Reflects load-balancing state from Kubernetes",

	cell.Invoke(registerK8sReflector),
)

type reflectorParams struct {
	cell.In

	Log               *slog.Logger
	Lifecycle         cell.Lifecycle
	JobGroup          job.Group
	ServicesResource  stream.Observable[resource.Event[*slim_corev1.Service]]
	EndpointsResource stream.Observable[resource.Event[*k8s.Endpoints]]
	PodsResource      stream.Observable[resource.Event[*slim_corev1.Pod]]
	Writer            *Writer
}

func registerK8sReflector(p reflectorParams) {
	if !p.Writer.IsEnabled() {
		return
	}
	initComplete := p.Writer.RegisterInitializer("k8s")
	p.JobGroup.Add(job.OneShot("reflector", func(ctx context.Context, health cell.Health) error {
		runResourceReflector(ctx, p, initComplete)
		return nil
	}))
}

func runResourceReflector(ctx context.Context, p reflectorParams, initComplete func(WriteTxn)) {
	// Buffer the events to commit in larger write transactions.
	svcEvents := stream.ToChannel(ctx,
		stream.Buffer(
			p.ServicesResource,
			300,                 // buffer size
			10*time.Millisecond, // wait time
			bufferEvent[*slim_corev1.Service],
		),
	)
	epEvents := stream.ToChannel(
		ctx,
		stream.Buffer(
			p.EndpointsResource,
			300,                 // buffer size
			10*time.Millisecond, // wait time
			bufferEvent[*k8s.Endpoints],
		),
	)
	podEvents := stream.ToChannel(
		ctx,
		stream.Buffer(
			p.PodsResource,
			300,                 // buffer size
			10*time.Millisecond, // wait time
			bufferEvent[*slim_corev1.Pod],
		),
	)

	// Keep track of currently existing backends by endpoint slice.
	currentBackends := map[string]sets.Set[loadbalancer.L3n4Addr]{}

	remainingSyncs := 3
	markSync := func(txn WriteTxn) {
		remainingSyncs--
		if remainingSyncs == 0 {
			initComplete(txn)
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
			for range podEvents {
			}
			return
		case buf, ok := <-svcEvents:
			if !ok {
				continue
			}
			txn := p.Writer.WriteTxn()
			for _, ev := range buf {
				ev.Done(nil)

				obj := ev.Object
				switch ev.Kind {
				case resource.Sync:
					markSync(txn)

				case resource.Upsert:
					svc, fes := convertService(obj)
					if svc == nil {
						continue
					}
					if err := p.Writer.UpsertServiceAndFrontends(txn, svc, fes...); err != nil {
						// NOTE: Opting to panic on these failures for now to catch issues early.
						// The production version of this needs to handle potential validation or
						// conflict issues correctly.
						panic(fmt.Sprintf("FIXME: UpsertServiceAndFrontends failed: %s", err))
					}
				case resource.Delete:
					name := loadbalancer.ServiceName{Namespace: obj.Namespace, Name: obj.Name}
					if err := p.Writer.DeleteServiceAndFrontends(txn, name); err != nil {
						// NOTE: Opting to panic on these failures for now to catch issues early.
						// The production version of this needs to handle potential validation or
						// conflict issues correctly.
						panic(fmt.Sprintf("FIXME: DeleteServiceAndFrontends failed: %s", err))
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
				ev.Done(nil)

				obj := ev.Object
				switch ev.Kind {
				case resource.Sync:
					markSync(txn)
				case resource.Upsert:
					name, backends := convertEndpoints(obj)

					if len(backends) > 0 {
						err := p.Writer.UpsertBackends(
							txn,
							name,
							source.Kubernetes,
							backends...)

						if err != nil {
							// NOTE: Opting to panic on these failures for now to catch issues early.
							// The production version of this needs to handle potential validation or
							// conflict issues correctly.
							panic(fmt.Sprintf("FIXME: UpsertBackends failed: %s", err))
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

				case resource.Delete:
					// Release the backends created before.
					name := loadbalancer.ServiceName{
						Name:      obj.ServiceID.Name,
						Namespace: obj.ServiceID.Namespace,
					}
					for be := range currentBackends[obj.EndpointSliceName] {
						p.Writer.ReleaseBackend(txn, name, be)
					}
				}
			}
			txn.Commit()

		case buf, ok := <-podEvents:
			if !ok {
				continue
			}

			txn := p.Writer.WriteTxn()
			for _, ev := range buf {
				ev.Done(nil)
				obj := ev.Object
				switch ev.Kind {
				case resource.Sync:
					markSync(txn)
				case resource.Upsert:
					if err := upsertHostPort(p, txn, obj); err != nil {
						panic(err)
					}

				case resource.Delete:
					if err := deleteHostPort(p, txn, obj); err != nil {
						panic(err)
					}
				}
			}
			txn.Commit()
		}
	}
}

var (
	zeroV4 = cmtypes.MustParseAddrCluster("0.0.0.0")
	zeroV6 = cmtypes.MustParseAddrCluster("::")
)

func convertService(svc *slim_corev1.Service) (s *Service, fes []FrontendParams) {
	if strings.ToLower(svc.Spec.ClusterIP) == "none" {
		// Skip headless services
		return
	}

	name := loadbalancer.ServiceName{Namespace: svc.Namespace, Name: svc.Name}
	s = &Service{
		Name:                name,
		Source:              source.Kubernetes,
		Labels:              labels.Map2Labels(svc.Labels, string(source.Kubernetes)),
		Annotations:         svc.Annotations,
		HealthCheckNodePort: uint16(svc.Spec.HealthCheckNodePort),
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

	// ClusterIP
	clusterIPs := sets.New(svc.Spec.ClusterIPs...)
	if svc.Spec.ClusterIP != "" {
		clusterIPs.Insert(svc.Spec.ClusterIP)
	}
	for ip := range clusterIPs {
		addr, err := cmtypes.ParseAddrCluster(ip)
		if err != nil {
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
			}
			fe.Address.AddrCluster = addr
			fe.Address.Scope = loadbalancer.ScopeExternal
			fe.Address.L4Addr = *p
			fes = append(fes, fe)
		}
	}

	// NodePort
	if svc.Spec.Type == slim_corev1.ServiceTypeNodePort {
		for _, scope := range scopes {
			for _, family := range svc.Spec.IPFamilies {
				for _, port := range svc.Spec.Ports {
					fe := FrontendParams{
						Type:        loadbalancer.SVCTypeNodePort,
						PortName:    loadbalancer.FEPortName(port.Name),
						ServiceName: name,
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

			for _, scope := range scopes {
				for _, port := range svc.Spec.Ports {
					fe := FrontendParams{
						Type:        loadbalancer.SVCTypeLoadBalancer,
						PortName:    loadbalancer.FEPortName(port.Name),
						ServiceName: name,
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

		for _, port := range svc.Spec.Ports {
			fe := FrontendParams{
				Type:        loadbalancer.SVCTypeExternalIPs,
				PortName:    loadbalancer.FEPortName(port.Name),
				ServiceName: name,
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

	// Sort the frontends by their address for stable ordering.
	sort.Slice(
		fes,
		func(i, j int) bool {
			return fes[i].Address.AddrCluster.Addr().Less(
				fes[j].Address.AddrCluster.Addr())
		})

	return
}

func convertEndpoints(ep *k8s.Endpoints) (name loadbalancer.ServiceName, out []BackendParams) {
	name = loadbalancer.ServiceName{
		Name:      ep.ServiceID.Name,
		Namespace: ep.ServiceID.Namespace,
	}
	for addrCluster, be := range ep.Backends {
		for portName, l4Addr := range be.Ports {
			l3n4Addr := loadbalancer.L3n4Addr{
				AddrCluster: addrCluster,
				L4Addr:      *l4Addr,
			}
			state := loadbalancer.BackendStateActive
			if be.Terminating {
				state = loadbalancer.BackendStateTerminating
			}
			be := BackendParams{
				L3n4Addr: l3n4Addr,
				NodeName: be.NodeName,
				PortName: portName,
				Weight:   loadbalancer.DefaultBackendWeight,
				State:    state,
			}
			out = append(out, be)
		}
	}
	return
}

func netnsCookieSupported() bool {
	// FIXME get implementation from watchers/pod.go or expose features in a some other way.
	return true
}

func upsertHostPort(params reflectorParams, wtxn WriteTxn, pod *slim_corev1.Pod) error {
	// FIXME: Remove orphaned backends (old pod IPs!). Instead of "UpsertBackends" could have
	// "SetBackends" that specifies the complete set of backends for a service (from a specific source).

	podIPs := k8sUtils.ValidIPs(pod.Status)
	containers := slices.Concat(pod.Spec.InitContainers, pod.Spec.Containers)

	updatedServices := sets.New[loadbalancer.ServiceName]()
	for _, c := range containers {
		for _, p := range c.Ports {
			if p.HostPort <= 0 {
				continue
			}

			if int(p.HostPort) >= option.Config.NodePortMin &&
				int(p.HostPort) <= option.Config.NodePortMax {
				params.Log.Warn("The requested hostPort is colliding with the configured NodePort range. Ignoring.",
					"HostPort", p.HostPort, "NodePortMin", option.Config.NodePortMin, "NodePortMax", option.Config.NodePortMax)
				continue
			}

			proto, err := loadbalancer.NewL4Type(string(p.Protocol))
			if err != nil {
				continue
			}

			serviceName := loadbalancer.ServiceName{
				Name:      fmt.Sprintf("%s/host-port/%d", pod.ObjectMeta.Name, p.HostPort),
				Namespace: pod.ObjectMeta.Namespace,
			}

			// Collect the set of old backends to clean up later.
			oldBackends := map[loadbalancer.L3n4Addr]*Backend{}
			iter := params.Writer.Backends().List(wtxn, BackendByServiceName(serviceName))
			for be, _, ok := iter.Next(); ok; be, _, ok = iter.Next() {
				oldBackends[be.L3n4Addr] = be
			}

			var ipv4, ipv6 bool

			// Construct the backends from the pod IPs and container ports.
			var bes []BackendParams
			for _, podIP := range podIPs {
				addr, err := cmtypes.ParseAddrCluster(podIP)
				if err != nil {
					params.Log.Warn("Invalid Pod IP address. Ignoring.", "ip", podIP)
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
				}
				bes = append(bes, bep)

				// Remove this from the set of old backends so we don't clean it up.
				delete(oldBackends, bep.L3n4Addr)
			}

			// Insert the new set of backends.
			err = params.Writer.UpsertBackends(wtxn, serviceName, source.Kubernetes, bes...)
			if err != nil {
				return fmt.Errorf("UpsertBackends: %w", err)
			}

			// Release the orphaned backends.
			for addr := range oldBackends {
				params.Writer.ReleaseBackend(wtxn, serviceName, addr)
			}

			loopbackHostport := false

			feIP := net.ParseIP(p.HostIP)
			if feIP != nil && feIP.IsLoopback() && !netnsCookieSupported() {
				params.Log.Warn("The requested loopback address for hostIP is not supported for kernels which don't provide netns cookies. Ignoring.",
					"hostIP", feIP)
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

			svc := &Service{
				ExtTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
				IntTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
				Name:             serviceName,
				LoopbackHostPort: loopbackHostport,
				Source:           source.Kubernetes,
			}
			_, err = params.Writer.UpsertService(wtxn, svc)
			if err != nil {
				return fmt.Errorf("UpsertService: %w", err)
			}
			if err := params.Writer.UpsertBackends(wtxn, serviceName, source.Kubernetes, bes...); err != nil {
				return fmt.Errorf("UpsertBackends: %w", err)
			}

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
				}
				if _, err := params.Writer.UpsertFrontend(wtxn, fe); err != nil {
					return fmt.Errorf("UpsertFrontend: %w", err)
				}
			}
			updatedServices.Insert(serviceName)
		}
	}

	// Find and remove orphaned HostPort services, frontends and backends.
	serviceNamePrefix := loadbalancer.ServiceName{
		Name:      pod.ObjectMeta.Name + "/host-port/",
		Namespace: pod.ObjectMeta.Namespace,
	}
	iter := params.Writer.Services().Prefix(wtxn, ServiceByName(serviceNamePrefix))
	for svc, _, ok := iter.Next(); ok; svc, _, ok = iter.Next() {
		if updatedServices.Has(svc.Name) {
			continue
		}

		// Delete this orphaned service and associated frontends. The backends will be removed
		// when they become unreferenced.
		err := params.Writer.DeleteServiceAndFrontends(wtxn, svc.Name)
		if err != nil {
			return fmt.Errorf("DeleteServiceAndFrontends: %w", err)
		}
	}

	return nil
}

func deleteHostPort(params reflectorParams, wtxn WriteTxn, pod *slim_corev1.Pod) error {
	serviceNamePrefix := loadbalancer.ServiceName{
		Name:      pod.ObjectMeta.Name + "/host-port/",
		Namespace: pod.ObjectMeta.Namespace,
	}
	iter := params.Writer.Services().Prefix(wtxn, ServiceByName(serviceNamePrefix))
	for svc, _, ok := iter.Next(); ok; svc, _, ok = iter.Next() {
		// Delete this orphaned servicea and associated frontends. The backends will be removed
		// when they become unreferenced.
		err := params.Writer.DeleteServiceAndFrontends(wtxn, svc.Name)
		if err != nil {
			return fmt.Errorf("DeleteServiceAndFrontends: %w", err)
		}
	}
	return nil
}

func bufferEvent[Obj runtime.Object](buf map[resource.Key]resource.Event[Obj], ev resource.Event[Obj]) map[resource.Key]resource.Event[Obj] {
	if ev.Kind == resource.Sync {
		ev.Done(nil)
		return buf
	}
	if buf == nil {
		buf = map[resource.Key]resource.Event[Obj]{}
	}

	if ev, ok := buf[ev.Key]; ok {
		ev.Done(nil)
	}
	buf[ev.Key] = ev
	return buf
}
