// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package experimental

import (
	"context"
	"fmt"
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
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
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
var ReflectorCell = cell.Module(
	"reflector",
	"Kubernetes services reflector",

	cell.Invoke(registerK8sReflector),
)

type reflectorParams struct {
	cell.In

	Lifecycle         cell.Lifecycle
	JobGroup          job.Group
	ServicesResource  resource.Resource[*slim_corev1.Service]
	EndpointsResource resource.Resource[*k8s.Endpoints]
	Writer            *Writer
}

func registerK8sReflector(p reflectorParams) {
	if !p.Writer.IsEnabled() {
		return
	}
	p.JobGroup.Add(job.OneShot("reflector", func(ctx context.Context, health cell.Health) error {
		runResourceReflector(ctx, p.ServicesResource, p.EndpointsResource, p.Writer)
		return nil
	}))
}

func runResourceReflector(ctx context.Context, svcR resource.Resource[*slim_corev1.Service], epR resource.Resource[*k8s.Endpoints], svcs *Writer) {
	// Buffer the events to commit in larger write transactions.
	svcEvents := stream.ToChannel(ctx,
		stream.Buffer(
			svcR,
			300,                 // buffer size
			10*time.Millisecond, // wait time
			bufferEvent[*slim_corev1.Service],
		),
	)
	epEvents := stream.ToChannel(
		ctx,
		stream.Buffer(
			epR,
			300,                 // buffer size
			10*time.Millisecond, // wait time
			bufferEvent[*k8s.Endpoints],
		),
	)

	// Keep track of currently existing backends by endpoint slice.
	currentBackends := map[string]sets.Set[loadbalancer.L3n4Addr]{}

	for svcEvents != nil || epEvents != nil {
		select {
		case buf, ok := <-svcEvents:
			if !ok {
				svcEvents = nil
				continue
			}
			txn := svcs.WriteTxn()
			for _, ev := range buf {
				ev.Done(nil)

				obj := ev.Object
				switch ev.Kind {
				case resource.Upsert:
					svc, fes := convertService(obj)
					if svc == nil {
						continue
					}
					if err := svcs.UpsertServiceAndFrontends(txn, svc, fes...); err != nil {
						// NOTE: Opting to panic on these failures for now to catch issues early.
						// The production version of this needs to handle potential validation or
						// conflict issues correctly.
						panic(fmt.Sprintf("FIXME: UpsertServiceAndFrontends failed: %s", err))
					}
				case resource.Delete:
					name := loadbalancer.ServiceName{Namespace: obj.Namespace, Name: obj.Name}
					if err := svcs.DeleteServiceAndFrontends(txn, name); err != nil {
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
				epEvents = nil
				continue
			}

			txn := svcs.WriteTxn()
			for _, ev := range buf {
				ev.Done(nil)

				obj := ev.Object
				switch ev.Kind {
				case resource.Upsert:
					name, backends := convertEndpoints(obj)

					old := currentBackends[obj.EndpointSliceName]

					err := svcs.UpsertBackends(
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
					// Release orphaned backends
					newAddrs := sets.New[loadbalancer.L3n4Addr]()
					for _, be := range backends {
						newAddrs.Insert(be.L3n4Addr)
					}
					for orphan := range old.Difference(newAddrs) {
						svcs.ReleaseBackend(txn, name, orphan)
					}
					currentBackends[obj.EndpointSliceName] = newAddrs

				case resource.Delete:
					name, backends := convertEndpoints(obj)
					for _, p := range backends {
						err := svcs.ReleaseBackend(
							txn,
							name,
							p.L3n4Addr,
						)
						if err != nil {
							// NOTE: Opting to panic on these failures for now to catch issues early.
							// The production version of this needs to handle potential validation or
							// conflict issues correctly.
							panic(fmt.Sprintf("FIXME: ReleaseBackend failed: %s", err))
						}
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

func convertService(svc *slim_corev1.Service) (s *Service, fes []*Frontend) {
	if strings.ToLower(svc.Spec.ClusterIP) == "none" {
		// Skip headless services
		return
	}

	name := loadbalancer.ServiceName{Namespace: svc.Namespace, Name: svc.Name}
	s = &Service{
		Name:   name,
		Source: source.Kubernetes,
		Labels: labels.Map2Labels(svc.Labels, string(source.Kubernetes)),
	}

	// NOTE: Omitted handling of ScopeInternal.
	scopes := []uint8{loadbalancer.ScopeExternal}

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
			fe := &Frontend{
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
					fe := &Frontend{
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
					fe := &Frontend{
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

		for _, scope := range scopes {
			for _, port := range svc.Spec.Ports {
				fe := &Frontend{
					Type:        loadbalancer.SVCTypeExternalIPs,
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

	return
}

func convertEndpoints(ep *k8s.Endpoints) (name loadbalancer.ServiceName, out []*loadbalancer.Backend) {
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
			be := &loadbalancer.Backend{
				L3n4Addr:   l3n4Addr,
				NodeName:   be.NodeName,
				FEPortName: portName,
				Weight:     loadbalancer.DefaultBackendWeight,
				State:      state,
			}
			out = append(out, be)
		}
	}
	return
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
