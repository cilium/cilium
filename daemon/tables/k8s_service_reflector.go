package tables

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/stream"

	"github.com/cilium/cilium/pkg/k8s"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_discovery_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/statedb/reflector"
)

var K8sReflectorCell = cell.Invoke(registerK8sReflector)

type reflectorParams struct {
	cell.In

	Scope             cell.Scope
	Lifecycle         cell.Lifecycle
	Jobs              job.Registry
	ServicesResource  resource.Resource[*slim_corev1.Service]
	EndpointsResource resource.Resource[*k8s.Endpoints]
	Services          *Services
}

func registerK8sReflector(p reflectorParams) error {
	if p.ServicesResource == nil {
		return nil
	}

	g := p.Jobs.NewGroup(p.Scope)
	g.Add(job.OneShot("reflector", func(ctx context.Context, health cell.HealthReporter) error {
		runResourceReflector(ctx, p.ServicesResource, p.EndpointsResource, p.Services)
		return nil
	}))
	p.Lifecycle.Append(g)
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

func runResourceReflector(ctx context.Context, svcR resource.Resource[*slim_corev1.Service], epR resource.Resource[*k8s.Endpoints], svcs *Services) {
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
				obj := ev.Object
				switch ev.Kind {
				case resource.Upsert:
					name := loadbalancer.ServiceName{Namespace: obj.Namespace, Name: obj.Name}
					var err error
					for _, svc := range toServiceParams(obj) {
						err = svcs.UpsertService(txn, name, svc)
						if err != nil {
							// TODO: how to resolve conflicts when the same service or frontend address
							// is added from different sources? do we retry, give up or update Service.Status?
							// Or should *Service be designed to allow overlaps by merging them ("shadowed services")?
							fmt.Printf("error with name %s, %#v: %s\n", name, svc, err)
							break
						}
					}
					ev.Done(err) // This keeps retrying forever in case of conflicts. Probably not what we want.
				case resource.Delete:
					name := loadbalancer.ServiceName{Namespace: obj.Namespace, Name: obj.Name}
					// FIXME: only need to parse out the addresses
					for _, p := range toServiceParams(obj) {
						err := svcs.DeleteService(txn, name, p.L3n4Addr)
						if err != nil {
							panic(err)
						}
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
				obj := ev.Object
				switch ev.Kind {
				case resource.Upsert:
					name, backends := endpointsToBackendParams(obj)

					old := currentBackends[obj.EndpointSliceName]

					err := svcs.UpsertBackends(
						txn,
						name,
						backends...)

					if err == nil {
						// Delete orphaned backends
						newAddrs := sets.New[loadbalancer.L3n4Addr]()
						for _, be := range backends {
							newAddrs.Insert(be.L3n4Addr)
						}
						for orphan := range old.Difference(newAddrs) {
							svcs.DeleteBackend(txn, name, orphan)
						}
						currentBackends[obj.EndpointSliceName] = newAddrs
					}

					ev.Done(err) // This keeps retrying forever in case of conflicts. Probably not what we want.
				case resource.Delete:
					// FIXME delete by owner. Or should we keep the state here to figure out which backends are
					// gone when the endpoint slice changes? The "owner" ("EndpointSliceName") notion doesn't really
					// translate to e.g. REST API.
					name, backends := endpointsToBackendParams(obj)
					var err error
					for _, p := range backends {
						err := svcs.DeleteBackend(
							txn,
							name,
							p.L3n4Addr,
						)
						if err != nil {
							break
						}
					}
					ev.Done(err) // This keeps retrying forever in case of conflicts. Probably not what we want.
				}
			}
			txn.Commit()

		}
	}

}

// startK8sReflector_EventObservable reflects services and endpoints from api-server into the service and backend
// tables without the intermediate cache.Store by directly hooking into the stream of events from client-go's
// Reflector.
//
// This is the end-goal as it's more resource efficient, but for now we have many uses of Resource[*Service] and
// Resource[*Endpoints], so this will have to wait.
//
// Still TBD here is to batch things up in order to commit multiple objects in one go.
func startK8sReflector_EventObservable(ctx context.Context, c client.Clientset, s *Services, wg *sync.WaitGroup) {
	// TODO consider doing a typed version of K8sEventObservable that also emits stuff
	// in batches, so that things like this are easier to do.
	services := reflector.K8sEventObservable(utils.ListerWatcherFromTyped(c.Slim().CoreV1().Services("")))
	endpointSlices := reflector.K8sEventObservable(utils.ListerWatcherFromTyped(c.Slim().DiscoveryV1().EndpointSlices("")))

	wg.Add(2)
	services.Observe(
		ctx,
		func(ev reflector.CacheStoreEvent) {
			txn := s.WriteTxn()
			// TODO commit in larger batches by using stream.Buffer
			defer txn.Commit()
			switch ev.Type {
			case reflector.CacheStoreAdd:
				fallthrough
			case reflector.CacheStoreUpdate:
				obj := ev.Obj.(*slim_corev1.Service)
				name := loadbalancer.ServiceName{Namespace: obj.Namespace, Name: obj.Name}
				svcs := toServiceParams(obj)
				for _, svc := range svcs {
					err := s.UpsertService(txn, name, svc)
					if err != nil {
						// TODO: how to resolve conflicts when the same service or frontend address
						// is added from different sources? do we retry, give up or update Service.Status?
						// Or should *Service be designed to allow overlaps by merging them ("shadowed services")?
						fmt.Printf("error with name %s, %#v: %s\n", name, svc, err)
						//panic(err)
					}
				}
			case reflector.CacheStoreDelete:
				svc := ev.Obj.(*slim_corev1.Service)

				name := loadbalancer.ServiceName{Namespace: svc.Namespace, Name: svc.Name}
				for _, p := range toServiceParams(svc) {
					err := s.DeleteService(txn, name, p.L3n4Addr)
					if err != nil {
						panic(err)
					}
				}

			case reflector.CacheStoreReplace:
				// Out-of-sync with the API server, resync by deleting all services and inserting the initial
				// set.
				s.DeleteServicesBySource(txn, source.Kubernetes)
				svcs := ev.Obj.([]any)
				for _, obj := range svcs {
					svc := obj.(*slim_corev1.Service)
					name := loadbalancer.ServiceName{Namespace: svc.Namespace, Name: svc.Name}
					for _, p := range toServiceParams(svc) {
						err := s.UpsertService(txn, name, p)
						if err != nil {
							// TODO: how to handle
							fmt.Printf("error with name %s, %#v: %s\n", name, p, err)
							//panic(err)
						}
					}
				}
			}

		},
		func(error) { wg.Done() },
	)

	endpointSlices.Observe(
		ctx,
		func(ev reflector.CacheStoreEvent) {
			txn := s.WriteTxn()
			// TODO commit in larger batches by using stream.Buffer
			defer txn.Commit()
			switch ev.Type {
			case reflector.CacheStoreAdd:
				fallthrough
			case reflector.CacheStoreUpdate:
				eps := ev.Obj.(*slim_discovery_v1.EndpointSlice)

				name, backends := endpointSliceToBackendParams(eps)
				fmt.Printf("endpoint slice updated for %q: %v\n", name, backends)

				// FIXME need to keep track of the backends here
				// so we know when to delete them when the EndpointSlice doesn't
				// refer to them anymore.

				err := s.UpsertBackends(
					txn,
					name,
					backends...)
				if err != nil {
					panic(err)
				}
			case reflector.CacheStoreDelete:
				eps := ev.Obj.(*slim_discovery_v1.EndpointSlice)
				name, backends := endpointSliceToBackendParams(eps)
				for _, p := range backends {
					s.DeleteBackend(
						txn,
						name,
						p.L3n4Addr,
					)
				}

			case reflector.CacheStoreReplace:
				// Out-of-sync with the API server, resync.
				s.DeleteBackendsBySource(txn, source.Kubernetes)
				epss := ev.Obj.([]any)
				for _, obj := range epss {
					eps := obj.(*slim_discovery_v1.EndpointSlice)
					name, backends := endpointSliceToBackendParams(eps)
					err := s.UpsertBackends(
						txn,
						name,
						backends...)
					if err != nil {
						fmt.Printf("error with upsert backend: %s: %s\n", name, err)
						//panic(err)
					}
				}
			}

		},
		func(error) { wg.Done() },
	)

}

func toServiceParams(svc *slim_corev1.Service) (out []*ServiceParams) {
	if strings.ToLower(svc.Spec.ClusterIP) == "none" {
		// Skip headless services (TODO do we need them anywhere? addK8sSVCs skips them)
		return
	}

	// Set the common properties.
	common := ServiceParams{
		Labels: labels.Map2Labels(svc.Labels, labels.LabelSourceK8s),
		Source: source.Kubernetes,
		// TODO: HealthCheckNodePort, SessionAffinity, SourceRanges
	}

	switch svc.Spec.ExternalTrafficPolicy {
	case slim_corev1.ServiceExternalTrafficPolicyLocal:
		common.ExtPolicy = loadbalancer.SVCTrafficPolicyLocal
	default:
		common.ExtPolicy = loadbalancer.SVCTrafficPolicyCluster
	}
	if svc.Spec.InternalTrafficPolicy != nil && *svc.Spec.InternalTrafficPolicy == slim_corev1.ServiceInternalTrafficPolicyLocal {
		common.IntPolicy = loadbalancer.SVCTrafficPolicyLocal
	} else {
		common.IntPolicy = loadbalancer.SVCTrafficPolicyCluster
	}

	// ClusterIP
	clusterIPs := sets.New[string](svc.Spec.ClusterIPs...)
	if svc.Spec.ClusterIP != "" {
		clusterIPs.Insert(svc.Spec.ClusterIP)
	}
	for ip := range clusterIPs {
		addr, err := cmtypes.ParseAddrCluster(ip)
		if err != nil {
			panic(err)
			//continue
		}

		params := common
		params.Type = loadbalancer.SVCTypeClusterIP
		params.L3n4Addr.AddrCluster = addr
		params.L3n4Addr.Scope = loadbalancer.ScopeExternal

		for _, port := range svc.Spec.Ports {
			params := params
			p := loadbalancer.NewL4Addr(loadbalancer.L4Type(port.Protocol), uint16(port.Port))
			if p == nil {
				panic(fmt.Sprintf("L4Addr parse of %v failed", port))
				//continue
			}
			params.L3n4Addr.L4Addr = *p
			params.PortName = loadbalancer.FEPortName(port.Name)
			out = append(out, &params)
		}
	}

	// FIXME
	zeroV4 := cmtypes.MustParseAddrCluster("0.0.0.0")
	zeroV6 := cmtypes.MustParseAddrCluster("::")

	// NodePort
	if svc.Spec.Type == slim_corev1.ServiceTypeNodePort {
		scopes := []uint8{loadbalancer.ScopeExternal}
		twoScopes := (common.ExtPolicy == loadbalancer.SVCTrafficPolicyLocal) != (common.IntPolicy == loadbalancer.SVCTrafficPolicyLocal)
		if twoScopes {
			scopes = append(scopes, loadbalancer.ScopeInternal)
		}

		for _, scope := range scopes {
			for _, family := range svc.Spec.IPFamilies {
				params := common
				switch family {
				case slim_corev1.IPv4Protocol:
					params.L3n4Addr.AddrCluster = zeroV4
				case slim_corev1.IPv6Protocol:
					params.L3n4Addr.AddrCluster = zeroV6
				default:
					continue
				}
				params.L3n4Addr.Scope = scope
				params.Type = loadbalancer.SVCTypeNodePort
				for _, port := range svc.Spec.Ports {
					params := params

					// FIXME proper zero value ipv4/ipv6
					p := loadbalancer.NewL4Addr(loadbalancer.L4Type(port.Protocol), uint16(port.NodePort))
					if p == nil {
						continue
					}
					params.L3n4Addr.L4Addr = *p
					params.PortName = loadbalancer.FEPortName(port.Name)
					out = append(out, &params)
				}
			}
		}
	}

	// LoadBalancer
	// ExternalIP

	return
}

func endpointsToBackendParams(ep *k8s.Endpoints) (name loadbalancer.ServiceName, out []BackendParams) {
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
			params := BackendParams{
				Source:        source.Kubernetes,
				HintsForZones: be.HintsForZones,
				Backend: loadbalancer.Backend{
					L3n4Addr:   l3n4Addr,
					NodeName:   be.NodeName,
					FEPortName: portName,
					Weight:     loadbalancer.DefaultBackendWeight,
					State:      state,
				},
			}
			out = append(out, params)
		}
	}
	return
}

func endpointSliceToBackendParams(ep *slim_discovery_v1.EndpointSlice) (name loadbalancer.ServiceName, out []BackendParams) {
	// Validate AddressType before parsing. Currently, we only support IPv4 and IPv6.
	if ep.AddressType != slim_discovery_v1.AddressTypeIPv4 &&
		ep.AddressType != slim_discovery_v1.AddressTypeIPv6 {
		return
	}

	name = loadbalancer.ServiceName{
		Name:      ep.GetLabels()[slim_discovery_v1.LabelServiceName],
		Namespace: ep.GetNamespace(),
	}

	for _, sub := range ep.Endpoints {
		// ready indicates that this endpoint is prepared to receive traffic,
		// according to whatever system is managing the endpoint. A nil value
		// indicates an unknown state. In most cases consumers should interpret this
		// unknown state as ready.
		// More info: vendor/k8s.io/api/discovery/v1/types.go
		isReady := sub.Conditions.Ready == nil || *sub.Conditions.Ready
		// serving is identical to ready except that it is set regardless of the
		// terminating state of endpoints. This condition should be set to true for
		// a ready endpoint that is terminating. If nil, consumers should defer to
		// the ready condition.
		// More info: vendor/k8s.io/api/discovery/v1/types.go
		isServing := (sub.Conditions.Serving == nil && isReady) || (sub.Conditions.Serving != nil && *sub.Conditions.Serving)
		// Terminating indicates that the endpoint is getting terminated. A
		// nil values indicates an unknown state. Ready is never true when
		// an endpoint is terminating. Propagate the terminating endpoint
		// state so that we can gracefully remove those endpoints.
		// More info: vendor/k8s.io/api/discovery/v1/types.go
		isTerminating := sub.Conditions.Terminating != nil && *sub.Conditions.Terminating

		// if is not Ready and EnableK8sTerminatingEndpoint is set
		// allow endpoints that are Serving and Terminating
		if !isReady {
			if !option.Config.EnableK8sTerminatingEndpoint {
				log.Debugf("discarding Endpoint on EndpointSlice %s: not Ready and EnableK8sTerminatingEndpoint %v", ep.Name, option.Config.EnableK8sTerminatingEndpoint)
				continue
			}
			// filter not Serving endpoints since those can not receive traffic
			if !isServing {
				log.Debugf("discarding Endpoint on EndpointSlice %s: not Serving and EnableK8sTerminatingEndpoint %v", ep.Name, option.Config.EnableK8sTerminatingEndpoint)
				continue
			}
		}

		for _, addr := range sub.Addresses {
			addrCluster, err := cmtypes.ParseAddrCluster(addr)
			if err != nil {
				continue
			}

			backend := BackendParams{
				Source: source.Kubernetes,
			}
			backend.State = loadbalancer.BackendStateActive
			backend.L3n4Addr.AddrCluster = addrCluster

			if sub.NodeName != nil {
				backend.NodeName = *sub.NodeName
			} else {
				if nodeName, ok := sub.DeprecatedTopology["kubernetes.io/hostname"]; ok {
					backend.NodeName = nodeName
				}
			}

			if sub.Hints != nil && (*sub.Hints).ForZones != nil {
				hints := (*sub.Hints).ForZones
				backend.HintsForZones = make([]string, len(hints))
				for i, hint := range hints {
					backend.HintsForZones[i] = hint.Name
				}
			}

			// If is not ready check if is serving and terminating
			if !isReady && option.Config.EnableK8sTerminatingEndpoint &&
				isServing && isTerminating {
				backend.State = loadbalancer.BackendStateTerminating
			}

			for _, port := range ep.Ports {
				name, lbPort := parseEndpointPortV1(port)
				if lbPort != nil {
					backend.FEPortName = name
					backend.L3n4Addr.L4Addr = *lbPort
					out = append(out, backend)
				}
			}

		}
	}

	return
}

// parseEndpointPortV1 returns the port name and the port parsed as a L4Addr from
// the given port.
func parseEndpointPortV1(port slim_discovery_v1.EndpointPort) (string, *loadbalancer.L4Addr) {
	proto := loadbalancer.TCP
	if port.Protocol != nil {
		switch *port.Protocol {
		case slim_corev1.ProtocolTCP:
			proto = loadbalancer.TCP
		case slim_corev1.ProtocolUDP:
			proto = loadbalancer.UDP
		case slim_corev1.ProtocolSCTP:
			proto = loadbalancer.SCTP
		default:
			return "", nil
		}
	}
	if port.Port == nil {
		return "", nil
	}
	var name string
	if port.Name != nil {
		name = *port.Name
	}
	lbPort := loadbalancer.NewL4Addr(proto, uint16(*port.Port))
	return name, lbPort
}
