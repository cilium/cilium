// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reflectors

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"maps"
	"net"
	"slices"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/stream"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"

	daemonK8s "github.com/cilium/cilium/daemon/k8s"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/container"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/loadbalancer"
	lbmaps "github.com/cilium/cilium/pkg/loadbalancer/maps"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

const (
	// reflectorBufferSize is the maximum size of the event buffer.
	reflectorBufferSize = 500

	// reflectorWaitTime is the maximum amount of time to try and fill the buffer.
	// A higher wait time will reduce processing of transient states and increases
	// throughput as it gives bigger batches downstream for processing. Batching
	// also helps to combine related objects, e.g. a Service may have multiple
	// associated EndpointSlices and preferably these would be processed together.
	reflectorWaitTime = 500 * time.Millisecond
)

// K8sReflectorCell reflects Kubernetes Service and EndpointSlice objects to the
// load-balancing tables.
//
// Note that this implementation uses Resource[*Service] and Resource[*Endpoints],
// which is not the desired end-game as we'll hold onto the same data multiple
// times. We should instead have a reflector that is built directly on the client-go
// reflector (k8s.RegisterReflector) and not populate an intermediate cache.Store.
// But as we're still experimenting it's easier to build on what already exists.
var K8sReflectorCell = cell.Module(
	"k8s-reflector",
	"Reflects load-balancing state from Kubernetes",

	// Bridge Resource[XYZ] to Observable[Event[XYZ]]. Makes it easier to
	// test [ReflectorCell].
	cell.ProvidePrivate(resourcesToStreams),
	cell.Invoke(RegisterK8sReflector),
)

type resourceIn struct {
	cell.In
	ServicesResource  resource.Resource[*slim_corev1.Service]
	EndpointsResource resource.Resource[*k8s.Endpoints]
}

type StreamsOut struct {
	cell.Out
	ServicesStream  stream.Observable[resource.Event[*slim_corev1.Service]]
	EndpointsStream stream.Observable[resource.Event[*k8s.Endpoints]]
}

// resourcesToStreams extracts the stream.Observable from resource.Resource.
// This makes the reflector easier to test as its API surface is reduced.
func resourcesToStreams(in resourceIn) StreamsOut {
	return StreamsOut{
		ServicesStream:  in.ServicesResource,
		EndpointsStream: in.EndpointsResource,
	}
}

type reflectorParams struct {
	cell.In

	DB                     *statedb.DB
	Log                    *slog.Logger
	Lifecycle              cell.Lifecycle
	JobGroup               job.Group
	ServicesResource       stream.Observable[resource.Event[*slim_corev1.Service]]
	EndpointsResource      stream.Observable[resource.Event[*k8s.Endpoints]]
	Pods                   statedb.Table[daemonK8s.LocalPod]
	Writer                 *writer.Writer
	Config                 loadbalancer.Config
	ExtConfig              loadbalancer.ExternalConfig
	HaveNetNSCookieSupport lbmaps.HaveNetNSCookieSupport
	TestConfig             *loadbalancer.TestConfig `optional:"true"`
	Nodes                  statedb.Table[*node.LocalNode]
	SVCMetrics             SVCMetrics `optional:"true"`
}

func (p reflectorParams) waitTime() time.Duration {
	if p.TestConfig != nil {
		// Use a much lower wait time in tests to trigger more edge cases and make them faster.
		return 10 * time.Millisecond
	}
	return reflectorWaitTime
}

func RegisterK8sReflector(p reflectorParams) {
	if !p.Writer.IsEnabled() || p.ServicesResource == nil {
		return
	}
	if p.SVCMetrics == nil {
		p.SVCMetrics = NewSVCMetricsNoop()
	}

	podsComplete := p.Writer.RegisterInitializer("k8s-pods")
	epsComplete := p.Writer.RegisterInitializer("k8s-endpoints")
	svcComplete := p.Writer.RegisterInitializer("k8s-services")
	p.JobGroup.Add(
		job.OneShot("reflect-services-endpoints", func(ctx context.Context, health cell.Health) error {
			return runServiceEndpointsReflector(ctx, health, p, svcComplete, epsComplete)
		}),
		job.OneShot("reflect-pods", func(ctx context.Context, health cell.Health) error {
			return runPodReflector(ctx, health, p, podsComplete)
		}),
	)
}

func runPodReflector(ctx context.Context, health cell.Health, p reflectorParams, initComplete func(writer.WriteTxn)) error {
	// Wait for pod table to be populated before proceeding.
	health.OK("Waiting for pods to be initialized")
	_, podsInitialized := p.Pods.Initialized(p.DB.ReadTxn())
	select {
	case <-ctx.Done():
		return nil
	case <-podsInitialized:
	}
	txn := p.Writer.WriteTxn()
	initComplete(txn)
	txn.Commit()

	health.OK("Running")

	rh := newReflectorHealth(health, p.Log)

	processBuffer := func(txn writer.WriteTxn, buf iter.Seq2[types.NamespacedName, statedb.Change[daemonK8s.LocalPod]]) {
		for _, change := range buf {
			obj := change.Object.Pod
			if obj.Spec.HostNetwork {
				continue
			}

			podName := obj.Namespace + "/" + obj.Name
			if change.Deleted {
				rh.update(podName, nil)
				if p.ExtConfig.KubeProxyReplacement {
					if err := deleteHostPort(p, txn, obj); err != nil {
						p.Log.Error("BUG: Unexpected failure in deleteHostPort",
							logfields.Error, err)
					}
				}
			} else {
				switch obj.Status.Phase {
				case slim_corev1.PodFailed, slim_corev1.PodSucceeded:
					// Pod has been terminated. Clean up the HostPort already even before the Pod object
					// has been removed to free up the HostPort for other pods.
					rh.update(podName, nil)
					if p.ExtConfig.KubeProxyReplacement {
						if err := deleteHostPort(p, txn, obj); err != nil {
							p.Log.Error("BUG: Unexpected failure in deleteHostPort",
								logfields.Error, err)
						}
					}
				case slim_corev1.PodRunning:
					var err error

					if obj.ObjectMeta.DeletionTimestamp != nil {
						// The pod has been marked for deletion. Stop processing HostPort changes
						// for it.
						continue
					}

					if p.ExtConfig.KubeProxyReplacement {
						err = upsertHostPort(p.HaveNetNSCookieSupport, p.Config, p.ExtConfig, p.Log, txn, p.Writer, obj)
					}
					rh.update(podName, err)
				}
			}
		}
	}

	podChanges := stream.ToChannel(
		ctx,
		stream.Buffer(
			statedb.Observable(p.DB, p.Pods),
			reflectorBufferSize,
			p.waitTime(),

			func(buf *container.InsertOrderedMap[types.NamespacedName, statedb.Change[daemonK8s.LocalPod]], change statedb.Change[daemonK8s.LocalPod]) *container.InsertOrderedMap[types.NamespacedName, statedb.Change[daemonK8s.LocalPod]] {
				if buf == nil {
					buf = container.NewInsertOrderedMap[types.NamespacedName, statedb.Change[daemonK8s.LocalPod]]()
				}
				pod := change.Object
				buf.Insert(types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}, change)
				return buf
			},
		),
	)

	for buf := range podChanges {
		txn := p.Writer.WriteTxn()
		processBuffer(txn, buf.All())
		txn.Commit()
		rh.report()
	}

	return nil
}

func runServiceEndpointsReflector(ctx context.Context, health cell.Health, p reflectorParams, initServices, initEndpoints func(writer.WriteTxn)) error {
	rh := newReflectorHealth(health, p.Log)

	processServiceEvent := func(txn writer.WriteTxn, kind resource.EventKind, obj *slim_corev1.Service) {
		switch kind {
		case resource.Sync:
			initServices(txn)

		case resource.Upsert:
			localNode, _, _ := p.Nodes.Get(txn, node.LocalNodeQuery)
			svc, fes := convertService(p.Config, p.ExtConfig, p.Log, localNode, obj, source.Kubernetes)
			if svc == nil {
				// The service should not be provisioned on this agent. Try to delete if it was previously.
				name := loadbalancer.NewServiceName(obj.Namespace, obj.Name)
				rh.update("svc:"+name.String(), nil)

				oldSvc, err := p.Writer.DeleteServiceAndFrontends(txn, name)
				if err != nil && !errors.Is(err, statedb.ErrObjectNotFound) {
					p.Log.Error("BUG: Unexpected failure in DeleteServiceAndFrontends",
						logfields.Error, err)
				}
				if oldSvc != nil {
					p.SVCMetrics.DelService(oldSvc)
				}
				return
			}
			p.SVCMetrics.AddService(svc)

			// Sort the frontends by address
			slices.SortStableFunc(fes, func(a, b loadbalancer.FrontendParams) int {
				return bytes.Compare(a.Address.Bytes(), b.Address.Bytes())
			})

			err := p.Writer.UpsertServiceAndFrontends(txn, svc, fes...)
			rh.update("svc:"+svc.Name.String(), err)

		case resource.Delete:
			name := loadbalancer.NewServiceName(obj.Namespace, obj.Name)
			rh.update("svc:"+name.String(), nil)

			svc, err := p.Writer.DeleteServiceAndFrontends(txn, name)
			if err != nil && !errors.Is(err, statedb.ErrObjectNotFound) {
				p.Log.Error("BUG: Unexpected failure in DeleteServiceAndFrontends",
					logfields.Error, err)
			}
			if svc != nil {
				p.SVCMetrics.DelService(svc)
			}
		}
	}

	currentEndpoints := map[string]endpointsEvent{}
	processEndpointsEvent := func(txn writer.WriteTxn, key bufferKey, kind resource.EventKind, allEps allEndpoints) {
		switch kind {
		case resource.Sync:
			initEndpoints(txn)

		case resource.Upsert:
			name := loadbalancer.NewServiceName(
				key.key.Namespace,
				key.key.Name,
			)
			var err error

			// Convert [k8s.Endpoints] to [loadbalancer.BackendParams]
			backends := convertEndpoints(p.Log, p.ExtConfig, name, allEps.Backends())

			// Find orphaned backends. We are using iter.Seq to avoid unnecessary allocations.
			var orphans iter.Seq[loadbalancer.L3n4Addr] = func(yield func(loadbalancer.L3n4Addr) bool) {
				for ep := range allEps.All() {
					previous, found := currentEndpoints[ep.name]
					if !found {
						continue
					}
					for addr, prevBe := range previous.backends {
						be, foundBe := ep.backends[addr]
						for l4Addr := range prevBe.Ports {
							foundPort := false
							if foundBe {
								_, foundPort = be.Ports[l4Addr]
							}
							if !foundPort {
								if !yield(
									loadbalancer.NewL3n4Addr(
										l4Addr.Protocol,
										addr,
										l4Addr.Port,
										loadbalancer.ScopeExternal,
									)) {
									return
								}
							}
						}
					}
				}
			}

			err = p.Writer.UpsertAndReleaseBackends(txn, name, source.Kubernetes, backends, orphans)

			for ep := range allEps.All() {
				if len(ep.backends) == 0 {
					delete(currentEndpoints, ep.name)
				} else {
					currentEndpoints[ep.name] = ep
				}
			}

			rh.update("eps:"+name.String(), err)

		case resource.Delete:
			// [bufferInsert] will only emit Sync and Upsert for the merged endpoints.
			panic("BUG: unexpected Delete event")
		}
	}

	// Use a pool for the buffers to avoid reallocs.
	bufferPool := sync.Pool{
		New: func() any {
			return container.NewInsertOrderedMap[bufferKey, bufferValue]()
		},
	}

	// Combine services and endpoint events into a single buffer.
	// Use InsertOrderedMap to retain relative ordering of events with different keys.
	// This highly increases the probability that related services and endpoints are committed
	// in the same transaction and thus reconciled together and reducing overall processing costs.
	events := stream.ToChannel(ctx,
		stream.Buffer(
			joinObservables(
				toObjectObservable(p.ServicesResource),
				toObjectObservable(p.EndpointsResource),
			),
			reflectorBufferSize,
			p.waitTime(),
			func(buf buffer, ev resource.Event[runtime.Object]) buffer {
				if buf == nil {
					buf = bufferPool.Get().(buffer)
				}
				return bufferInsert(buf, ev)
			},
		),
	)

	processBuffer := func(buf buffer) {
		txn := p.Writer.WriteTxn()
		defer txn.Commit()
		for key, val := range buf.All() {
			if key.isSvc {
				processServiceEvent(txn, val.kind, val.svc)
			} else {
				processEndpointsEvent(txn, key, val.kind, val.allEndpoints)
			}
		}
	}

	for buf := range events {
		processBuffer(buf)
		buf.Clear()
		bufferPool.Put(buf)
		rh.report()
	}
	return nil
}

type bufferKey struct {
	key   resource.Key
	isSvc bool
}

type bufferValue struct {
	kind         resource.EventKind
	svc          *slim_corev1.Service
	allEndpoints allEndpoints
}

type endpointsEvent struct {
	name     string
	backends map[cmtypes.AddrCluster]*k8s.Backend
}

// allEndpoints holds one or more [k8s.Endpoints] that target the same service within a single buffer.
// This type is designed to avoid allocations for the usual case of single endpoint slice per service.
type allEndpoints struct {
	head endpointsEvent
	tail []endpointsEvent
}

func (ae allEndpoints) insert(deleted bool, ep *k8s.Endpoints) allEndpoints {
	ev := endpointsEvent{
		name: ep.EndpointSliceName,
	}
	if !deleted {
		ev.backends = ep.Backends
	}

	if ae.head.name == "" || ae.head.name == ev.name {
		ae.head = ev
		return ae
	}
	for i, x := range ae.tail {
		if ev.name == x.name {
			ae.tail[i] = ev
			return ae
		}
	}
	ae.tail = append(ae.tail, ev)
	return ae
}

func (ae *allEndpoints) All() iter.Seq[endpointsEvent] {
	return func(yield func(endpointsEvent) bool) {
		if ae.head.name != "" {
			if !yield(ae.head) {
				return
			}
		}
		for _, ep := range ae.tail {
			if !yield(ep) {
				return
			}
		}
	}
}

func (ae *allEndpoints) Backends() iter.Seq2[cmtypes.AddrCluster, *k8s.Backend] {
	return func(yield func(cmtypes.AddrCluster, *k8s.Backend) bool) {
		for ep := range ae.All() {
			for addr, be := range ep.backends {
				if !yield(addr, be) {
					return
				}
			}
		}
	}
}

// buffer for holding a batch of service or endpoint events
type buffer = *container.InsertOrderedMap[bufferKey, bufferValue]

func bufferInsert(buf buffer, ev resource.Event[runtime.Object]) buffer {
	switch obj := ev.Object.(type) {
	case *k8s.Endpoints:
		if ev.Kind == resource.Sync {
			buf.Insert(bufferKey{isSvc: false}, bufferValue{kind: ev.Kind})
			return buf
		}
		key := bufferKey{
			resource.Key{Name: obj.ServiceName.Name(), Namespace: obj.ServiceName.Namespace()},
			false,
		}
		var allEps allEndpoints
		if old, ok := buf.Get(key); ok {
			allEps = old.allEndpoints
		}
		allEps = allEps.insert(ev.Kind == resource.Delete, obj)

		// Since we may merge a mixture of Upsert and Delete events together we handle
		// deletion as an Upsert of [endpointsEvent] with nil backends.
		buf.Insert(key, bufferValue{
			kind:         resource.Upsert,
			allEndpoints: allEps,
		})
	case *slim_corev1.Service:
		buf.Insert(bufferKey{key: ev.Key, isSvc: true}, bufferValue{kind: ev.Kind, svc: obj})
	default:
		panic(fmt.Sprintf("BUG: unhandled type %T", obj))
	}
	return buf
}

type reflectorHealth struct {
	health    cell.Health
	log       *slog.Logger
	prevError error
	allErrors map[string]error
}

func newReflectorHealth(h cell.Health, log *slog.Logger) *reflectorHealth {
	return &reflectorHealth{
		health:    h,
		log:       log,
		prevError: nil,
		allErrors: map[string]error{},
	}
}

func (rh *reflectorHealth) update(key string, err error) {
	if err == nil {
		delete(rh.allErrors, key)
	} else {
		rh.allErrors[key] = err
	}
}

func (rh *reflectorHealth) report() {
	if len(rh.allErrors) == 0 && rh.prevError == nil {
		return
	}

	processingError := errors.Join(slices.Collect(maps.Values(rh.allErrors))...)
	if !errors.Is(processingError, rh.prevError) {
		if processingError == nil {
			rh.health.OK("Running")
			rh.log.Info("Recovered from errors", logfields.Error, rh.prevError)
		} else {
			rh.health.Degraded("Failure processing services", processingError)
			rh.log.Warn("Failure processing services",
				logfields.Error, processingError)
		}
	}
	rh.prevError = processingError
}

// hostPortServiceNamePrefix returns the common prefix for synthetic HostPort services
// for the pod with the given name. This prefix is used as-is when cleaning up existing
// HostPort entries for a pod. This handles the pod recreation where name stays but UID
// changes, which we might see only as an update without any deletion.
func hostPortServiceNamePrefix(pod *slim_corev1.Pod) loadbalancer.ServiceName {
	return loadbalancer.NewServiceName(
		pod.ObjectMeta.Namespace,
		fmt.Sprintf("%s:host-port:", pod.ObjectMeta.Name),
	)
}

func upsertHostPort(netnsCookie lbmaps.HaveNetNSCookieSupport, config loadbalancer.Config, extConfig loadbalancer.ExternalConfig, log *slog.Logger, wtxn writer.WriteTxn, writer *writer.Writer, pod *slim_corev1.Pod) error {
	podIPs := k8sUtils.ValidIPs(pod.Status)
	containers := slices.Concat(pod.Spec.InitContainers, pod.Spec.Containers)
	serviceNamePrefix := hostPortServiceNamePrefix(pod)

	type podServices struct {
		service loadbalancer.Service
		bes     []loadbalancer.BackendParams
		fes     sets.Set[loadbalancer.FrontendParams]
	}

	servicesForThisPod := make(map[loadbalancer.ServiceName]*podServices)

	updatedServices := sets.New[loadbalancer.ServiceName]()
	for _, c := range containers {
		for _, p := range c.Ports {
			if p.HostPort <= 0 {
				continue
			}

			if uint16(p.HostPort) >= config.NodePortMin &&
				uint16(p.HostPort) <= config.NodePortMax {
				log.Warn("The requested hostPort is colliding with the configured NodePort range. Ignoring.",
					logfields.HostPort, p.HostPort,
					logfields.NodePortMin, config.NodePortMin,
					logfields.NodePortMax, config.NodePortMax,
				)
				continue
			}

			proto, err := loadbalancer.NewL4Type(string(p.Protocol))
			if err != nil {
				continue
			}

			// HostPort service names are of form:
			// <namespace>/<name>:host-port:<port>:<uid>.
			serviceName := serviceNamePrefix.AppendSuffix(
				fmt.Sprintf("%d:%s",
					p.HostPort,
					pod.ObjectMeta.UID),
			)

			svc, ok := servicesForThisPod[serviceName]
			if !ok {
				servicesForThisPod[serviceName] = &podServices{
					service: loadbalancer.Service{
						ExtTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
						IntTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
						Name:             serviceName,
						LoopbackHostPort: false,
						Source:           source.Kubernetes,
					},
					fes: sets.Set[loadbalancer.FrontendParams]{},
				}
				svc = servicesForThisPod[serviceName]
			}

			var ipv4, ipv6 bool

			// Construct the backends from the pod IPs and container ports.
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

				bep := loadbalancer.BackendParams{
					Address: loadbalancer.NewL3n4Addr(
						proto,
						addr,
						uint16(p.ContainerPort),
						loadbalancer.ScopeExternal,
					),
					Weight: loadbalancer.DefaultBackendWeight,
				}
				svc.bes = append(svc.bes, bep)
			}

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
					svc.service.LoopbackHostPort = true
				} else if svc.service.LoopbackHostPort {
					// if it's not a loopback but the service was previously marked with LoopbackHostPort, then it's
					// an unsupported combination
					log.Warn("service with LoopbackHostPort not supported for port with non-loopback address")
					continue
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

			for _, feIP := range feIPs {
				addr := cmtypes.MustAddrClusterFromIP(feIP)
				fe := loadbalancer.FrontendParams{
					Type:        loadbalancer.SVCTypeHostPort,
					ServiceName: serviceName,
					Address: loadbalancer.NewL3n4Addr(
						proto,
						addr,
						uint16(p.HostPort),
						loadbalancer.ScopeExternal,
					),
					ServicePort: uint16(p.HostPort),
				}

				svc.fes.Insert(fe)
			}

			updatedServices.Insert(serviceName)
		}
	}

	for serviceName, svc := range servicesForThisPod {
		err := writer.UpsertServiceAndFrontends(wtxn, &svc.service, svc.fes.UnsortedList()...)
		if err != nil {
			return fmt.Errorf("UpsertServiceAndFrontends: %w", err)
		}

		if err := writer.SetBackends(wtxn, serviceName, source.Kubernetes, svc.bes...); err != nil {
			return fmt.Errorf("SetBackends: %w", err)
		}
	}

	// Find and remove orphaned HostPort services, frontends and backends
	// if 'HostPort' has changed or has been unset.
	for svc := range writer.Services().Prefix(wtxn, loadbalancer.ServiceByName(serviceNamePrefix)) {
		if updatedServices.Has(svc.Name) {
			continue
		}

		err := writer.DeleteBackendsOfService(wtxn, svc.Name, source.Kubernetes)
		if err != nil {
			return fmt.Errorf("DeleteBackendsOfService: %w", err)
		}

		_, err = writer.DeleteServiceAndFrontends(wtxn, svc.Name)
		if err != nil {
			return fmt.Errorf("DeleteServiceAndFrontends: %w", err)
		}
	}

	return nil
}

func deleteHostPort(params reflectorParams, wtxn writer.WriteTxn, pod *slim_corev1.Pod) error {
	serviceNamePrefix := hostPortServiceNamePrefix(pod)
	for svc := range params.Writer.Services().Prefix(wtxn, loadbalancer.ServiceByName(serviceNamePrefix)) {
		err := params.Writer.DeleteBackendsOfService(wtxn, svc.Name, source.Kubernetes)
		if err != nil {
			return fmt.Errorf("DeleteBackendsOfService: %w", err)
		}
		_, err = params.Writer.DeleteServiceAndFrontends(wtxn, svc.Name)
		if err != nil {
			return fmt.Errorf("DeleteServiceAndFrontends: %w", err)
		}
	}
	return nil
}

func toObjectObservable[T runtime.Object](src stream.Observable[resource.Event[T]]) stream.Observable[resource.Event[runtime.Object]] {
	return stream.Map(src, func(ev resource.Event[T]) resource.Event[runtime.Object] {
		// Already mark the event as handled as we don't need retries.
		ev.Done(nil)

		return resource.Event[runtime.Object]{
			Kind:   ev.Kind,
			Key:    ev.Key,
			Object: ev.Object,
			Done:   ev.Done,
		}
	})
}

func joinObservables[T any](src stream.Observable[T], srcs ...stream.Observable[T]) stream.Observable[T] {
	return stream.FuncObservable[T](
		func(ctx context.Context, next func(T), complete func(error)) {
			// Use a mutex to serialize the 'next' callbacks
			var mu lock.Mutex

			remainingCompletions := len(srcs)
			emit := func(x T) {
				mu.Lock()
				defer mu.Unlock()
				if remainingCompletions > 0 {
					next(x)
				}
			}

			comp := func(err error) {
				mu.Lock()
				defer mu.Unlock()
				remainingCompletions--
				if remainingCompletions == 0 {
					complete(err)
				}
			}
			src.Observe(ctx, emit, comp)
			for _, src := range srcs {
				src.Observe(ctx, emit, comp)
			}
		})
}
