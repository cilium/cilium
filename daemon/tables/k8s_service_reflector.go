package tables

import (
	"context"
	"fmt"
	"sync"

	corev1 "k8s.io/api/core/v1"

	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/statedb/reflector"
)

var K8sReflectorCell = cell.Invoke(registerK8sReflector)

func registerK8sReflector(lc cell.Lifecycle, c client.Clientset, s *Services) error {
	if !c.IsEnabled() {
		return fmt.Errorf("Please set --k8s-kubeconfig-path")
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	lc.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			startK8sReflector(ctx, c, s, &wg)
			return nil
		},
		OnStop: func(cell.HookContext) error {
			cancel()
			wg.Wait()
			return nil
		},
	})
	return nil
}

func startK8sReflector(ctx context.Context, c client.Clientset, s *Services, wg *sync.WaitGroup) {
	// TODO consider doing a typed version of K8sEventObservable that also emits stuff
	// in batches, so that things like this are easier to do.
	services := reflector.K8sEventObservable(utils.ListerWatcherFromTyped(c.CoreV1().Services("")))
	endpoints := reflector.K8sEventObservable(utils.ListerWatcherFromTyped(c.CoreV1().Endpoints("")))

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
				svc := ev.Obj.(*corev1.Service)
				// For sake of example, this just does ClusterIP services
				if svc.Spec.Type != corev1.ServiceTypeClusterIP {
					return
				}
				err := s.UpsertService(
					txn,
					loadbalancer.ServiceName{Namespace: svc.Namespace, Name: svc.Name},
					toServiceParams(svc),
				)
				if err != nil {
					// TODO: how to resolve conflicts when the same service or frontend address
					// is added from different sources? do we retry, give up or update Service.Status?
					// Or should *Service be designed to allow overlaps by merging them ("shadowed services")?
					panic(err)
				}
			case reflector.CacheStoreDelete:
				svc := ev.Obj.(*corev1.Service)
				s.DeleteServicesByName(txn, loadbalancer.ServiceName{Namespace: svc.Namespace, Name: svc.Name}, source.Kubernetes)

			case reflector.CacheStoreReplace:
				// Out-of-sync with the API server, resync by deleting all services and inserting the initial
				// set.
				s.DeleteServicesBySource(txn, source.Kubernetes)
				svcs := ev.Obj.([]any)
				for _, obj := range svcs {
					svc := obj.(*corev1.Service)
					s.UpsertService(
						txn,
						loadbalancer.ServiceName{Namespace: svc.Namespace, Name: svc.Name},
						toServiceParams(svc),
					)
				}
			}

		},
		func(error) { wg.Done() },
	)

	endpoints.Observe(
		ctx,
		func(ev reflector.CacheStoreEvent) {
			txn := s.WriteTxn()
			// TODO commit in larger batches by using stream.Buffer
			defer txn.Commit()
			switch ev.Type {
			case reflector.CacheStoreAdd:
				fallthrough
			case reflector.CacheStoreUpdate:
				eps := ev.Obj.(*corev1.Endpoints)

				err := s.UpsertBackends(
					txn,
					loadbalancer.ServiceName{Namespace: eps.Namespace, Name: eps.Name},
					toBackendParams(eps)...,
				)
				if err != nil {
					panic(err)
				}
			case reflector.CacheStoreDelete:
				eps := ev.Obj.(*corev1.Endpoints)
				for _, p := range toBackendParams(eps) {
					s.DeleteBackend(
						txn,
						loadbalancer.ServiceName{Namespace: eps.Namespace, Name: eps.Name},
						p.L3n4Addr,
					)
				}

			case reflector.CacheStoreReplace:
				// Out-of-sync with the API server, resync.
				s.DeleteBackendsBySource(txn, source.Kubernetes)
				epss := ev.Obj.([]any)
				for _, obj := range epss {
					eps := obj.(*corev1.Endpoints)

					err := s.UpsertBackends(
						txn,
						loadbalancer.ServiceName{Namespace: eps.Namespace, Name: eps.Name},
						toBackendParams(eps)...,
					)
					if err != nil {
						panic(err)
					}
				}
			}

		},
		func(error) { wg.Done() },
	)

}

func toServiceParams(svc *corev1.Service) ServiceParams {
	port := svc.Spec.Ports[0].Port
	return ServiceParams{
		L3n4Addr:         *loadbalancer.NewL3n4Addr(loadbalancer.TCP, types.MustParseAddrCluster(svc.Spec.ClusterIP), uint16(port), loadbalancer.ScopeExternal),
		Type:             loadbalancer.SVCTypeClusterIP,
		Labels:           labels.Map2Labels(svc.Labels, labels.LabelSourceK8s),
		Source:           source.Kubernetes,
		NatPolicy:        loadbalancer.SVCNatPolicyNone,
		ExtPolicy:        loadbalancer.SVCTrafficPolicyNone,
		IntPolicy:        loadbalancer.SVCTrafficPolicyNone,
		LoopbackHostPort: false,
		SessionAffinity:  nil,
		HealthCheck:      nil,
	}
}

func toBackendParams(eps *corev1.Endpoints) (out []BackendParams) {
	for _, ep := range eps.Subsets {
		for _, addr := range ep.Addresses {
			for _, port := range ep.Ports {
				out = append(out, BackendParams{
					L3n4Addr: *loadbalancer.NewL3n4Addr(
						loadbalancer.TCP,
						types.MustParseAddrCluster(addr.IP),
						uint16(port.Port),
						loadbalancer.ScopeExternal,
					),
					Source:    source.Kubernetes,
					PortName:  "",
					NodeName:  "",
					Weight:    0,
					State:     loadbalancer.BackendStateActive,
					Preferred: false,
				})
			}

		}
	}
	return
}
