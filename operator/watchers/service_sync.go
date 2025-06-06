// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"log/slog"
	"maps"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/annotation"
	serviceStore "github.com/cilium/cilium/pkg/clustermesh/store"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/k8s"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
)

type ServiceSyncCallback func(context.Context)

// ServiceSyncCell implements synchronization of Kubernetes services and endpoints
// to kvstore.
var ServiceSyncCell = cell.Module(
	"service-sync",
	"Synchronizes Kubernetes services to KVStore",

	cell.Invoke(registerServiceSync),
	cell.Provide(newClusterServiceConverter),
)

type ClusterServiceConverter interface {
	Convert(svc *slim_corev1.Service, eps []*k8s.Endpoints) (out *serviceStore.ClusterService, toUpsert bool)
	ForDeletion(svc *slim_corev1.Service) (out *serviceStore.ClusterService)
}

type ServiceSyncParams struct {
	cell.In

	Log                     *slog.Logger
	ClusterInfo             cmtypes.ClusterInfo
	Clientset               k8sClient.Clientset
	Services                resource.Resource[*slim_corev1.Service]
	Endpoints               resource.Resource[*k8s.Endpoints]
	StoreFactory            store.Factory
	ClusterServiceConverter ClusterServiceConverter
	Backend                 promise.Promise[kvstore.BackendOperations] `optional:"true"`
	ServiceSyncCallback     ServiceSyncCallback                        `optional:"true"`
}

type serviceSync struct {
	ServiceSyncParams

	storePromise promise.Promise[store.SyncStore]
}

func registerServiceSync(jg job.Group, p ServiceSyncParams) {
	if !operatorOption.Config.SyncK8sServices || option.Config.KVStore == "" || !p.Clientset.IsEnabled() {
		return
	}

	s := &serviceSync{ServiceSyncParams: p}

	storeResolver, storePromise := promise.New[store.SyncStore]()
	s.storePromise = storePromise

	jg.Add(
		job.OneShot(
			"service-sync",
			s.loop,
		),
		job.OneShot(
			"run-store",
			func(ctx context.Context, health cell.Health) error {
				var backend kvstore.BackendOperations
				if s.Backend != nil {
					var err error
					backend, err = s.Backend.Await(ctx)
					if err != nil {
						storeResolver.Reject(err)
						return err
					}
				} else {
					backend = kvstore.Client()
				}
				store := s.StoreFactory.NewSyncStore(
					s.ClusterInfo.Name,
					backend,
					serviceStore.ServiceStorePrefix,
				)
				storeResolver.Resolve(store)
				store.Run(ctx)
				return nil
			},
		),
	)
}

func (s *serviceSync) loop(ctx context.Context, health cell.Health) error {
	store, err := s.storePromise.Await(ctx)
	if err != nil {
		return err
	}

	converter := s.ClusterServiceConverter

	services, err := s.Services.Store(ctx)
	if err != nil {
		return err
	}

	endpoints, err := s.Endpoints.Store(ctx)
	if err != nil {
		return err
	}

	getEndpoints := func(namespace, name string) []*k8s.Endpoints {
		eps, _ := endpoints.ByIndex(k8s.ServiceIndex, namespace+"/"+name)
		return eps
	}

	serviceEvents := s.Services.Events(ctx)
	endpointEvents := s.Endpoints.Events(ctx)

	upsert := func(cs *serviceStore.ClusterService) {
		if err := store.UpsertKey(ctx, cs); err != nil {
			// An error is triggered only in case it concerns service marshaling,
			// as kvstore operations are automatically re-tried in case of error.
			s.Log.Warn("Failed synchronizing service",
				logfields.Error, err,
				logfields.K8sSvcName, cs.Name,
				logfields.K8sNamespace, cs.Namespace,
			)
		}
	}

	for serviceEvents != nil || endpointEvents != nil {
		select {
		case ev, ok := <-serviceEvents:
			if !ok {
				serviceEvents = nil
				continue
			}
			ev.Done(nil)

			// Ignore kubernetes endpoints events
			if ev.Key.Name == "kube-scheduler" || ev.Key.Name == "kube-controller-manager" {
				continue
			}

			switch ev.Kind {
			case resource.Sync:
				s.Log.Info("Initial list of services successfully received from Kubernetes")
				if s.ServiceSyncCallback != nil {
					store.Synced(ctx, s.ServiceSyncCallback)
				} else {
					store.Synced(ctx)
				}
			case resource.Upsert:
				svc := ev.Object
				cs, toUpsert := converter.Convert(svc, getEndpoints(ev.Key.Namespace, ev.Key.Name))
				if toUpsert {
					upsert(cs)
				} else {
					store.DeleteKey(ctx, cs)
				}
			case resource.Delete:
				store.DeleteKey(ctx, converter.ForDeletion(ev.Object))
			}

		case ev, ok := <-endpointEvents:
			if !ok {
				endpointEvents = nil
				continue
			}

			ev.Done(nil)

			if ev.Kind == resource.Sync {
				continue
			}

			ep := ev.Object

			// Ignore kubernetes endpoints events
			if ep.ServiceID.Name == "kube-scheduler" || ep.ServiceID.Name == "kube-controller-manager" {
				continue
			}

			svc, exists, _ := services.GetByKey(resource.Key{Namespace: ep.ServiceID.Namespace, Name: ep.ServiceID.Name})
			if !exists {
				// Service does not exist yet.
				continue
			}

			if cs, toUpsert := converter.Convert(svc, getEndpoints(ep.ServiceID.Namespace, ep.ServiceID.Name)); toUpsert {
				upsert(cs)
			}
		}
	}

	return nil
}

type DefaultClusterServiceConverter struct{}

// Convert implements ClusterServiceConverter.
func (d DefaultClusterServiceConverter) Convert(k8sService *slim_corev1.Service, eps []*k8s.Endpoints) (out *serviceStore.ClusterService, toUpsert bool) {
	svc := serviceStore.NewClusterService(k8sService.Name, k8sService.Namespace)
	maps.Copy(svc.Labels, k8sService.Labels)
	maps.Copy(svc.Selector, k8sService.Spec.Selector)

	portConfig := serviceStore.PortConfiguration{}
	for _, port := range k8sService.Spec.Ports {
		p := loadbalancer.NewL4Addr(loadbalancer.L4Type(port.Protocol), uint16(port.Port))
		portConfig[string(port.Name)] = p
	}

	svc.Frontends = map[string]serviceStore.PortConfiguration{}
	clusterIPs := k8sService.Spec.ClusterIPs
	if len(clusterIPs) == 0 {
		clusterIPs = []string{k8sService.Spec.ClusterIP}
	}
	for _, feIP := range clusterIPs {
		svc.Frontends[feIP] = portConfig
	}

	svc.Backends = map[string]serviceStore.PortConfiguration{}
	for _, ep := range eps {
		for addrCluster, backend := range ep.Backends {
			svc.Backends[addrCluster.Addr().String()] = backend.Ports
			if backend.Hostname != "" {
				svc.Hostnames[addrCluster.Addr().String()] = backend.Hostname
			}
		}
	}

	svc.Shared = annotation.GetAnnotationShared(k8sService)
	svc.IncludeExternal = annotation.GetAnnotationIncludeExternal(k8sService)

	return &svc, true
}

// ForDeletion implements ClusterServiceConverter.
func (d DefaultClusterServiceConverter) ForDeletion(k8sService *slim_corev1.Service) (out *serviceStore.ClusterService) {
	svc := serviceStore.NewClusterService(k8sService.Name, k8sService.Namespace)
	return &svc
}

var _ ClusterServiceConverter = DefaultClusterServiceConverter{}

func newClusterServiceConverter() ClusterServiceConverter {
	return DefaultClusterServiceConverter{}
}
