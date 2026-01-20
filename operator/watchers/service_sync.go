// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"

	operatorK8s "github.com/cilium/cilium/operator/k8s"
	"github.com/cilium/cilium/pkg/annotation"
	cmnamespace "github.com/cilium/cilium/pkg/clustermesh/namespace"
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
)

type ServiceSyncConfig struct {
	// Enabled if true enables the k8s services to kvstore synchronization.
	Enabled bool

	// Synced if given is called when synchronization here is done. This is
	// used by clustermesh-apiserver to further wait for its resources to be
	// processed.
	Synced func(context.Context)
}

// ServiceSyncCell implements synchronization of Kubernetes services and endpoints
// to kvstore.
var ServiceSyncCell = cell.Module(
	"service-sync",
	"Synchronizes Kubernetes services to KVStore",

	cell.Invoke(registerServiceSync),
	cell.Provide(newClusterServiceConverter),
)

type ClusterServiceConverter interface {
	Convert(svc *slim_corev1.Service, getEndpoints func(namespace, name string) []*k8s.Endpoints) (out *serviceStore.ClusterService, toUpsert bool, err error)
	ForDeletion(svc *slim_corev1.Service) (out *serviceStore.ClusterService)
}

type ServiceSyncParams struct {
	cell.In

	Config                  ServiceSyncConfig
	Log                     *slog.Logger
	ClusterInfo             cmtypes.ClusterInfo
	Clientset               k8sClient.Clientset
	KVStoreClient           kvstore.Client
	Services                resource.Resource[*slim_corev1.Service]
	Endpoints               resource.Resource[*k8s.Endpoints]
	StoreFactory            store.Factory
	ClusterServiceConverter ClusterServiceConverter

	Namespaces resource.Resource[*slim_corev1.Namespace]
}

type serviceSync struct {
	ServiceSyncParams
	store store.SyncStore
}

func registerServiceSync(jg job.Group, p ServiceSyncParams) {
	if !p.Config.Enabled || !p.Clientset.IsEnabled() || !p.KVStoreClient.IsEnabled() {
		return
	}

	s := &serviceSync{
		ServiceSyncParams: p,
		store: p.StoreFactory.NewSyncStore(
			p.ClusterInfo.Name,
			p.KVStoreClient,
			serviceStore.ServiceStorePrefix,
		),
	}

	jg.Add(
		job.OneShot(
			"service-sync",
			s.loop,
		),
		job.OneShot(
			"run-store",
			func(ctx context.Context, _ cell.Health) error {
				s.store.Run(ctx)
				return nil
			},
		),
	)
}

func (s *serviceSync) loop(ctx context.Context, health cell.Health) error {
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
		eps, _ := endpoints.ByIndex(operatorK8s.ServiceIndex, namespace+"/"+name)
		return eps
	}

	serviceEvents := s.Services.Events(ctx)
	endpointEvents := s.Endpoints.Events(ctx)

	namespaceEvents := s.Namespaces.Events(ctx)

	upsert := func(cs *serviceStore.ClusterService) {
		if err := s.store.UpsertKey(ctx, cs); err != nil {
			// An error is triggered only in case it concerns service marshaling,
			// as kvstore operations are automatically re-tried in case of error.
			s.Log.Warn("Failed synchronizing service",
				logfields.Error, err,
				logfields.K8sSvcName, cs.Name,
				logfields.K8sNamespace, cs.Namespace,
			)
		}
	}

	for serviceEvents != nil || endpointEvents != nil || namespaceEvents != nil {
		select {
		case ev, ok := <-serviceEvents:
			if !ok {
				serviceEvents = nil
				continue
			}

			switch ev.Kind {
			case resource.Sync:
				s.Log.Info("Initial list of services successfully received from Kubernetes")
				if s.Config.Synced != nil {
					s.store.Synced(ctx, s.Config.Synced)
				} else {
					s.store.Synced(ctx)
				}
				ev.Done(nil)
			case resource.Upsert:
				svc := ev.Object
				cs, toUpsert, err := converter.Convert(svc, getEndpoints)
				if err != nil {
					s.Log.Warn("Failed to convert service, will retry",
						logfields.Error, err,
						logfields.K8sSvcName, svc.Name,
						logfields.K8sNamespace, svc.Namespace,
					)
					ev.Done(err)
					continue
				}
				if toUpsert {
					upsert(cs)
				} else {
					s.store.DeleteKey(ctx, cs)
				}
				ev.Done(nil)
			case resource.Delete:
				s.store.DeleteKey(ctx, converter.ForDeletion(ev.Object))
				ev.Done(nil)
			}

		case ev, ok := <-endpointEvents:
			if !ok {
				endpointEvents = nil
				continue
			}

			if ev.Kind == resource.Sync {
				ev.Done(nil)
				continue
			}

			ep := ev.Object

			svc, exists, _ := services.GetByKey(resource.Key{Namespace: ep.ServiceName.Namespace(), Name: ep.ServiceName.Name()})
			if !exists {
				// Service does not exist yet.
				ev.Done(nil)
				continue
			}

			cs, toUpsert, err := converter.Convert(svc, getEndpoints)
			if err != nil {
				s.Log.Warn("Failed to convert service for endpoint update, will retry",
					logfields.Error, err,
					logfields.K8sSvcName, svc.Name,
					logfields.K8sNamespace, svc.Namespace,
				)
				ev.Done(err)
				continue
			}
			if toUpsert {
				upsert(cs)
			}
			ev.Done(nil)

		case ev, ok := <-namespaceEvents:
			if !ok {
				namespaceEvents = nil
				continue
			}

			if ev.Kind == resource.Sync {
				ev.Done(nil)
				continue
			}

			nsName := ev.Key.Name

			// Get all services in this namespace and resync them
			svcs, err := services.ByIndex(cache.NamespaceIndex, nsName)
			if err != nil {
				s.Log.Warn("Failed to list services for namespace update",
					logfields.Error, err,
					logfields.K8sNamespace, nsName,
				)
				ev.Done(err)
				continue
			}

			var errs []error
			for _, svc := range svcs {
				// Convert handles both global and non-global namespaces
				cs, toUpsert, err := converter.Convert(svc, getEndpoints)
				if err != nil {
					s.Log.Warn("Failed to convert service for namespace update",
						logfields.Error, err,
						logfields.K8sSvcName, svc.Name,
						logfields.K8sNamespace, svc.Namespace,
					)
					errs = append(errs, err)
					continue
				}
				if toUpsert {
					upsert(cs)
				} else {
					s.store.DeleteKey(ctx, cs)
				}
			}
			ev.Done(errors.Join(errs...))
		}
	}

	return nil
}

func isHeadless(svc *slim_corev1.Service) bool {
	_, headless := svc.Labels[v1.IsHeadlessService]
	if strings.ToLower(svc.Spec.ClusterIP) == "none" {
		headless = true
	}
	return headless
}

type DefaultClusterServiceConverter struct {
	cinfo            cmtypes.ClusterInfo
	namespaceManager cmnamespace.Manager
}

// Convert implements ClusterServiceConverter.
func (d DefaultClusterServiceConverter) Convert(k8sService *slim_corev1.Service, getEndpoints func(namespace, name string) []*k8s.Endpoints) (out *serviceStore.ClusterService, toUpsert bool, err error) {
	if shared := annotation.GetAnnotationShared(k8sService); !shared {
		return d.ForDeletion(k8sService), false, nil
	}

	// Check if namespace is global
	isGlobal, err := d.namespaceManager.IsGlobalNamespaceByName(k8sService.Namespace)
	if err != nil {
		return nil, false, err
	}
	if !isGlobal {
		return d.ForDeletion(k8sService), false, nil
	}

	svc := serviceStore.NewClusterService(k8sService.Name, k8sService.Namespace)
	svc.Cluster = d.cinfo.Name
	svc.ClusterID = d.cinfo.ID
	svc.Shared = true
	svc.IncludeExternal = true
	maps.Copy(svc.Labels, k8sService.Labels)
	maps.Copy(svc.Selector, k8sService.Spec.Selector)

	if !isHeadless(k8sService) {
		portConfig := serviceStore.PortConfiguration{}
		for _, port := range k8sService.Spec.Ports {
			p := loadbalancer.NewL4Addr(loadbalancer.L4Type(port.Protocol), uint16(port.Port))
			portConfig[string(port.Name)] = &p
		}
		svc.Frontends = map[string]serviceStore.PortConfiguration{}
		clusterIPs := k8sService.Spec.ClusterIPs
		if len(clusterIPs) == 0 {
			clusterIPs = []string{k8sService.Spec.ClusterIP}
		}
		for _, feIP := range clusterIPs {
			svc.Frontends[feIP] = portConfig
		}
	}

	svc.Backends = map[string]serviceStore.PortConfiguration{}
	for _, ep := range getEndpoints(svc.Namespace, svc.Name) {
		for addrCluster, backend := range ep.Backends {
			if !backend.Conditions.IsReady() && !backend.Conditions.IsServing() {
				continue
			}
			addrString := addrCluster.Addr().String()
			svc.Backends[addrString] = backend.ToPortConfiguration()
			if backend.Hostname != "" {
				svc.Hostnames[addrString] = backend.Hostname
			}
			if backend.Zone != "" {
				forZones := make([]serviceStore.ForZone, 0, len(backend.HintsForZones))
				for _, zone := range backend.HintsForZones {
					forZones = append(forZones, serviceStore.ForZone{Name: zone})
				}
				svc.Zones[addrString] = serviceStore.BackendZone{
					Zone:     backend.Zone,
					ForZones: forZones,
				}
			}
		}
	}

	return &svc, true, nil
}

// ForDeletion implements ClusterServiceConverter.
func (d DefaultClusterServiceConverter) ForDeletion(k8sService *slim_corev1.Service) (out *serviceStore.ClusterService) {
	return &serviceStore.ClusterService{
		Name:      k8sService.Name,
		Namespace: k8sService.Namespace,
		Cluster:   d.cinfo.Name,
		ClusterID: d.cinfo.ID,
	}
}

var _ ClusterServiceConverter = DefaultClusterServiceConverter{}

func newClusterServiceConverter(cinfo cmtypes.ClusterInfo, nsMgr cmnamespace.Manager) ClusterServiceConverter {
	return DefaultClusterServiceConverter{cinfo, nsMgr}
}
