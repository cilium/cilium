// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"errors"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"k8s.io/client-go/tools/cache"

	operatorK8s "github.com/cilium/cilium/operator/k8s"
	"github.com/cilium/cilium/pkg/annotation"
	cmnamespace "github.com/cilium/cilium/pkg/clustermesh/namespace"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	clusterEndpointSlice "github.com/cilium/cilium/pkg/clustermesh/types/endpointslice"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_discovery_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type EndpointSliceExportSyncConfig struct {
	// Enabled if true enables the k8s EndpointSlices to kvstore synchronization.
	Enabled bool

	// Synced if given is called when synchronization here is done. This is
	// used by clustermesh-apiserver to further wait for its resources to be
	// processed.
	Synced func(context.Context)
}

// EndpointSliceExportSyncCell implements synchronization of Kubernetes EndpointSlices
// backing global services to kvstore.
var EndpointSliceExportSyncCell = cell.Module(
	"endpointslice-export-sync",
	"Synchronizes Kubernetes EndpointSlices to KVStore",

	cell.Invoke(registerEndpointSliceExportSync),
	cell.Provide(newClusterEndpointSliceConverter),
)

type ClusterEndpointSliceConverter interface {
	Convert(event resource.Event[*slim_discovery_v1.EndpointSlice], getService func(namespace, name string) (*slim_corev1.Service, bool, error)) (upsert *clusterEndpointSlice.ClusterEndpointSlice, delete *clusterEndpointSlice.ClusterEndpointSlice, err error)
}

type EndpointSliceExportSyncParams struct {
	cell.In

	Config         EndpointSliceExportSyncConfig
	Log            *slog.Logger
	ClusterInfo    cmtypes.ClusterInfo
	Clientset      k8sClient.Clientset
	KVStoreClient  kvstore.Client
	Services       resource.Resource[*slim_corev1.Service]
	EndpointSlices resource.Resource[*slim_discovery_v1.EndpointSlice]
	StoreFactory   store.Factory

	ClusterEndpointSliceConverter ClusterEndpointSliceConverter
	Namespaces                    resource.Resource[*slim_corev1.Namespace]
}

type endpointSliceExportSync struct {
	EndpointSliceExportSyncParams
	store store.SyncStore
}

func registerEndpointSliceExportSync(jg job.Group, p EndpointSliceExportSyncParams) {
	if !p.Config.Enabled || !p.Clientset.IsEnabled() || !p.KVStoreClient.IsEnabled() {
		return
	}

	s := &endpointSliceExportSync{
		EndpointSliceExportSyncParams: p,
		store: p.StoreFactory.NewSyncStore(
			p.ClusterInfo.Name,
			p.KVStoreClient,
			clusterEndpointSlice.EndpointSliceStorePrefix,
		),
	}

	jg.Add(
		job.OneShot(
			"sync",
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

func (s *endpointSliceExportSync) loop(ctx context.Context, health cell.Health) error {
	converter := s.ClusterEndpointSliceConverter

	services, err := s.Services.Store(ctx)
	if err != nil {
		return err
	}

	endpointSlices, err := s.EndpointSlices.Store(ctx)
	if err != nil {
		return err
	}

	serviceEvents := s.Services.Events(ctx)
	endpointSliceEvents := s.EndpointSlices.Events(ctx)
	namespaceEvents := s.Namespaces.Events(ctx)

	getService := func(namespace, name string) (*slim_corev1.Service, bool, error) {
		return services.GetByKey(resource.Key{Namespace: namespace, Name: name})
	}
	upsert := func(eps *clusterEndpointSlice.ClusterEndpointSlice) {
		if err := s.store.UpsertKey(ctx, eps); err != nil {
			// An error is triggered only in case it concerns endpoint slice marshaling,
			// as kvstore operations are automatically re-tried in case of error.
			s.Log.Warn(
				"Failed synchronizing endpoint slice",
				logfields.Error, err,
				logfields.Name, eps.Name,
				logfields.K8sNamespace, eps.Namespace,
			)
		}
	}

	for serviceEvents != nil || endpointSliceEvents != nil || namespaceEvents != nil {
		select {
		case ev, ok := <-endpointSliceEvents:
			if !ok {
				endpointSliceEvents = nil
				continue
			}

			if ev.Kind == resource.Sync {
				s.Log.Info("Initial list of endpoint slices successfully received from Kubernetes")
				if s.Config.Synced != nil {
					s.store.Synced(ctx, s.Config.Synced)
				} else {
					s.store.Synced(ctx)
				}
				ev.Done(nil)
				continue
			}

			toUpsert, toDelete, err := converter.Convert(ev, getService)
			if err != nil {
				s.Log.Warn(
					"Failed to convert endpoint slice, will retry",
					logfields.Error, err,
					logfields.K8sSvcName, ev.Key.Name,
					logfields.K8sNamespace, ev.Key.Namespace,
				)
				ev.Done(err)
				continue
			}
			if toUpsert != nil {
				upsert(toUpsert)
			}
			if toDelete != nil {
				s.store.DeleteKey(ctx, toDelete)
			}
			ev.Done(nil)

		case ev, ok := <-serviceEvents:
			if !ok {
				serviceEvents = nil
				continue
			}
			if ev.Kind == resource.Sync {
				ev.Done(nil)
				continue
			}

			var errs []error
			epsList, err := endpointSlices.ByIndex(operatorK8s.ServiceIndex, ev.Key.String())
			if err != nil {
				s.Log.Warn(
					"Failed to list endpoint slices for service update",
					logfields.Error, err,
					logfields.K8sNamespace, ev.Key.Name,
				)
				ev.Done(err)
				continue
			}

			for _, eps := range epsList {
				toUpsert, toDelete, err := converter.Convert(
					resource.Event[*slim_discovery_v1.EndpointSlice]{
						Kind: ev.Kind, Key: resource.NewKey(eps), Object: eps,
					}, func(namespace, name string) (*slim_corev1.Service, bool, error) {
						return ev.Object, true, nil
					},
				)
				if err != nil {
					s.Log.Warn(
						"Failed to convert endpoint slice, will retry",
						logfields.Error, err,
						logfields.K8sSvcName, eps.Name,
						logfields.K8sNamespace, eps.Namespace,
					)
					errs = append(errs, err)
					continue
				}
				if toUpsert != nil {
					upsert(toUpsert)
				}
				if toDelete != nil {
					s.store.DeleteKey(ctx, toDelete)
				}
			}
			ev.Done(errors.Join(errs...))

		case ev, ok := <-namespaceEvents:
			if !ok {
				namespaceEvents = nil
				continue
			}

			if ev.Kind == resource.Sync {
				ev.Done(nil)
				continue
			}

			epsList, err := endpointSlices.ByIndex(cache.NamespaceIndex, ev.Key.Name)
			if err != nil {
				s.Log.Warn(
					"Failed to list endpoint slices for namespace update",
					logfields.Error, err,
					logfields.K8sNamespace, ev.Key.Name,
				)
				ev.Done(err)
				continue
			}

			var errs []error
			for _, eps := range epsList {
				toUpsert, toDelete, err := converter.Convert(
					resource.Event[*slim_discovery_v1.EndpointSlice]{
						Kind: ev.Kind, Key: resource.NewKey(eps), Object: eps,
					}, getService,
				)
				if err != nil {
					s.Log.Warn(
						"Failed to convert endpoint slice, will retry",
						logfields.Error, err,
						logfields.K8sSvcName, eps.Name,
						logfields.K8sNamespace, eps.Namespace,
					)
					errs = append(errs, err)
					continue
				}
				if toUpsert != nil {
					upsert(toUpsert)
				}
				if toDelete != nil {
					s.store.DeleteKey(ctx, toDelete)
				}
			}
			ev.Done(errors.Join(errs...))
		}
	}

	return nil
}

type DefaultClusterEndpointSliceConverter struct {
	cinfo            cmtypes.ClusterInfo
	namespaceManager cmnamespace.Manager
}

// Convert implements ClusterEndpointSliceConverter.
func (d DefaultClusterEndpointSliceConverter) Convert(event resource.Event[*slim_discovery_v1.EndpointSlice], getService func(namespace, name string) (*slim_corev1.Service, bool, error)) (upsert *clusterEndpointSlice.ClusterEndpointSlice, delete *clusterEndpointSlice.ClusterEndpointSlice, err error) {
	eps := event.Object
	if event.Kind == resource.Delete {
		return nil, d.forDeletion(eps), nil
	}

	svcName := eps.Labels[slim_discovery_v1.LabelServiceName]
	svc, exists, err := getService(eps.Namespace, svcName)
	if err != nil {
		return nil, nil, err
	}
	if !exists || !annotation.GetAnnotationShared(svc) {
		return nil, d.forDeletion(eps), nil
	}

	// Check if namespace is global.
	isGlobal, err := d.namespaceManager.IsGlobalNamespaceByName(svc.Namespace)
	if err != nil {
		return nil, nil, err
	}
	if !isGlobal {
		return nil, d.forDeletion(eps), nil
	}

	return &clusterEndpointSlice.ClusterEndpointSlice{
		Cluster:     d.cinfo.Name,
		ClusterID:   d.cinfo.ID,
		Namespace:   eps.Namespace,
		Name:        eps.Name,
		Labels:      eps.Labels,
		Annotations: eps.Annotations,
		AddressType: eps.AddressType,
		Endpoints:   eps.Endpoints,
		Ports:       eps.Ports,
	}, nil, nil
}

func (d DefaultClusterEndpointSliceConverter) forDeletion(eps *slim_discovery_v1.EndpointSlice) *clusterEndpointSlice.ClusterEndpointSlice {
	return &clusterEndpointSlice.ClusterEndpointSlice{
		Cluster:   d.cinfo.Name,
		ClusterID: d.cinfo.ID,
		Namespace: eps.Namespace,
		Name:      eps.Name,
	}
}

var _ ClusterEndpointSliceConverter = DefaultClusterEndpointSliceConverter{}

func newClusterEndpointSliceConverter(cinfo cmtypes.ClusterInfo, nsMgr cmnamespace.Manager) ClusterEndpointSliceConverter {
	return DefaultClusterEndpointSliceConverter{cinfo, nsMgr}
}
