// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mcsapi

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	mcsapiv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	"github.com/cilium/cilium/pkg/clustermesh/mcsapi/types"
	mcsapitypes "github.com/cilium/cilium/pkg/clustermesh/mcsapi/types"
	cmnamespace "github.com/cilium/cilium/pkg/clustermesh/namespace"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// ServiceExportResource builds the Resource[ServiceExport] object.
func ServiceExportResource(lc cell.Lifecycle, cs client.Clientset, mp workqueue.MetricsProvider, opts ...func(*metav1.ListOptions)) resource.Resource[*mcsapiv1alpha1.ServiceExport] {
	if !cs.IsEnabled() {
		return nil
	}

	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped(cs.MulticlusterV1alpha1().ServiceExports("")),
		opts...,
	)
	return resource.New[*mcsapiv1alpha1.ServiceExport](
		lc, lw, mp,
		resource.WithMetric("ServiceExport"),
		resource.WithIndexers(cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}),
	)
}

// ServiceExportSyncCallback represents a callback that, if provided, is executed
// when the first synchronization is completed.
type ServiceExportSyncCallback func(context.Context)

// ServiceExportSyncConfig contains configuration for ServiceExport synchronization.
type ServiceExportSyncConfig struct {
	// NamespaceFilteringEnabled indicates whether namespace-based filtering should be applied.
	// When true, only service exports in global namespaces will be synced.
	NamespaceFilteringEnabled bool
}

type ServiceExportSyncParameters struct {
	cell.In

	Logger      *slog.Logger
	Config      mcsapitypes.MCSAPIConfig
	SyncConfig  ServiceExportSyncConfig
	ClusterInfo cmtypes.ClusterInfo

	Clientset     client.Clientset
	KVStoreClient kvstore.Client
	StoreFactory  store.Factory

	ServiceExports resource.Resource[*mcsapiv1alpha1.ServiceExport]
	Services       resource.Resource[*slim_corev1.Service]

	SyncCallback ServiceExportSyncCallback `optional:"true"`

	// NamespaceManager is used to determine if a namespace is global.
	// Required when SyncConfig.NamespaceFilteringEnabled is true.
	NamespaceManager cmnamespace.Manager `optional:"true"`
	// Namespaces is the resource for watching namespace events.
	// Required when SyncConfig.NamespaceFilteringEnabled is true.
	Namespaces resource.Resource[*slim_corev1.Namespace] `optional:"true"`
}

func registerServiceExportSync(jg job.Group, cfg ServiceExportSyncParameters) {
	if !cfg.Clientset.IsEnabled() || !cfg.KVStoreClient.IsEnabled() {
		return
	}

	store := cfg.StoreFactory.NewSyncStore(
		cfg.ClusterInfo.Name,
		cfg.KVStoreClient,
		types.ServiceExportStorePrefix,
	)

	jg.Add(
		job.OneShot(
			"serviceexport-sync",
			func(ctx context.Context, _ cell.Health) error {
				(&serviceExportSync{
					logger:      cfg.Logger,
					enabled:     cfg.Config.EnableMCSAPI,
					clusterName: cfg.ClusterInfo.Name,

					clientset:      cfg.Clientset,
					serviceExports: cfg.ServiceExports,
					services:       cfg.Services,

					store:        store,
					syncCallback: cfg.SyncCallback,

					namespaceFilteringEnabled: cfg.SyncConfig.NamespaceFilteringEnabled,
					namespaceManager:          cfg.NamespaceManager,
					namespaces:                cfg.Namespaces,
				}).loop(ctx)
				return nil
			},
		),
		job.OneShot(
			"run-serviceexport-store",
			func(ctx context.Context, _ cell.Health) error {
				store.Run(ctx)
				return nil
			},
		),
	)
}

type serviceExportSync struct {
	logger      *slog.Logger
	enabled     bool
	clusterName string

	clientset      client.Clientset
	serviceExports resource.Resource[*mcsapiv1alpha1.ServiceExport]
	services       resource.Resource[*slim_corev1.Service]

	store        store.SyncStore
	syncCallback ServiceExportSyncCallback

	// Namespace filtering support
	namespaceFilteringEnabled bool
	namespaceManager          cmnamespace.Manager
	namespaces                resource.Resource[*slim_corev1.Namespace]
}

func (s *serviceExportSync) loop(ctx context.Context) {
	if s.syncCallback == nil {
		s.syncCallback = func(ctx context.Context) {}
	}

	if !s.enabled {
		// We pretend that service exports are synced even if the feature is
		// disabled to simplify consumers logic so that they don't have to do any
		// special handling/checks if a remote cluster has this feature disabled
		// as it's the only cluster mesh type that can be disabled separately.
		// This is especially useful in the case of the kvstoremesh.
		s.store.Synced(ctx, s.syncCallback)
		return
	}

	if s.clientset != nil /* clientset is nil in tests */ {
		err := checkCRD(ctx, s.clientset, mcsapiv1alpha1.SchemeGroupVersion.WithKind("serviceexports"))
		if err != nil {
			s.logger.Warn("starting synchronizing service exports without the required CRD installed", logfields.Error, err)
			// Also pretend that the service exports are synced for the same reason
			// as above.
			s.store.Synced(ctx, s.syncCallback)
			return
		}
	}

	serviceEvents := s.services.Events(ctx)
	serviceStore, err := s.services.Store(ctx)
	if err != nil {
		s.logger.Error("can't init service store", logfields.Error, err)
		return
	}
	serviceExportsEvents := s.serviceExports.Events(ctx)
	serviceExportStore, err := s.serviceExports.Store(ctx)
	if err != nil {
		s.logger.Error("can't init service export store", logfields.Error, err)
		return
	}

	// Setup namespace events channel if namespace filtering is enabled
	var namespaceEvents <-chan resource.Event[*slim_corev1.Namespace]
	if s.namespaceFilteringEnabled {
		s.logger.Debug("Namespace filtering is enabled for service export sync")
		namespaceEvents = s.namespaces.Events(ctx)
	} else {
		s.logger.Debug("Namespace filtering is disabled for service export sync")
	}

	// isNamespaceGlobal checks if the namespace is global. If namespace filtering
	// is disabled, all namespaces are considered global.
	isNamespaceGlobal := func(namespace string) (bool, error) {
		if !s.namespaceFilteringEnabled || s.namespaceManager == nil {
			return true, nil
		}
		isGlobal, err := s.namespaceManager.IsGlobalNamespaceByName(namespace)
		if err != nil {
			return false, err
		}
		return isGlobal, nil
	}

	// syncServiceExport syncs a service export based on namespace global status
	syncServiceExport := func(key resource.Key) error {
		// Check namespace global status before syncing
		isGlobal, err := isNamespaceGlobal(key.Namespace)
		if err != nil {
			s.logger.Warn("Failed to determine if namespace is global",
				logfields.Error, err,
				logfields.K8sSvcName, key.Name,
				logfields.K8sNamespace, key.Namespace,
			)
			return err
		}
		if !isGlobal {
			s.logger.Debug("Skipping service export sync for non-global namespace",
				logfields.K8sSvcName, key.Name,
				logfields.K8sNamespace, key.Namespace,
			)
			return nil
		}
		return s.syncMCSAPIServiceSpec(ctx, serviceStore, serviceExportStore, key)
	}

	servicesSynced, serviceExportsSynced := false, false
	for serviceEvents != nil || serviceExportsEvents != nil {
		select {
		case ev, ok := <-serviceEvents:
			if !ok {
				serviceEvents = nil
				continue
			}

			if ev.Kind == resource.Sync {
				servicesSynced = true
				if servicesSynced && serviceExportsSynced {
					s.store.Synced(ctx, s.syncCallback)
				}
				ev.Done(nil)
				continue
			}

			ev.Done(syncServiceExport(ev.Key))

		case ev, ok := <-serviceExportsEvents:
			if !ok {
				serviceExportsEvents = nil
				continue
			}

			if ev.Kind == resource.Sync {
				serviceExportsSynced = true
				if servicesSynced && serviceExportsSynced {
					s.store.Synced(ctx, s.syncCallback)
				}
				ev.Done(nil)
				continue
			}

			ev.Done(syncServiceExport(ev.Key))

		case ev, ok := <-namespaceEvents:
			if !ok {
				s.logger.Info("Namespace event channel closed, ignoring future namespace events")
				namespaceEvents = nil
				continue
			}

			if ev.Kind == resource.Sync {
				ev.Done(nil)
				continue
			}

			// Handle namespace changes - resync all service exports in this namespace
			if ev.Object == nil {
				ev.Done(nil)
				continue
			}

			nsName := ev.Key.Name
			isGlobal := s.namespaceManager.IsGlobalNamespaceByObject(ev.Object)

			s.logger.Debug("Namespace global status changed, resyncing service exports",
				logfields.K8sNamespace, nsName,
				logfields.IsGlobalNamespace, isGlobal,
			)

			// Get all service exports in this namespace and resync them
			svcExports, err := serviceExportStore.ByIndex(cache.NamespaceIndex, nsName)
			if err != nil {
				s.logger.Warn("Failed to list service exports for namespace update",
					logfields.Error, err,
					logfields.K8sNamespace, nsName,
				)
				ev.Done(err)
				continue
			}

			for _, svcExport := range svcExports {
				key := resource.Key{Namespace: svcExport.Namespace, Name: svcExport.Name}
				if ev.Kind == resource.Delete || !isGlobal {
					// Namespace deleted or no longer global - delete service export from kvstore
					s.store.DeleteKey(ctx, types.NewEmptyMCSAPIServiceSpec(s.clusterName, key.Namespace, key.Name))
				} else {
					// Namespace became global - upsert service export
					s.syncMCSAPIServiceSpec(ctx, serviceStore, serviceExportStore, key)
				}
			}
			ev.Done(nil)
		}
	}
}

func (s *serviceExportSync) syncMCSAPIServiceSpec(
	ctx context.Context,
	serviceStore resource.Store[*slim_corev1.Service],
	serviceExportStore resource.Store[*mcsapiv1alpha1.ServiceExport],
	key resource.Key,
) error {
	svc, exist, err := serviceStore.GetByKey(key)
	if err != nil {
		return err
	}
	if !exist {
		return s.store.DeleteKey(ctx, types.NewEmptyMCSAPIServiceSpec(s.clusterName, key.Namespace, key.Name))
	}
	svcExport, exist, err := serviceExportStore.GetByKey(key)
	if err != nil {
		return err
	}
	if !exist {
		return s.store.DeleteKey(ctx, types.NewEmptyMCSAPIServiceSpec(s.clusterName, key.Namespace, key.Name))
	}
	if !checkLocalSlimSvcValidForExport(svc) {
		return s.store.DeleteKey(ctx, types.NewEmptyMCSAPIServiceSpec(s.clusterName, key.Namespace, key.Name))
	}

	mcsAPISvcSpec := types.FromCiliumServiceToMCSAPIServiceSpec(s.clusterName, svc, svcExport)
	return s.store.UpsertKey(ctx, mcsAPISvcSpec)
}
