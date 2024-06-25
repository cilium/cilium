// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mcsapi

import (
	"context"
	"sync"

	"github.com/cilium/hive/cell"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	mcsapiv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	"github.com/cilium/cilium/pkg/clustermesh/mcsapi/types"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "mcsapi")

// ServiceExportResource builds the Resource[ServiceExport] object.
func ServiceExportResource(lc cell.Lifecycle, cs client.Clientset, opts ...func(*metav1.ListOptions)) resource.Resource[*mcsapiv1alpha1.ServiceExport] {
	if !cs.IsEnabled() {
		return nil
	}

	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped(cs.MulticlusterV1alpha1().ServiceExports("")),
		opts...,
	)
	return resource.New[*mcsapiv1alpha1.ServiceExport](lc, lw, resource.WithMetric("ServiceExport"))
}

type ServiceExportSyncParameters struct {
	ClusterName             string
	ClusterMeshEnableMCSAPI bool
	Clientset               client.Clientset
	ServiceExports          resource.Resource[*mcsapiv1alpha1.ServiceExport]
	Services                resource.Resource[*slim_corev1.Service]
	Backend                 store.SyncStoreBackend
	StoreFactory            store.Factory
	SyncCallback            func(context.Context)

	// Used for testing purposes
	store        store.SyncStore
	skipCrdCheck bool
}

func StartSynchronizingServiceExports(ctx context.Context, cfg ServiceExportSyncParameters) {
	if cfg.store == nil {
		if cfg.Backend == nil {
			cfg.Backend = kvstore.Client()
		}

		cfg.store = cfg.StoreFactory.NewSyncStore(cfg.ClusterName,
			cfg.Backend, types.ServiceExportStorePrefix)
	}

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		cfg.store.Run(ctx)
		wg.Done()
	}()

	if !cfg.ClusterMeshEnableMCSAPI || cfg.ServiceExports == nil {
		// We pretend that service exports are synced even if the feature is
		// disabled to simplify consumers logic so that they don't have to do any
		// special handling/checks if a remote cluster has this feature disabled
		// as it's the only cluster mesh type that can be disabled separately.
		// This is especially useful in the case of the kvstoremesh.
		cfg.store.Synced(ctx, cfg.SyncCallback)
		return
	}
	if !cfg.skipCrdCheck {
		err := checkCRD(ctx, cfg.Clientset, mcsapiv1alpha1.SchemeGroupVersion.WithKind("serviceexports"))
		if err != nil {
			log.WithError(err).Warn("starting synchronizing service exports without the required CRD installed")
			// Also pretend that the service exports are synced for the same reason
			// as above.
			cfg.store.Synced(ctx, cfg.SyncCallback)
			return
		}
	}

	serviceEvents := cfg.Services.Events(ctx)
	serviceStore, err := cfg.Services.Store(ctx)
	if err != nil {
		log.WithError(err).Error("can't init service store")
		return
	}
	serviceExportsEvents := cfg.ServiceExports.Events(ctx)
	serviceExportStore, err := cfg.ServiceExports.Store(ctx)
	if err != nil {
		log.WithError(err).Error("can't init service export store")
		return
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
					cfg.store.Synced(ctx, cfg.SyncCallback)
				}
				ev.Done(nil)
				continue
			}

			ev.Done(syncMCSAPIServiceSpec(ctx, cfg.ClusterName, cfg.store,
				serviceStore, serviceExportStore, ev.Key))

		case ev, ok := <-serviceExportsEvents:
			if !ok {
				serviceExportsEvents = nil
				continue
			}

			if ev.Kind == resource.Sync {
				serviceExportsSynced = true
				if servicesSynced && serviceExportsSynced {
					cfg.store.Synced(ctx, cfg.SyncCallback)
				}
				ev.Done(nil)
				continue
			}

			ev.Done(syncMCSAPIServiceSpec(ctx, cfg.ClusterName, cfg.store,
				serviceStore, serviceExportStore, ev.Key))
		}
	}
	wg.Wait()
}

func syncMCSAPIServiceSpec(
	ctx context.Context, clusterName string, kvs store.SyncStore,
	serviceStore resource.Store[*slim_corev1.Service],
	serviceExportStore resource.Store[*mcsapiv1alpha1.ServiceExport],
	key resource.Key,
) error {
	svc, exist, err := serviceStore.GetByKey(key)
	if err != nil {
		return err
	}
	if !exist {
		return kvs.DeleteKey(ctx, types.NewEmptyMCSAPIServiceSpec(clusterName, key.Namespace, key.Name))
	}
	svcExport, exist, err := serviceExportStore.GetByKey(key)
	if err != nil {
		return err
	}
	if !exist {
		return kvs.DeleteKey(ctx, types.NewEmptyMCSAPIServiceSpec(clusterName, key.Namespace, key.Name))
	}

	mcsAPISvcSpec := types.FromCiliumServiceToMCSAPIServiceSpec(clusterName, svc, svcExport)
	return kvs.UpsertKey(ctx, mcsAPISvcSpec)
}
