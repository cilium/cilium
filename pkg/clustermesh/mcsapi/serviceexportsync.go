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
	"github.com/cilium/cilium/pkg/clustermesh/operator"
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
func ServiceExportResource(lc cell.Lifecycle, cfg operator.MCSAPIConfig, cs client.Clientset, opts ...func(*metav1.ListOptions)) resource.Resource[*mcsapiv1alpha1.ServiceExport] {
	if !cs.IsEnabled() || !cfg.ClusterMeshEnableMCSAPI {
		return nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped(cs.MulticlusterV1alpha1().ServiceExports("")),
		opts...,
	)
	return resource.New[*mcsapiv1alpha1.ServiceExport](lc, lw, resource.WithMetric("ServiceExport"))
}

type ServiceExportSyncParameters struct {
	ClusterName    string
	ServiceExports resource.Resource[*mcsapiv1alpha1.ServiceExport]
	Services       resource.Resource[*slim_corev1.Service]
	Backend        store.SyncStoreBackend
	StoreFactory   store.Factory
	Store          store.SyncStore
	SyncCallback   func(context.Context)
}

func StartSynchronizingServiceExports(ctx context.Context, wg *sync.WaitGroup, cfg ServiceExportSyncParameters) {
	if cfg.Store == nil {
		if cfg.Backend == nil {
			// Needs to be assigned in a separate goroutine, since it might block
			// if the client is not yet initialized.
			cfg.Backend = kvstore.Client()
		}

		cfg.Store = cfg.StoreFactory.NewSyncStore(cfg.ClusterName,
			cfg.Backend, types.ServiceExportStorePrefix)
	}

	wg.Add(1)
	go func() {
		cfg.Store.Run(ctx)
		wg.Done()
	}()

	if cfg.ServiceExports == nil {
		cfg.Store.Synced(ctx, cfg.SyncCallback)
		return
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
					cfg.Store.Synced(ctx, cfg.SyncCallback)
				}
				ev.Done(nil)
				continue
			}

			ev.Done(syncMCSAPIServiceSpec(ctx, cfg.ClusterName, cfg.Store,
				serviceStore, serviceExportStore, ev.Key))

		case ev, ok := <-serviceExportsEvents:
			if !ok {
				serviceExportsEvents = nil
				continue
			}

			if ev.Kind == resource.Sync {
				serviceExportsSynced = true
				if servicesSynced && serviceExportsSynced {
					cfg.Store.Synced(ctx, cfg.SyncCallback)
				}
				ev.Done(nil)
				continue
			}

			ev.Done(syncMCSAPIServiceSpec(ctx, cfg.ClusterName, cfg.Store,
				serviceStore, serviceExportStore, ev.Key))
		}
	}
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
