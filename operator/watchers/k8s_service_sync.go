// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"sync"

	"github.com/sirupsen/logrus"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/k8s"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	serviceStore "github.com/cilium/cilium/pkg/service/store"
)

var (
	K8sSvcCache = k8s.NewServiceCache(nil)

	// k8sSvcCacheSynced is used do signalize when all services are synced with
	// k8s.
	k8sSvcCacheSynced = make(chan struct{})
	kvs               store.SyncStore
)

func k8sServiceHandler(ctx context.Context, cinfo cmtypes.ClusterInfo, shared bool) {
	serviceHandler := func(event k8s.ServiceEvent) {
		defer event.SWG.Done()

		svc := k8s.NewClusterService(event.ID, event.Service, event.Endpoints)
		svc.Cluster = cinfo.Name
		svc.ClusterID = cinfo.ID

		scopedLog := log.WithFields(logrus.Fields{
			logfields.K8sSvcName:   event.ID.Name,
			logfields.K8sNamespace: event.ID.Namespace,
			"action":               event.Action.String(),
			"service":              event.Service.String(),
			"endpoints":            event.Endpoints.String(),
			"shared":               event.Service.Shared,
		})
		scopedLog.Debug("Kubernetes service definition changed")

		if shared && !event.Service.Shared {
			// The annotation may have been added, delete an eventual existing service
			kvs.DeleteKey(ctx, &svc)
			return
		}

		switch event.Action {
		case k8s.UpdateService:
			if err := kvs.UpsertKey(ctx, &svc); err != nil {
				// An error is triggered only in case it concerns service marshaling,
				// as kvstore operations are automatically re-tried in case of error.
				scopedLog.WithError(err).Warning("Failed synchronizing service")
			}

		case k8s.DeleteService:
			kvs.DeleteKey(ctx, &svc)
		}
	}
	for {
		select {
		case event, ok := <-K8sSvcCache.Events:
			if !ok {
				return
			}

			serviceHandler(event)

		case <-ctx.Done():
			return
		}
	}
}

type ServiceSyncParameters struct {
	ClusterInfo  cmtypes.ClusterInfo
	Clientset    k8sClient.Clientset
	Services     resource.Resource[*slim_corev1.Service]
	Endpoints    resource.Resource[*k8s.Endpoints]
	Backend      store.SyncStoreBackend
	SharedOnly   bool
	StoreFactory store.Factory
}

// StartSynchronizingServices starts a controller for synchronizing services from k8s to kvstore
// 'shared' specifies whether only shared services are synchronized. If 'false' then all services
// will be synchronized. For clustermesh we only need to synchronize shared services, while for
// VM support we need to sync all the services.
func StartSynchronizingServices(ctx context.Context, wg *sync.WaitGroup, cfg ServiceSyncParameters) {
	kvstoreReady := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		if cfg.Backend == nil {
			// Needs to be assigned in a separate goroutine, since it might block
			// if the client is not yet initialized.
			cfg.Backend = kvstore.Client()
		}

		store := cfg.StoreFactory.NewSyncStore(cfg.ClusterInfo.Name,
			cfg.Backend, serviceStore.ServiceStorePrefix)
		kvs = store
		close(kvstoreReady)
		store.Run(ctx)
	}()

	// Start synchronizing ServiceCache to kvstore
	wg.Add(1)
	go func() {
		defer wg.Done()

		// Wait for kvstore
		<-kvstoreReady

		log.Info("Starting to synchronize Kubernetes services to kvstore")
		k8sServiceHandler(ctx, cfg.ClusterInfo, cfg.SharedOnly)
	}()

	// Start populating the service cache with Kubernetes services and endpoints
	wg.Add(1)
	go func() {
		defer wg.Done()

		swg := lock.NewStoppableWaitGroup()
		serviceEvents := cfg.Services.Events(ctx)
		endpointEvents := cfg.Endpoints.Events(ctx)

		servicesSynced, endpointsSynced := false, false

		// onSync is called when the initial listing and processing of
		// services and endpoints has finished.
		onSync := func() {
			// Wait until all work has been finished up to the sync event.
			swg.Stop()
			swg.Wait()

			// k8sSvcCacheSynced is used by GetServiceIP() to not query an incomplete
			// service cache.
			close(k8sSvcCacheSynced)

			log.Info("Initial list of services successfully received from Kubernetes")
			kvs.Synced(ctx)
		}

		for serviceEvents != nil || endpointEvents != nil {
			select {
			case ev, ok := <-serviceEvents:
				if !ok {
					serviceEvents = nil
					continue
				}

				// Ignore kubernetes endpoints events
				if ev.Key.Name == "kube-scheduler" || ev.Key.Name == "kube-controller-manager" {
					ev.Done(nil)
					continue
				}

				switch ev.Kind {
				case resource.Sync:
					servicesSynced = true
					if servicesSynced && endpointsSynced {
						onSync()
					}
				case resource.Upsert:
					K8sSvcCache.UpdateService(ev.Object, swg)
				case resource.Delete:
					K8sSvcCache.DeleteService(ev.Object, swg)
				}
				ev.Done(nil)

			case ev, ok := <-endpointEvents:
				if !ok {
					endpointEvents = nil
					continue
				}

				switch ev.Kind {
				case resource.Sync:
					endpointsSynced = true
					if servicesSynced && endpointsSynced {
						onSync()
					}
				case resource.Upsert:
					K8sSvcCache.UpdateEndpoints(ev.Object, swg)
				case resource.Delete:
					K8sSvcCache.DeleteEndpoints(ev.Object.EndpointSliceID, swg)
				}
				ev.Done(nil)
			}
		}
	}()
}

// ServiceGetter is a wrapper for 2 k8sCaches, its intention is for
// `shortCutK8sCache` to be used until `k8sSvcCacheSynced` is closed, for which
// `k8sCache` is started to be used.
type ServiceGetter struct {
	shortCutK8sCache k8s.ServiceIPGetter
	k8sCache         k8s.ServiceIPGetter
}

// NewServiceGetter returns a new ServiceGetter holding 2 k8sCaches
func NewServiceGetter(sc *k8s.ServiceCache) *ServiceGetter {
	return &ServiceGetter{
		shortCutK8sCache: sc,
		k8sCache:         K8sSvcCache,
	}
}

// GetServiceIP returns the result of GetServiceIP for `s.shortCutK8sCache`
// until `k8sSvcCacheSynced` is closed. This is helpful as we can have a
// shortcut of `s.k8sCache` since we can pre-populate `s.shortCutK8sCache` with
// the entries that we need until `s.k8sCache` is synchronized with kubernetes.
func (s *ServiceGetter) GetServiceIP(svcID k8s.ServiceID) *loadbalancer.L3n4Addr {
	select {
	case <-k8sSvcCacheSynced:
		return s.k8sCache.GetServiceIP(svcID)
	default:
		return s.shortCutK8sCache.GetServiceIP(svcID)
	}
}
