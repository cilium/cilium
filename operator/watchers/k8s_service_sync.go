// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/k8s"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/k8s/watchers/subscriber"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	serviceCache "github.com/cilium/cilium/pkg/service/cache"
	serviceStore "github.com/cilium/cilium/pkg/service/store"
)

var (
	kvs        *store.SharedStore
	sharedOnly bool
)

func k8sEventMetric(scope, action string) {
	metrics.EventTS.WithLabelValues(metrics.LabelEventSourceK8s, scope, action)
}

func k8sServiceHandler(cache serviceCache.ServiceCache, clusterName string) {
	for event := range cache.Events(context.TODO()) {
		svc := k8s.NewClusterService(event.ID, event.Service, event.Endpoints)
		svc.Cluster = clusterName

		log.WithFields(logrus.Fields{
			logfields.K8sSvcName:   event.ID.Name,
			logfields.K8sNamespace: event.ID.Namespace,
			"action":               event.Action.String(),
			"service":              event.Service.String(),
			"endpoints":            event.Endpoints.String(),
			"shared":               event.Service.Shared,
		}).Debug("Kubernetes service definition changed")

		if sharedOnly && !event.Service.Shared {
			// The annotation may have been added, delete an eventual existing service
			kvs.DeleteLocalKey(context.TODO(), &svc)
			return
		}

		switch event.Action {
		case serviceCache.UpdateService:
			kvs.UpdateLocalKeySync(context.TODO(), &svc)

		case serviceCache.DeleteService:
			kvs.DeleteLocalKey(context.TODO(), &svc)
		}
	}
}

// ServiceSyncConfiguration is the required configuration for StartSynchronizingServices
type ServiceSyncConfiguration interface {
	// LocalClusterName must return the local cluster name
	LocalClusterName() string

	utils.ServiceConfiguration
}

// StartSynchronizingServices starts a controller for synchronizing services from k8s to kvstore
// 'shared' specifies whether only shared services are synchronized. If 'false' then all services
// will be synchronized. For clustermesh we only need to synchronize shared services, while for
// VM support we need to sync all the services.
func StartSynchronizingServices(clientset k8sClient.Clientset, sc serviceCache.ServiceCache, shared bool, cfg ServiceSyncConfiguration) {
	sharedOnly = shared

	go func() {
		log.Info("Waiting to join kvstore")
		store, err := store.JoinSharedStore(store.Configuration{
			Prefix:                  serviceStore.ServiceStorePrefix,
			SynchronizationInterval: 5 * time.Minute,
			SharedKeyDeleteDelay:    0,
			KeyCreator: func() store.Key {
				return &serviceStore.ClusterService{}
			},
			Backend:  nil,
			Observer: nil,
			Context:  nil,
		})

		if err != nil {
			log.WithError(err).Fatal("Unable to join kvstore store to announce services")
		}

		kvs = store
		log.Info("Starting to synchronize Kubernetes services to kvstore")
		go k8sServiceHandler(sc, cfg.LocalClusterName())
	}()
}
