// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"time"

	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/serializer"
	"github.com/cilium/cilium/pkg/service"

	"github.com/sirupsen/logrus"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
)

var (
	k8sSvcCache = k8s.NewServiceCache()
	// k8sSvcCacheSynced is used do signalize when all services are synced with
	// k8s.
	k8sSvcCacheSynced = make(chan struct{})
	servicesStore     *store.SharedStore
)

func k8sServiceHandler() {
	serviceHandler := func(event k8s.ServiceEvent) {
		defer event.SWG.Done()

		svc := k8s.NewClusterService(event.ID, event.Service, event.Endpoints)
		svc.Cluster = option.Config.ClusterName

		log.WithFields(logrus.Fields{
			logfields.K8sSvcName:   event.ID.Name,
			logfields.K8sNamespace: event.ID.Namespace,
			"action":               event.Action.String(),
			"service":              event.Service.String(),
			"endpoints":            event.Endpoints.String(),
			"shared":               event.Service.Shared,
		}).Debug("Kubernetes service definition changed")

		if !event.Service.Shared {
			// The annotation may have been added, delete an eventual existing service
			servicesStore.DeleteLocalKey(context.TODO(), &svc)
			return
		}

		switch event.Action {
		case k8s.UpdateService:
			servicesStore.UpdateLocalKeySync(context.TODO(), &svc)

		case k8s.DeleteService:
			servicesStore.DeleteLocalKey(context.TODO(), &svc)
		}
	}
	for {
		event, ok := <-k8sSvcCache.Events
		if !ok {
			return
		}

		serviceHandler(event)
	}
}

func startSynchronizingServices() {
	log.Info("Starting to synchronize k8s services to kvstore...")

	readyChan := make(chan struct{}, 0)

	go func() {
		store, err := store.JoinSharedStore(store.Configuration{
			Prefix: service.ServiceStorePrefix,
			KeyCreator: func() store.Key {
				return &service.ClusterService{}
			},
			SynchronizationInterval: 5 * time.Minute,
		})

		if err != nil {
			log.WithError(err).Fatal("Unable to join kvstore store to announce services")
		}

		servicesStore = store
		close(readyChan)
	}()

	serSvcs := serializer.NewFunctionQueue(1024)
	swgSvcs := lock.NewStoppableWaitGroup()

	serEps := serializer.NewFunctionQueue(1024)
	swgEps := lock.NewStoppableWaitGroup()

	// Watch for v1.Service changes and push changes into ServiceCache
	_, svcController := informer.NewInformer(
		cache.NewListWatchFromClient(k8s.Client().CoreV1().RESTClient(),
			"services", v1.NamespaceAll, fields.Everything()),
		&v1.Service{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				metrics.EventTSK8s.SetToCurrentTime()
				if k8sSvc := k8s.CopyObjToV1Services(obj); k8sSvc != nil {
					log.Debugf("Received service addition %+v", k8sSvc)
					swgSvcs.Add()
					serSvcs.Enqueue(func() error {
						defer swgSvcs.Done()
						k8sSvcCache.UpdateService(k8sSvc, swgSvcs)
						return nil
					}, serializer.NoRetry)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				metrics.EventTSK8s.SetToCurrentTime()
				if oldk8sSvc := k8s.CopyObjToV1Services(oldObj); oldk8sSvc != nil {
					if newk8sSvc := k8s.CopyObjToV1Services(newObj); newk8sSvc != nil {
						if k8s.EqualV1Services(oldk8sSvc, newk8sSvc) {
							return
						}

						log.Debugf("Received service update %+v", newk8sSvc)
						swgSvcs.Add()
						serSvcs.Enqueue(func() error {
							defer swgSvcs.Done()
							k8sSvcCache.UpdateService(newk8sSvc, swgSvcs)
							return nil
						}, serializer.NoRetry)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				metrics.EventTSK8s.SetToCurrentTime()
				k8sSvc := k8s.CopyObjToV1Services(obj)
				if k8sSvc == nil {
					deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
					if !ok {
						return
					}
					// Delete was not observed by the watcher but is
					// removed from kube-apiserver. This is the last
					// known state and the object no longer exists.
					k8sSvc = k8s.CopyObjToV1Services(deletedObj.Obj)
					if k8sSvc == nil {
						return
					}
				}
				log.Debugf("Received service deletion %+v", k8sSvc)
				swgSvcs.Add()
				serSvcs.Enqueue(func() error {
					defer swgSvcs.Done()
					k8sSvcCache.DeleteService(k8sSvc, swgSvcs)
					return nil
				}, serializer.NoRetry)
			},
		},
		k8s.ConvertToK8sService,
	)

	go svcController.Run(wait.NeverStop)

	// Watch for v1.Endpoints changes and push changes into ServiceCache
	_, endpointController := informer.NewInformer(
		cache.NewListWatchFromClient(k8s.Client().CoreV1().RESTClient(),
			"endpoints", v1.NamespaceAll,
			// Don't get any events from kubernetes endpoints.
			fields.ParseSelectorOrDie("metadata.name!=kube-scheduler,metadata.name!=kube-controller-manager"),
		),
		&v1.Endpoints{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				metrics.EventTSK8s.SetToCurrentTime()
				if k8sEP := k8s.CopyObjToV1Endpoints(obj); k8sEP != nil {
					swgEps.Add()
					serEps.Enqueue(func() error {
						defer swgEps.Done()
						k8sSvcCache.UpdateEndpoints(k8sEP, swgEps)
						return nil
					}, serializer.NoRetry)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				metrics.EventTSK8s.SetToCurrentTime()
				if oldk8sEP := k8s.CopyObjToV1Endpoints(oldObj); oldk8sEP != nil {
					if newk8sEP := k8s.CopyObjToV1Endpoints(newObj); newk8sEP != nil {
						if k8s.EqualV1Endpoints(oldk8sEP, newk8sEP) {
							return
						}
						swgEps.Add()
						serEps.Enqueue(func() error {
							defer swgEps.Done()
							k8sSvcCache.UpdateEndpoints(newk8sEP, swgEps)
							return nil
						}, serializer.NoRetry)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				metrics.EventTSK8s.SetToCurrentTime()
				k8sEP := k8s.CopyObjToV1Endpoints(obj)
				if k8sEP == nil {
					deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
					if !ok {
						return
					}
					// Delete was not observed by the watcher but is
					// removed from kube-apiserver. This is the last
					// known state and the object no longer exists.
					k8sEP = k8s.CopyObjToV1Endpoints(deletedObj.Obj)
					if k8sEP == nil {
						return
					}
				}
				swgEps.Add()
				serEps.Enqueue(func() error {
					defer swgEps.Done()
					k8sSvcCache.DeleteEndpoints(k8sEP, swgEps)
					return nil
				}, serializer.NoRetry)
			},
		},
		k8s.ConvertToK8sEndpoints,
	)

	go endpointController.Run(wait.NeverStop)

	go func() {
		cache.WaitForCacheSync(wait.NeverStop, svcController.HasSynced)
		swgSvcs.Stop()
		cache.WaitForCacheSync(wait.NeverStop, endpointController.HasSynced)
		swgEps.Stop()

		swgSvcs.Wait()
		swgEps.Wait()
		close(k8sSvcCacheSynced)
	}()

	go func() {
		<-readyChan
		log.Info("Starting to synchronize Kubernetes services to kvstore")
		k8sServiceHandler()
	}()
}
