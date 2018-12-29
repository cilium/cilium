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
	"time"

	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/service"
	"github.com/cilium/cilium/pkg/versioned"

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/sirupsen/logrus"
)

var (
	k8sSvcCache   = k8s.NewServiceCache()
	servicesStore *store.SharedStore
)

func k8sServiceHandler() {
	for {
		event, ok := <-k8sSvcCache.Events
		if !ok {
			return
		}

		log.WithFields(logrus.Fields{
			logfields.K8sSvcName:   event.ID.Name,
			logfields.K8sNamespace: event.ID.Namespace,
			"action":               event.Action.String(),
			"service":              event.Service.String(),
			"endpoints":            event.Endpoints.String(),
			"shared":               event.Service.Shared,
		}).Info("Kubernetes service definition changed")

		svcID := api.NewK8sServiceIdentifier(event.ID.Name, event.ID.Namespace, event.Service.Labels)

		cnpCache.Range(func(k, v interface{}) bool {
			cnp := v.(*cilium_v2.CiliumNetworkPolicy)
			if cnp.MatchesServiceIdentifier(svcID) {
				addDerivativeCNP(cnp)
			}
			return true
		})

		if synchronizeServices {
			svc := k8s.NewClusterService(event.ID, event.Service, event.Endpoints)
			svc.Cluster = option.Config.ClusterName

			if !event.Service.Shared {
				// The annotation may have been added, delete an eventual existing service
				servicesStore.DeleteLocalKey(&svc)
				continue
			}

			switch event.Action {
			case k8s.UpdateService, k8s.UpdateIngress:
				servicesStore.UpdateLocalKeySync(&svc)

			case k8s.DeleteService, k8s.DeleteIngress:
				servicesStore.DeleteLocalKey(&svc)
			}
		}
	}
}

func startSynchronizingServices() {
	log.Info("Starting to synchronize Kubernetes services to kvstore")

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

	// Watch for v1.Service changes and push changes into ServiceCache
	_, svcController := utils.ControllerFactory(
		k8s.Client().CoreV1().RESTClient(),
		&v1.Service{},
		utils.ResourceEventHandlerFactory(
			func(new interface{}) func() error {
				return func() error {
					log.Debugf("Received service addition %+v", new)
					k8sSvcCache.UpdateService(new.(*v1.Service))
					return nil
				}
			},
			func(old interface{}) func() error {
				return func() error {
					log.Debugf("Received service deletion %+v", old)
					k8sSvcCache.DeleteService(old.(*v1.Service))
					return nil
				}
			},
			func(old, new interface{}) func() error {
				return func() error {
					log.Debugf("Received service update %+v", new)
					k8sSvcCache.UpdateService(new.(*v1.Service))
					return nil
				}
			},
			func(m versioned.Map) versioned.Map {
				return m
			},
			&v1.Service{},
			k8s.Client(),
			0,
			nil,
		),
		fields.Everything(),
	)

	go svcController.Run(wait.NeverStop)

	// Watch for v1.Endpoints changes and push changes into ServiceCache
	_, endpointController := utils.ControllerFactory(
		k8s.Client().CoreV1().RESTClient(),
		&v1.Endpoints{},
		utils.ResourceEventHandlerFactory(
			func(new interface{}) func() error {
				return func() error {
					k8sSvcCache.UpdateEndpoints(new.(*v1.Endpoints))
					return nil
				}
			},
			func(old interface{}) func() error {
				return func() error {
					k8sSvcCache.DeleteEndpoints(old.(*v1.Endpoints))
					return nil
				}
			},
			func(old, new interface{}) func() error {
				return func() error {
					k8sSvcCache.UpdateEndpoints(new.(*v1.Endpoints))
					return nil
				}
			},
			func(m versioned.Map) versioned.Map {
				return m
			},
			&v1.Endpoints{},
			k8s.Client(),
			0,
			nil,
		),
		// Don't get any events from kubernetes endpoints.
		fields.ParseSelectorOrDie("metadata.name!=kube-scheduler,metadata.name!=kube-controller-manager"),
	)

	go endpointController.Run(wait.NeverStop)
	go k8sServiceHandler()
}
