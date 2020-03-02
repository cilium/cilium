// Copyright 2016-2019 Authors of Cilium
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

package watchers

import (
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/serializer"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

func (k *K8sWatcher) servicesInit(k8sClient kubernetes.Interface, serSvcs *serializer.FunctionQueue, swgSvcs *lock.StoppableWaitGroup) {

	_, svcController := informer.NewInformer(
		cache.NewListWatchFromClient(k8sClient.CoreV1().RESTClient(),
			"services", v1.NamespaceAll, fields.Everything()),
		&v1.Service{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(metricService, metricCreate, valid, equal) }()
				if k8sSvc := k8s.CopyObjToV1Services(obj); k8sSvc != nil {
					valid = true
					swgSvcs.Add()
					serSvcs.Enqueue(func() error {
						defer swgSvcs.Done()
						err := k.addK8sServiceV1(k8sSvc, swgSvcs)
						k.K8sEventProcessed(metricService, metricCreate, err == nil)
						return nil
					}, serializer.NoRetry)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(metricService, metricUpdate, valid, equal) }()
				if oldk8sSvc := k8s.CopyObjToV1Services(oldObj); oldk8sSvc != nil {
					valid = true
					if newk8sSvc := k8s.CopyObjToV1Services(newObj); newk8sSvc != nil {
						if k8s.EqualV1Services(oldk8sSvc, newk8sSvc, k.datapath.LocalNodeAddressing()) {
							equal = true
							return
						}

						swgSvcs.Add()
						serSvcs.Enqueue(func() error {
							defer swgSvcs.Done()
							err := k.updateK8sServiceV1(oldk8sSvc, newk8sSvc, swgSvcs)
							k.K8sEventProcessed(metricService, metricUpdate, err == nil)
							return nil
						}, serializer.NoRetry)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(metricService, metricDelete, valid, equal) }()
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

				valid = true
				swgSvcs.Add()
				serSvcs.Enqueue(func() error {
					defer swgSvcs.Done()
					err := k.deleteK8sServiceV1(k8sSvc, swgSvcs)
					k.K8sEventProcessed(metricService, metricDelete, err == nil)
					return nil
				}, serializer.NoRetry)
			},
		},
		k8s.ConvertToK8sService,
	)
	k.blockWaitGroupToSyncResources(wait.NeverStop, swgSvcs, svcController, K8sAPIGroupServiceV1Core)
	go svcController.Run(wait.NeverStop)
	k.k8sAPIGroups.addAPI(K8sAPIGroupServiceV1Core)
}

func (k *K8sWatcher) addK8sServiceV1(svc *types.Service, swg *lock.StoppableWaitGroup) error {
	k.K8sSvcCache.UpdateService(svc, swg)
	return nil
}

func (k *K8sWatcher) updateK8sServiceV1(oldSvc, newSvc *types.Service, swg *lock.StoppableWaitGroup) error {
	return k.addK8sServiceV1(newSvc, swg)
}

func (k *K8sWatcher) deleteK8sServiceV1(svc *types.Service, swg *lock.StoppableWaitGroup) error {
	k.K8sSvcCache.DeleteService(svc, swg)
	return nil
}
