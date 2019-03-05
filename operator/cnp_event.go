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

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/k8s"
	informer "github.com/cilium/cilium/pkg/k8s/client/informers/externalversions"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/policy/groups"

	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
)

const (
	reSyncPeriod = 5 * time.Minute
)

func init() {
	runtime.ErrorHandlers = []func(error){
		k8s.K8sErrorHandler,
	}
}

func enableCNPWatcher() error {
	si := informer.NewSharedInformerFactory(ciliumK8sClient, reSyncPeriod)
	ciliumV2Controller := si.Cilium().V2().CiliumNetworkPolicies().Informer()
	ciliumV2Controller.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			metrics.EventTSK8s.SetToCurrentTime()
			if cnp := k8s.CopyObjToV2CNP(obj); cnp != nil {
				groups.AddDerivativeCNPIfNeeded(cnp)
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			metrics.EventTSK8s.SetToCurrentTime()
			if oldCNP := k8s.CopyObjToV2CNP(oldObj); oldCNP != nil {
				if newCNP := k8s.CopyObjToV2CNP(newObj); newCNP != nil {
					groups.UpdateDerivativeCNPIfNeeded(newCNP, oldCNP)
				}
			}
		},
		DeleteFunc: func(obj interface{}) {
			metrics.EventTSK8s.SetToCurrentTime()
			if cnp := k8s.CopyObjToV2CNP(obj); cnp != nil {
				// The derivative policy will be deleted by the parent but need
				// to delete the cnp from the pooling.
				groups.DeleteDerivativeFromCache(cnp)
			}
		},
	})
	si.Start(wait.NeverStop)

	controller.NewManager().UpdateController("cnp-to-groups",
		controller.ControllerParams{
			DoFunc: func() error {
				groups.UpdateCNPInformation()
				return nil
			},
			RunInterval: 5 * time.Minute,
		})

	return nil
}
