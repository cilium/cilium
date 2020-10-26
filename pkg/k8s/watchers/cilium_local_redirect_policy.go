//  Copyright 2020 Authors of Cilium
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package watchers

import (
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/redirectpolicy"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
)

func (k *K8sWatcher) ciliumLocalRedirectPolicyInit(ciliumLRPClient *k8s.K8sCiliumClient) {

	_, lrpController := informer.NewInformer(
		cache.NewListWatchFromClient(ciliumLRPClient.CiliumV2().RESTClient(),
			"ciliumlocalredirectpolicies", v1.NamespaceAll, fields.Everything()),
		&cilium_v2.CiliumLocalRedirectPolicy{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(metricCLRP, metricCreate, valid, equal) }()
				if cLRP := k8s.ObjToCLRP(obj); cLRP != nil {
					valid = true
					err := k.addCiliumLocalRedirectPolicy(cLRP)
					k.K8sEventProcessed(metricCLRP, metricCreate, err == nil)
				}

			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				log.Info("Local Redirect Policy updates are not handled")

			},
			DeleteFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(metricCLRP, metricDelete, valid, equal) }()
				cLRP := k8s.ObjToCLRP(obj)
				if cLRP == nil {
					return
				}
				valid = true
				err := k.deleteCiliumLocalRedirectPolicy(cLRP)
				k.K8sEventProcessed(metricCLRP, metricDelete, err == nil)
			},
		},
		k8s.ConvertToCiliumLocalRedirectPolicy,
	)

	k.blockWaitGroupToSyncResources(
		wait.NeverStop,
		nil,
		lrpController.HasSynced,
		k8sAPIGroupCiliumLocalRedirectPolicyV2,
	)

	go lrpController.Run(wait.NeverStop)
	k.k8sAPIGroups.AddAPI(k8sAPIGroupCiliumLocalRedirectPolicyV2)
}

func (k *K8sWatcher) addCiliumLocalRedirectPolicy(clrp *cilium_v2.CiliumLocalRedirectPolicy) error {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.CiliumLocalRedirectName: clrp.ObjectMeta.Name,
		logfields.K8sUID:                  clrp.ObjectMeta.UID,
		logfields.K8sAPIVersion:           clrp.TypeMeta.APIVersion,
		logfields.K8sNamespace:            clrp.ObjectMeta.Namespace,
	})

	scopedLog.Debug("Add CiliumLocalRedirectPolicy")

	rp, policyAddErr := redirectpolicy.Parse(clrp, true)
	if policyAddErr == nil {
		_, policyAddErr = k.redirectPolicyManager.AddRedirectPolicy(*rp)
	}

	if policyAddErr != nil {
		scopedLog.WithError(policyAddErr).Warn("Failed to add CiliumLocalRedirectPolicy")
	} else {
		scopedLog.Info("Added CiliumLocalRedirectPolicy")
	}

	//TODO update status

	return policyAddErr
}

func (k *K8sWatcher) deleteCiliumLocalRedirectPolicy(clrp *cilium_v2.CiliumLocalRedirectPolicy) error {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.CiliumLocalRedirectName: clrp.ObjectMeta.Name,
		logfields.K8sUID:                  clrp.ObjectMeta.UID,
		logfields.K8sAPIVersion:           clrp.TypeMeta.APIVersion,
		logfields.K8sNamespace:            clrp.ObjectMeta.Namespace,
	})

	scopedLog.Debug("Delete CiliumLocalRedirectPolicy")

	rp, policyDelErr := redirectpolicy.Parse(clrp, false)
	if policyDelErr == nil {
		policyDelErr = k.redirectPolicyManager.DeleteRedirectPolicy(*rp)
	}

	if policyDelErr != nil {
		scopedLog.WithError(policyDelErr).Warn("Failed to delete CiliumLocalRedirectPolicy")
	} else {
		scopedLog.Info("Deleted CiliumLocalRedirectPolicy")
	}

	return policyDelErr
}
