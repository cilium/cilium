//  Copyright 2021 Authors of Cilium
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
	cilium_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/srv6policy"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
)

func (k *K8sWatcher) ciliumEgressSRv6PolicyInit(ciliumClient *k8s.K8sCiliumClient) {
	_, egpController := informer.NewInformer(
		cache.NewListWatchFromClient(ciliumClient.CiliumV2alpha1().RESTClient(),
			"ciliumegresssrv6policies", v1.NamespaceAll, fields.Everything()),
		&cilium_v2alpha1.CiliumEgressSRv6Policy{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(metricCESRP, metricCreate, valid, equal) }()
				if cesrp := k8s.ObjToCESRP(obj); cesrp != nil {
					valid = true
					err := k.addCiliumEgressSRv6Policy(cesrp)
					k.K8sEventProcessed(metricCESRP, metricCreate, err == nil)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(metricCESRP, metricUpdate, valid, equal) }()

				oldCesrp := k8s.ObjToCESRP(oldObj)
				if oldCesrp == nil {
					return
				}
				deleteErr := k.deleteCiliumEgressSRv6Policy(oldCesrp)
				newCesrp := k8s.ObjToCESRP(newObj)
				if newCesrp == nil {
					return
				}
				valid = true
				addErr := k.addCiliumEgressSRv6Policy(newCesrp)
				k.K8sEventProcessed(metricCESRP, metricUpdate, deleteErr == nil && addErr == nil)
			},
			DeleteFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(metricCESRP, metricDelete, valid, equal) }()
				cesrp := k8s.ObjToCESRP(obj)
				if cesrp == nil {
					return
				}
				valid = true
				err := k.deleteCiliumEgressSRv6Policy(cesrp)
				k.K8sEventProcessed(metricCESRP, metricDelete, err == nil)
			},
		},
		k8s.ConvertToCiliumEgressSRv6Policy,
	)

	k.blockWaitGroupToSyncResources(
		wait.NeverStop,
		nil,
		egpController.HasSynced,
		k8sAPIGroupCiliumEgressSRv6PolicyV2Alpha1,
	)

	go egpController.Run(wait.NeverStop)
	k.k8sAPIGroups.AddAPI(k8sAPIGroupCiliumEgressSRv6PolicyV2Alpha1)
}

func (k *K8sWatcher) addCiliumEgressSRv6Policy(cesrp *cilium_v2alpha1.CiliumEgressSRv6Policy) error {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.CiliumEgressSRv6PolicyName: cesrp.ObjectMeta.Name,
		logfields.K8sUID:                     cesrp.ObjectMeta.UID,
		logfields.K8sAPIVersion:              cesrp.TypeMeta.APIVersion,
	})

	ep, err := srv6policy.Parse(cesrp)
	if err != nil {
		scopedLog.WithError(err).Warn("Failed to add CiliumEgressSRv6Policy: malformed policy config.")
		return err
	}
	if _, err := k.srv6Manager.AddSRv6Policy(*ep); err != nil {
		scopedLog.WithError(err).Warn("Failed to add CiliumEgressSRv6Policy.")
		return err
	}

	scopedLog.Info("Added CiliumEgressSRv6Policy")
	return err
}

func (k *K8sWatcher) deleteCiliumEgressSRv6Policy(cesrp *cilium_v2alpha1.CiliumEgressSRv6Policy) error {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.CiliumEgressSRv6PolicyName: cesrp.ObjectMeta.Name,
		logfields.K8sUID:                     cesrp.ObjectMeta.UID,
		logfields.K8sAPIVersion:              cesrp.TypeMeta.APIVersion,
	})

	epID := srv6policy.ParseConfigID(cesrp)
	if err := k.srv6Manager.DeleteSRv6Policy(epID); err != nil {
		scopedLog.WithError(err).Warn("Failed to delete CiliumEgressSRv6Policy.")
		return err
	}

	scopedLog.Info("Deleted CiliumEgressSRv6Policy")
	return nil
}
