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
	"github.com/cilium/cilium/pkg/egresspolicy"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
)

func (k *K8sWatcher) ciliumEgressNATPolicyInit(ciliumNPClient *k8s.K8sCiliumClient) {
	_, egpController := informer.NewInformer(
		cache.NewListWatchFromClient(ciliumNPClient.CiliumV2alpha1().RESTClient(),
			"ciliumegressnatpolicies", v1.NamespaceAll, fields.Everything()),
		&cilium_v2alpha1.CiliumEgressNATPolicy{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(metricCENP, metricCreate, valid, equal) }()
				if cenp := k8s.ObjToCENP(obj); cenp != nil {
					valid = true
					err := k.addCiliumEgressNATPolicy(cenp)
					k.K8sEventProcessed(metricCENP, metricCreate, err == nil)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(metricCENP, metricUpdate, valid, equal) }()

				oldCenp := k8s.ObjToCENP(oldObj)
				if oldCenp == nil {
					return
				}
				deleteErr := k.deleteCiliumEgressNATPolicy(oldCenp)
				newCenp := k8s.ObjToCENP(newObj)
				if newCenp == nil {
					return
				}
				valid = true
				addErr := k.addCiliumEgressNATPolicy(newCenp)
				k.K8sEventProcessed(metricCENP, metricUpdate, deleteErr == nil && addErr == nil)
			},
			DeleteFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(metricCENP, metricDelete, valid, equal) }()
				cenp := k8s.ObjToCENP(obj)
				if cenp == nil {
					return
				}
				valid = true
				err := k.deleteCiliumEgressNATPolicy(cenp)
				k.K8sEventProcessed(metricCENP, metricDelete, err == nil)
			},
		},
		k8s.ConvertToCiliumEgressNATPolicy,
	)

	k.blockWaitGroupToSyncResources(
		wait.NeverStop,
		nil,
		egpController.HasSynced,
		k8sAPIGroupCiliumEgressNATPolicyV2,
	)

	go egpController.Run(wait.NeverStop)
	k.k8sAPIGroups.AddAPI(k8sAPIGroupCiliumEgressNATPolicyV2)
}

func (k *K8sWatcher) addCiliumEgressNATPolicy(cenp *cilium_v2alpha1.CiliumEgressNATPolicy) error {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.CiliumEgressNATPolicyName: cenp.ObjectMeta.Name,
		logfields.K8sUID:                    cenp.ObjectMeta.UID,
		logfields.K8sAPIVersion:             cenp.TypeMeta.APIVersion,
	})

	ep, err := egresspolicy.Parse(cenp)
	if err != nil {
		scopedLog.WithError(err).Warn("Failed to add CiliumEgressNATPolicy: malformed policy config.")
		return err
	}
	if _, err := k.egressPolicyManager.AddEgressPolicy(*ep); err != nil {
		scopedLog.WithError(err).Warn("Failed to add CiliumEgressNATPolicy.")
		return err
	}

	scopedLog.Info("Added CiliumEgressNATPolicy")
	return err
}

func (k *K8sWatcher) deleteCiliumEgressNATPolicy(cenp *cilium_v2alpha1.CiliumEgressNATPolicy) error {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.CiliumEgressNATPolicyName: cenp.ObjectMeta.Name,
		logfields.K8sUID:                    cenp.ObjectMeta.UID,
		logfields.K8sAPIVersion:             cenp.TypeMeta.APIVersion,
	})

	epID := egresspolicy.ParseConfigID(cenp)
	if err := k.egressPolicyManager.DeleteEgressPolicy(epID); err != nil {
		scopedLog.WithError(err).Warn("Failed to delete CiliumEgressNATPolicy.")
		return err
	}

	scopedLog.Info("Deleted CiliumEgressNATPolicy")
	return nil
}
