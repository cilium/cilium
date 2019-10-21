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
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/serializer"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

func (k *K8sWatcher) networkPoliciesInit(k8sClient kubernetes.Interface, serKNPs *serializer.FunctionQueue, swgKNPs *lock.StoppableWaitGroup) {

	_, policyController := informer.NewInformer(
		cache.NewListWatchFromClient(k8sClient.NetworkingV1().RESTClient(),
			"networkpolicies", v1.NamespaceAll, fields.Everything()),
		&networkingv1.NetworkPolicy{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(metricKNP, metricCreate, valid, equal) }()
				if k8sNP := k8s.CopyObjToV1NetworkPolicy(obj); k8sNP != nil {
					valid = true
					swgKNPs.Add()
					serKNPs.Enqueue(func() error {
						defer swgKNPs.Done()
						err := k.addK8sNetworkPolicyV1(k8sNP)
						k.K8sEventProcessed(metricKNP, metricCreate, err == nil)
						return nil
					}, serializer.NoRetry)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(metricKNP, metricUpdate, valid, equal) }()
				if oldK8sNP := k8s.CopyObjToV1NetworkPolicy(oldObj); oldK8sNP != nil {
					valid = true
					if newK8sNP := k8s.CopyObjToV1NetworkPolicy(newObj); newK8sNP != nil {
						if k8s.EqualV1NetworkPolicy(oldK8sNP, newK8sNP) {
							equal = true
							return
						}

						swgKNPs.Add()
						serKNPs.Enqueue(func() error {
							defer swgKNPs.Done()
							err := k.updateK8sNetworkPolicyV1(oldK8sNP, newK8sNP)
							k.K8sEventProcessed(metricKNP, metricUpdate, err == nil)
							return nil
						}, serializer.NoRetry)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(metricKNP, metricDelete, valid, equal) }()
				k8sNP := k8s.CopyObjToV1NetworkPolicy(obj)
				if k8sNP == nil {
					deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
					if !ok {
						return
					}
					// Delete was not observed by the watcher but is
					// removed from kube-apiserver. This is the last
					// known state and the object no longer exists.
					k8sNP = k8s.CopyObjToV1NetworkPolicy(deletedObj.Obj)
					if k8sNP == nil {
						return
					}
				}

				valid = true
				swgKNPs.Add()
				serKNPs.Enqueue(func() error {
					defer swgKNPs.Done()
					err := k.deleteK8sNetworkPolicyV1(k8sNP)
					k.K8sEventProcessed(metricKNP, metricDelete, err == nil)
					return nil
				}, serializer.NoRetry)
			},
		},
		k8s.ConvertToNetworkPolicy,
	)
	k.blockWaitGroupToSyncResources(wait.NeverStop, swgKNPs, policyController, k8sAPIGroupNetworkingV1Core)
	go policyController.Run(wait.NeverStop)

	k.k8sAPIGroups.addAPI(k8sAPIGroupNetworkingV1Core)
}

func (k *K8sWatcher) addK8sNetworkPolicyV1(k8sNP *types.NetworkPolicy) error {
	scopedLog := log.WithField(logfields.K8sAPIVersion, k8sNP.TypeMeta.APIVersion)
	rules, err := k8s.ParseNetworkPolicy(k8sNP.NetworkPolicy)
	if err != nil {
		scopedLog.WithError(err).WithFields(logrus.Fields{
			logfields.CiliumNetworkPolicy: logfields.Repr(k8sNP),
		}).Error("Error while parsing k8s kubernetes NetworkPolicy")
		return err
	}
	scopedLog = scopedLog.WithField(logfields.K8sNetworkPolicyName, k8sNP.ObjectMeta.Name)

	opts := policy.AddOptions{Replace: true, Source: metrics.LabelEventSourceK8s}
	if _, err := k.policyManager.PolicyAdd(rules, &opts); err != nil {
		scopedLog.WithError(err).WithFields(logrus.Fields{
			logfields.CiliumNetworkPolicy: logfields.Repr(rules),
		}).Error("Unable to add NetworkPolicy rules to policy repository")
		return err
	}

	scopedLog.Info("NetworkPolicy successfully added")
	return nil
}

func (k *K8sWatcher) updateK8sNetworkPolicyV1(oldk8sNP, newk8sNP *types.NetworkPolicy) error {
	log.WithFields(logrus.Fields{
		logfields.K8sAPIVersion:                 oldk8sNP.TypeMeta.APIVersion,
		logfields.K8sNetworkPolicyName + ".old": oldk8sNP.ObjectMeta.Name,
		logfields.K8sNamespace + ".old":         oldk8sNP.ObjectMeta.Namespace,
		logfields.K8sNetworkPolicyName:          newk8sNP.ObjectMeta.Name,
		logfields.K8sNamespace:                  newk8sNP.ObjectMeta.Namespace,
	}).Debug("Received policy update")

	return k.addK8sNetworkPolicyV1(newk8sNP)
}

func (k *K8sWatcher) deleteK8sNetworkPolicyV1(k8sNP *types.NetworkPolicy) error {
	labels := k8s.GetPolicyLabelsv1(k8sNP.NetworkPolicy)

	if labels == nil {
		log.Fatalf("provided v1 NetworkPolicy is nil, so cannot delete it")
	}

	scopedLog := log.WithFields(logrus.Fields{
		logfields.K8sNetworkPolicyName: k8sNP.ObjectMeta.Name,
		logfields.K8sNamespace:         k8sNP.ObjectMeta.Namespace,
		logfields.K8sAPIVersion:        k8sNP.TypeMeta.APIVersion,
		logfields.Labels:               logfields.Repr(labels),
	})
	if _, err := k.policyManager.PolicyDelete(labels); err != nil {
		scopedLog.WithError(err).Error("Error while deleting k8s NetworkPolicy")
		return err
	}

	scopedLog.Info("NetworkPolicy successfully removed")
	return nil
}
