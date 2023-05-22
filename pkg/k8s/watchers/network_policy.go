// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/tools/cache"

	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/informer"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	slimclientset "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/source"
)

func (k *K8sWatcher) networkPoliciesInit(slimClient slimclientset.Interface, swgKNPs *lock.StoppableWaitGroup) {
	apiGroup := k8sAPIGroupNetworkingV1Core
	store, policyController := informer.NewInformer(
		utils.ListerWatcherFromTyped[*slim_networkingv1.NetworkPolicyList](
			slimClient.NetworkingV1().NetworkPolicies("")),
		&slim_networkingv1.NetworkPolicy{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(apiGroup, metricKNP, resources.MetricCreate, valid, equal) }()
				if k8sNP := k8s.ObjToV1NetworkPolicy(obj); k8sNP != nil {
					valid = true
					err := k.addK8sNetworkPolicyV1(k8sNP)
					k.K8sEventProcessed(metricKNP, resources.MetricCreate, err == nil)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(apiGroup, metricKNP, resources.MetricUpdate, valid, equal) }()
				if oldK8sNP := k8s.ObjToV1NetworkPolicy(oldObj); oldK8sNP != nil {
					if newK8sNP := k8s.ObjToV1NetworkPolicy(newObj); newK8sNP != nil {
						valid = true
						if oldK8sNP.DeepEqual(newK8sNP) {
							equal = true
							return
						}

						err := k.updateK8sNetworkPolicyV1(oldK8sNP, newK8sNP)
						k.K8sEventProcessed(metricKNP, resources.MetricUpdate, err == nil)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(apiGroup, metricKNP, resources.MetricDelete, valid, equal) }()
				k8sNP := k8s.ObjToV1NetworkPolicy(obj)
				if k8sNP == nil {
					return
				}

				valid = true
				err := k.deleteK8sNetworkPolicyV1(k8sNP)
				k.K8sEventProcessed(metricKNP, resources.MetricDelete, err == nil)
			},
		},
		nil,
	)
	k.networkpolicyStore = store
	k.blockWaitGroupToSyncResources(k.stop, swgKNPs, policyController.HasSynced, k8sAPIGroupNetworkingV1Core)
	go policyController.Run(k.stop)

	k.k8sAPIGroups.AddAPI(apiGroup)
}

func (k *K8sWatcher) addK8sNetworkPolicyV1(k8sNP *slim_networkingv1.NetworkPolicy) error {
	scopedLog := log.WithField(logfields.K8sAPIVersion, k8sNP.TypeMeta.APIVersion)
	rules, err := k8s.ParseNetworkPolicy(k8sNP)
	if err != nil {
		metrics.PolicyImportErrorsTotal.Inc() // Deprecated in Cilium 1.14, to be removed in 1.15.
		metrics.PolicyChangeTotal.WithLabelValues(metrics.LabelValueOutcomeFail).Inc()
		scopedLog.WithError(err).WithFields(logrus.Fields{
			logfields.CiliumNetworkPolicy: logfields.Repr(k8sNP),
		}).Error("Error while parsing k8s kubernetes NetworkPolicy")
		return err
	}
	scopedLog = scopedLog.WithField(logfields.K8sNetworkPolicyName, k8sNP.ObjectMeta.Name)

	opts := policy.AddOptions{
		Replace: true,
		Source:  source.Kubernetes,
		Resource: ipcacheTypes.NewResourceID(
			ipcacheTypes.ResourceKindNetpol,
			k8sNP.ObjectMeta.Namespace,
			k8sNP.ObjectMeta.Name,
		),
	}
	if _, err := k.policyManager.PolicyAdd(rules, &opts); err != nil {
		metrics.PolicyImportErrorsTotal.Inc() // Deprecated in Cilium 1.14, to be removed in 1.15.
		metrics.PolicyChangeTotal.WithLabelValues(metrics.LabelValueOutcomeFail).Inc()
		scopedLog.WithError(err).WithFields(logrus.Fields{
			logfields.CiliumNetworkPolicy: logfields.Repr(rules),
		}).Error("Unable to add NetworkPolicy rules to policy repository")
		return err
	}

	metrics.PolicyChangeTotal.WithLabelValues(metrics.LabelValueOutcomeSuccess).Inc()
	scopedLog.Info("NetworkPolicy successfully added")
	return nil
}

func (k *K8sWatcher) updateK8sNetworkPolicyV1(oldk8sNP, newk8sNP *slim_networkingv1.NetworkPolicy) error {
	log.WithFields(logrus.Fields{
		logfields.K8sAPIVersion:                 oldk8sNP.TypeMeta.APIVersion,
		logfields.K8sNetworkPolicyName + ".old": oldk8sNP.ObjectMeta.Name,
		logfields.K8sNamespace + ".old":         oldk8sNP.ObjectMeta.Namespace,
		logfields.K8sNetworkPolicyName:          newk8sNP.ObjectMeta.Name,
		logfields.K8sNamespace:                  newk8sNP.ObjectMeta.Namespace,
	}).Debug("Received policy update")

	return k.addK8sNetworkPolicyV1(newk8sNP)
}

func (k *K8sWatcher) deleteK8sNetworkPolicyV1(k8sNP *slim_networkingv1.NetworkPolicy) error {
	labels := k8s.GetPolicyLabelsv1(k8sNP)

	if labels == nil {
		log.Fatalf("provided v1 NetworkPolicy is nil, so cannot delete it")
	}

	scopedLog := log.WithFields(logrus.Fields{
		logfields.K8sNetworkPolicyName: k8sNP.ObjectMeta.Name,
		logfields.K8sNamespace:         k8sNP.ObjectMeta.Namespace,
		logfields.K8sAPIVersion:        k8sNP.TypeMeta.APIVersion,
		logfields.Labels:               logfields.Repr(labels),
	})
	if _, err := k.policyManager.PolicyDelete(labels, &policy.DeleteOptions{
		Source: source.Kubernetes,
		Resource: ipcacheTypes.NewResourceID(
			ipcacheTypes.ResourceKindNetpol,
			k8sNP.ObjectMeta.Namespace,
			k8sNP.ObjectMeta.Name,
		),
	}); err != nil {
		metrics.PolicyChangeTotal.WithLabelValues(metrics.LabelValueOutcomeFail).Inc()
		scopedLog.WithError(err).Error("Error while deleting k8s NetworkPolicy")
		return err
	}

	metrics.PolicyChangeTotal.WithLabelValues(metrics.LabelValueOutcomeSuccess).Inc()
	scopedLog.Info("NetworkPolicy successfully removed")
	return nil
}
