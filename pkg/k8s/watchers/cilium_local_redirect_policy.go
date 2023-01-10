// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/redirectpolicy"
)

func (k *K8sWatcher) ciliumLocalRedirectPolicyInit(ciliumLRPClient client.Clientset) {
	apiGroup := k8sAPIGroupCiliumLocalRedirectPolicyV2
	_, lrpController := informer.NewInformer(
		cache.NewListWatchFromClient(ciliumLRPClient.CiliumV2().RESTClient(),
			"ciliumlocalredirectpolicies", v1.NamespaceAll, fields.Everything()),
		&cilium_v2.CiliumLocalRedirectPolicy{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(apiGroup, metricCLRP, resources.MetricCreate, valid, equal) }()
				if cLRP := k8s.ObjToCLRP(obj); cLRP != nil {
					valid = true
					err := k.addCiliumLocalRedirectPolicy(cLRP)
					k.K8sEventProcessed(metricCLRP, resources.MetricCreate, err == nil)
				}

			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				log.Info("Local Redirect Policy updates are not handled")

			},
			DeleteFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(apiGroup, metricCLRP, resources.MetricDelete, valid, equal) }()
				cLRP := k8s.ObjToCLRP(obj)
				if cLRP == nil {
					return
				}
				valid = true
				err := k.deleteCiliumLocalRedirectPolicy(cLRP)
				k.K8sEventProcessed(metricCLRP, resources.MetricDelete, err == nil)
			},
		},
		k8s.ConvertToCiliumLocalRedirectPolicy,
	)

	k.blockWaitGroupToSyncResources(
		k.stop,
		nil,
		lrpController.HasSynced,
		k8sAPIGroupCiliumLocalRedirectPolicyV2,
	)

	go lrpController.Run(k.stop)
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
