// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/worldcidrs"
)

func (k *K8sWatcher) ciliumWorldCIDRSetInit(ciliumClient client.Clientset) {
	apiGroup := k8sAPIGroupCiliumWorldCIDRSetV2
	_, egpController := informer.NewInformer(
		cache.NewListWatchFromClient(ciliumClient.CiliumV2alpha1().RESTClient(),
			"ciliumworldcidrsets", v1.NamespaceAll, fields.Everything()),
		&v2alpha1.CiliumWorldCIDRSet{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(apiGroup, metricCWCIDR, resources.MetricCreate, valid, equal) }()
				if cwcidr := k8s.ObjToCWCIDR(obj); cwcidr != nil {
					valid = true
					err := k.addCiliumWorldCIDRSet(cwcidr)
					k.K8sEventProcessed(metricCWCIDR, resources.MetricCreate, err == nil)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(apiGroup, metricCWCIDR, resources.MetricUpdate, valid, equal) }()

				newCegp := k8s.ObjToCWCIDR(newObj)
				if newCegp == nil {
					return
				}
				valid = true
				addErr := k.addCiliumWorldCIDRSet(newCegp)
				k.K8sEventProcessed(metricCWCIDR, resources.MetricUpdate, addErr == nil)
			},
			DeleteFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(apiGroup, metricCWCIDR, resources.MetricDelete, valid, equal) }()
				cwcidr := k8s.ObjToCWCIDR(obj)
				if cwcidr == nil {
					return
				}
				valid = true
				k.deleteCiliumWorldCIDRSet(cwcidr)
				k.K8sEventProcessed(metricCWCIDR, resources.MetricDelete, true)
			},
		},
		k8s.ConvertToCiliumWorldCIDRSet,
	)

	k.blockWaitGroupToSyncResources(
		k.stop,
		nil,
		egpController.HasSynced,
		k8sAPIGroupCiliumWorldCIDRSetV2,
	)

	go egpController.Run(k.stop)
	k.k8sAPIGroups.AddAPI(k8sAPIGroupCiliumWorldCIDRSetV2)
}

func (k *K8sWatcher) addCiliumWorldCIDRSet(cwcidr *v2alpha1.CiliumWorldCIDRSet) error {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.CiliumWorldCIDRSetName: cwcidr.ObjectMeta.Name,
		logfields.K8sUID:                 cwcidr.ObjectMeta.UID,
		logfields.K8sAPIVersion:          cwcidr.TypeMeta.APIVersion,
	})

	ep, err := worldcidrs.ParseCWCIDR(cwcidr)
	if err != nil {
		scopedLog.WithError(err).Warn("Failed to add CiliumWorldCIDRSet: malformed CIDR set.")
		return err
	}
	k.worldCIDRsManager.OnAddWorldCIDRSet(*ep)

	return err
}

func (k *K8sWatcher) deleteCiliumWorldCIDRSet(cwcidr *v2alpha1.CiliumWorldCIDRSet) {
	epID := worldcidrs.ParseCWCIDRSetID(cwcidr)
	k.worldCIDRsManager.OnDeleteWorldCIDRSet(epID)
}
