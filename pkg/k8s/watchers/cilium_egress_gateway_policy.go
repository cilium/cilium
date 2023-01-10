// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/egressgateway"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

func (k *K8sWatcher) ciliumEgressGatewayPolicyInit(ciliumNPClient client.Clientset) {
	apiGroup := k8sAPIGroupCiliumEgressGatewayPolicyV2
	_, egpController := informer.NewInformer(
		cache.NewListWatchFromClient(ciliumNPClient.CiliumV2().RESTClient(),
			"ciliumegressgatewaypolicies", v1.NamespaceAll, fields.Everything()),
		&cilium_v2.CiliumEgressGatewayPolicy{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(apiGroup, metricCEGP, resources.MetricCreate, valid, equal) }()
				if cegp := k8s.ObjToCEGP(obj); cegp != nil {
					valid = true
					err := k.addCiliumEgressGatewayPolicy(cegp)
					k.K8sEventProcessed(metricCEGP, resources.MetricCreate, err == nil)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(apiGroup, metricCEGP, resources.MetricUpdate, valid, equal) }()

				newCegp := k8s.ObjToCEGP(newObj)
				if newCegp == nil {
					return
				}
				valid = true
				addErr := k.addCiliumEgressGatewayPolicy(newCegp)
				k.K8sEventProcessed(metricCEGP, resources.MetricUpdate, addErr == nil)
			},
			DeleteFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(apiGroup, metricCEGP, resources.MetricDelete, valid, equal) }()
				cegp := k8s.ObjToCEGP(obj)
				if cegp == nil {
					return
				}
				valid = true
				k.deleteCiliumEgressGatewayPolicy(cegp)
				k.K8sEventProcessed(metricCEGP, resources.MetricDelete, true)
			},
		},
		k8s.ConvertToCiliumEgressGatewayPolicy,
	)

	k.blockWaitGroupToSyncResources(
		k.stop,
		nil,
		egpController.HasSynced,
		k8sAPIGroupCiliumEgressGatewayPolicyV2,
	)

	go egpController.Run(k.stop)
	k.k8sAPIGroups.AddAPI(k8sAPIGroupCiliumEgressGatewayPolicyV2)
}

func (k *K8sWatcher) addCiliumEgressGatewayPolicy(cegp *cilium_v2.CiliumEgressGatewayPolicy) error {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.CiliumEgressGatewayPolicyName: cegp.ObjectMeta.Name,
		logfields.K8sUID:                        cegp.ObjectMeta.UID,
		logfields.K8sAPIVersion:                 cegp.TypeMeta.APIVersion,
	})

	ep, err := egressgateway.ParseCEGP(cegp)
	if err != nil {
		scopedLog.WithError(err).Warn("Failed to add CiliumEgressGatewayPolicy: malformed policy config.")
		return err
	}
	k.egressGatewayManager.OnAddEgressPolicy(*ep)

	return err
}

func (k *K8sWatcher) deleteCiliumEgressGatewayPolicy(cegp *cilium_v2.CiliumEgressGatewayPolicy) {
	epID := egressgateway.ParseCEGPConfigID(cegp)
	k.egressGatewayManager.OnDeleteEgressPolicy(epID)
}
