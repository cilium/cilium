// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"

	"github.com/cilium/cilium/pkg/hubble/exporter/exporteroption"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
)

func (k *K8sWatcher) ciliumFlowLoggingInit(ctx context.Context, client client.Clientset) {
	apiGroup := k8sAPIGroupCiliumFlowLoggingV2Alpha1
	_, cflController := informer.NewInformer(
		utils.ListerWatcherFromTyped[*cilium_v2a1.CiliumFlowLoggingList](
			client.CiliumV2alpha1().CiliumFlowLoggings()),
		&cilium_v2a1.CiliumFlowLogging{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(apiGroup, metricCFL, resources.MetricCreate, valid, equal) }()
				if cfl := k8s.CastInformerEvent[cilium_v2a1.CiliumFlowLogging](obj); cfl != nil {
					valid = true
					err := k.addCiliumFlowLogging(cfl)
					k.K8sEventProcessed(metricCFL, resources.MetricCreate, err == nil)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				log.WithField("watcher", "CiliumFlowLogging").Warn("Received update event for immutable CR. Ignoring")
			},
			DeleteFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(apiGroup, metricCFL, resources.MetricDelete, valid, equal) }()
				CFL := k8s.CastInformerEvent[cilium_v2a1.CiliumFlowLogging](obj)
				if CFL == nil {
					return
				}
				valid = true
				err := k.deleteCiliumFlowLogging(CFL)
				k.K8sEventProcessed(metricCFL, resources.MetricDelete, err == nil)
			},
		},
		nil,
	)

	k.blockWaitGroupToSyncResources(
		wait.NeverStop,
		nil,
		cflController.HasSynced,
		apiGroup,
	)

	go cflController.Run(ctx.Done())
	k.k8sAPIGroups.AddAPI(apiGroup)
}

func (k *K8sWatcher) addCiliumFlowLogging(cfl *cilium_v2a1.CiliumFlowLogging) error {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.CFLName:       cfl.ObjectMeta.Name,
		logfields.K8sUID:        cfl.ObjectMeta.UID,
		logfields.K8sAPIVersion: cfl.TypeMeta.APIVersion,
	})

	scopedLog.Debug("Added CiliumFlowLogging")

	if k.flowLoggingManager != nil {
		opts := []exporteroption.Option{}
		if len(cfl.Spec.AllowList) > 0 {
			opts = append(opts, exporteroption.WithAllowList(cfl.Spec.AllowList))
		}
		if len(cfl.Spec.DenyList) > 0 {
			opts = append(opts, exporteroption.WithDenyList(cfl.Spec.DenyList))
		}
		if len(cfl.Spec.FieldMask) > 0 {
			opts = append(opts, exporteroption.WithFieldMask(cfl.Spec.FieldMask))
		}
		return k.flowLoggingManager.Start(string(cfl.UID), cfl.Name, opts)
	}
	return nil
}

func (k *K8sWatcher) deleteCiliumFlowLogging(cfl *cilium_v2a1.CiliumFlowLogging) error {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.CFLName:       cfl.ObjectMeta.Name,
		logfields.K8sUID:        cfl.ObjectMeta.UID,
		logfields.K8sAPIVersion: cfl.TypeMeta.APIVersion,
	})

	scopedLog.Debug("Deleted CiliumFlowLogging")
	if k.flowLoggingManager != nil {
		return k.flowLoggingManager.Stop(string(cfl.UID))
	}
	return nil
}
