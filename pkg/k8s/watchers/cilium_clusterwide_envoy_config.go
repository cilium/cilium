// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"

	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/service"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
)

func (k *K8sWatcher) ciliumClusterwideEnvoyConfigInit(ciliumNPClient *k8s.K8sCiliumClient) {
	ccecStore := cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)

	ccecController := informer.NewInformerWithStore(
		cache.NewListWatchFromClient(ciliumNPClient.CiliumV2alpha1().RESTClient(),
			cilium_v2alpha1.CCECPluralName, v1.NamespaceAll, fields.Everything()),
		&cilium_v2alpha1.CiliumClusterwideEnvoyConfig{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(metricCCEC, metricCreate, valid, equal) }()
				if ccec := k8s.ObjToCCEC(obj); ccec != nil {
					valid = true
					err := k.addCiliumClusterwideEnvoyConfig(ccec)
					k.K8sEventProcessed(metricCCEC, metricCreate, err == nil)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(metricCCEC, metricUpdate, valid, equal) }()

				if oldCCEC := k8s.ObjToCCEC(oldObj); oldCCEC != nil {
					if newCCEC := k8s.ObjToCCEC(newObj); newCCEC != nil {
						valid = true
						if newCCEC.DeepEqual(oldCCEC) {
							equal = true
							return
						}
						err := k.updateCiliumClusterwideEnvoyConfig(oldCCEC, newCCEC)
						k.K8sEventProcessed(metricCCEC, metricUpdate, err == nil)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(metricCCEC, metricDelete, valid, equal) }()
				ccec := k8s.ObjToCCEC(obj)
				if ccec == nil {
					return
				}
				valid = true
				err := k.deleteCiliumClusterwideEnvoyConfig(ccec)
				k.K8sEventProcessed(metricCCEC, metricDelete, err == nil)
			},
		},
		k8s.ConvertToCiliumClusterwideEnvoyConfig,
		ccecStore,
	)

	k.blockWaitGroupToSyncResources(
		wait.NeverStop,
		nil,
		ccecController.HasSynced,
		k8sAPIGroupCiliumClusterwideEnvoyConfigV2Alpha1,
	)

	go ccecController.Run(wait.NeverStop)
	k.k8sAPIGroups.AddAPI(k8sAPIGroupCiliumClusterwideEnvoyConfigV2Alpha1)
}

func (k *K8sWatcher) addCiliumClusterwideEnvoyConfig(ccec *cilium_v2alpha1.CiliumClusterwideEnvoyConfig) error {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.CiliumClusterwideEnvoyConfigName: ccec.ObjectMeta.Name,
		logfields.K8sUID:        ccec.ObjectMeta.UID,
		logfields.K8sAPIVersion: ccec.TypeMeta.APIVersion,
	})

	resources, err := envoy.ParseResources("", ccec.Spec.Resources, k.envoyConfigManager)
	if err != nil {
		scopedLog.WithError(err).Warn("Failed to add CiliumClusterwideEnvoyConfig: malformed Envoy config")
		return err
	}
	if err := k.envoyConfigManager.UpsertEnvoyResources(context.TODO(), resources, k.envoyConfigManager); err != nil {
		scopedLog.WithError(err).Warn("Failed to add CiliumClusterwideEnvoyConfig")
		return err
	}

	name := service.Name{Name: ccec.ObjectMeta.Name, Namespace: ccec.ObjectMeta.Namespace}
	if err := k.addK8sServiceRedirects(name, &ccec.Spec, resources); err != nil {
		scopedLog.WithError(err).Warn("Failed to redirect K8s services to Envoy")
		return err
	}

	scopedLog.Debug("Added CiliumClusterwideEnvoyConfig")
	return err
}

func (k *K8sWatcher) updateCiliumClusterwideEnvoyConfig(oldCCEC *cilium_v2alpha1.CiliumClusterwideEnvoyConfig, newCCEC *cilium_v2alpha1.CiliumClusterwideEnvoyConfig) error {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.CiliumClusterwideEnvoyConfigName: newCCEC.ObjectMeta.Name,
		logfields.K8sUID:        newCCEC.ObjectMeta.UID,
		logfields.K8sAPIVersion: newCCEC.TypeMeta.APIVersion,
	})

	oldResources, err := envoy.ParseResources("", oldCCEC.Spec.Resources, k.envoyConfigManager)
	if err != nil {
		scopedLog.WithError(err).Warn("Failed to update CiliumClusterwideEnvoyConfig: malformed old Envoy config")
		return err
	}
	newResources, err := envoy.ParseResources("", newCCEC.Spec.Resources, k.envoyConfigManager)
	if err != nil {
		scopedLog.WithError(err).Warn("Failed to update CiliumClusterwideEnvoyConfig: malformed new Envoy config")
		return err
	}
	name := service.Name{Name: oldCCEC.ObjectMeta.Name, Namespace: oldCCEC.ObjectMeta.Namespace}
	if err = k.removeK8sServiceRedirects(name, &oldCCEC.Spec, &newCCEC.Spec, oldResources, newResources); err != nil {
		scopedLog.WithError(err).Warn("Failed to update K8s service redirections")
		return err
	}

	if err = k.envoyConfigManager.UpdateEnvoyResources(context.TODO(), oldResources, newResources, k.envoyConfigManager); err != nil {
		scopedLog.WithError(err).Warn("Failed to update CiliumClusterwideEnvoyConfig")
		return err
	}

	if err := k.addK8sServiceRedirects(name, &newCCEC.Spec, newResources); err != nil {
		scopedLog.WithError(err).Warn("Failed to redirect K8s services to Envoy")
		return err
	}

	scopedLog.Debug("Updated CiliumClusterwideEnvoyConfig")
	return nil
}

func (k *K8sWatcher) deleteCiliumClusterwideEnvoyConfig(ccec *cilium_v2alpha1.CiliumClusterwideEnvoyConfig) error {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.CiliumClusterwideEnvoyConfigName: ccec.ObjectMeta.Name,
		logfields.K8sUID:        ccec.ObjectMeta.UID,
		logfields.K8sAPIVersion: ccec.TypeMeta.APIVersion,
	})

	resources, err := envoy.ParseResources("", ccec.Spec.Resources, k.envoyConfigManager)
	if err != nil {
		scopedLog.WithError(err).Warn("Failed to delete CiliumClusterwideEnvoyConfig: parsing rersource names failed")
		return err
	}

	name := service.Name{Name: ccec.ObjectMeta.Name, Namespace: ccec.ObjectMeta.Namespace}
	if err = k.deleteK8sServiceRedirects(name, &ccec.Spec); err != nil {
		scopedLog.WithError(err).Warn("Failed to delete K8s service redirections")
		return err
	}

	if err = k.envoyConfigManager.DeleteEnvoyResources(context.TODO(), resources, k.envoyConfigManager); err != nil {
		scopedLog.WithError(err).Warn("Failed to delete Envoy resources")
		return err
	}

	scopedLog.Debug("Deleted CiliumClusterwideEnvoyConfig")
	return nil
}
