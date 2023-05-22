// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"

	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
)

func (k *K8sWatcher) ciliumClusterwideEnvoyConfigInit(ctx context.Context, clientset client.Clientset) {
	apiGroup := k8sAPIGroupCiliumClusterwideEnvoyConfigV2
	_, ccecController := informer.NewInformer(
		utils.ListerWatcherFromTyped[*cilium_v2.CiliumClusterwideEnvoyConfigList](k.clientset.CiliumV2().CiliumClusterwideEnvoyConfigs()),
		&cilium_v2.CiliumClusterwideEnvoyConfig{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(apiGroup, metricCCEC, resources.MetricCreate, valid, equal) }()
				if ccec := k8s.ObjToCCEC(obj); ccec != nil {
					valid = true
					err := k.addCiliumClusterwideEnvoyConfig(ccec)
					k.K8sEventProcessed(metricCCEC, resources.MetricCreate, err == nil)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(apiGroup, metricCCEC, resources.MetricUpdate, valid, equal) }()

				if oldCCEC := k8s.ObjToCCEC(oldObj); oldCCEC != nil {
					if newCCEC := k8s.ObjToCCEC(newObj); newCCEC != nil {
						valid = true
						if newCCEC.DeepEqual(oldCCEC) {
							equal = true
							return
						}
						err := k.updateCiliumClusterwideEnvoyConfig(oldCCEC, newCCEC)
						k.K8sEventProcessed(metricCCEC, resources.MetricUpdate, err == nil)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(apiGroup, metricCCEC, resources.MetricDelete, valid, equal) }()
				ccec := k8s.ObjToCCEC(obj)
				if ccec == nil {
					return
				}
				valid = true
				err := k.deleteCiliumClusterwideEnvoyConfig(ccec)
				k.K8sEventProcessed(metricCCEC, resources.MetricDelete, err == nil)
			},
		},
		k8s.ConvertToCiliumClusterwideEnvoyConfig,
	)

	k.blockWaitGroupToSyncResources(
		wait.NeverStop,
		nil,
		ccecController.HasSynced,
		apiGroup,
	)

	go ccecController.Run(ctx.Done())
	k.k8sAPIGroups.AddAPI(apiGroup)
}

func (k *K8sWatcher) addCiliumClusterwideEnvoyConfig(ccec *cilium_v2.CiliumClusterwideEnvoyConfig) error {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.CiliumClusterwideEnvoyConfigName: ccec.ObjectMeta.Name,
		logfields.K8sUID:        ccec.ObjectMeta.UID,
		logfields.K8sAPIVersion: ccec.TypeMeta.APIVersion,
	})

	resources, err := envoy.ParseResources(
		ccec.GetNamespace(),
		ccec.GetName(),
		ccec.Spec.Resources,
		true,
		k.envoyConfigManager,
		len(ccec.Spec.Services) > 0,
		!isIngressKind(&ccec.ObjectMeta),
	)
	if err != nil {
		scopedLog.WithError(err).Warn("Failed to add CiliumClusterwideEnvoyConfig: malformed Envoy config")
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), option.Config.EnvoyConfigTimeout)
	defer cancel()
	if err := k.envoyConfigManager.UpsertEnvoyResources(ctx, resources, k.envoyConfigManager); err != nil {
		scopedLog.WithError(err).Warn("Failed to add CiliumClusterwideEnvoyConfig")
		return err
	}

	name := loadbalancer.ServiceName{Name: ccec.ObjectMeta.Name, Namespace: ccec.ObjectMeta.Namespace}
	if err := k.addK8sServiceRedirects(name, &ccec.Spec, resources); err != nil {
		scopedLog.WithError(err).Warn("Failed to redirect K8s services to Envoy")
		return err
	}

	if len(resources.Listeners) > 0 {
		// TODO: Policy does not need to be recomputed for this, but if we do not 'force'
		// the bpf maps are not updated with the new proxy ports either. Move from the
		// simple boolean to an enum that can more selectively skip regeneration steps (like
		// we do for the datapath recompilations already?)
		k.policyManager.TriggerPolicyUpdates(true, "Envoy Listeners added")
	}

	scopedLog.Debug("Added CiliumClusterwideEnvoyConfig")
	return err
}

func (k *K8sWatcher) updateCiliumClusterwideEnvoyConfig(oldCCEC *cilium_v2.CiliumClusterwideEnvoyConfig, newCCEC *cilium_v2.CiliumClusterwideEnvoyConfig) error {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.CiliumClusterwideEnvoyConfigName: newCCEC.ObjectMeta.Name,
		logfields.K8sUID:        newCCEC.ObjectMeta.UID,
		logfields.K8sAPIVersion: newCCEC.TypeMeta.APIVersion,
	})

	oldResources, err := envoy.ParseResources(
		oldCCEC.GetNamespace(),
		oldCCEC.GetName(),
		oldCCEC.Spec.Resources,
		false,
		k.envoyConfigManager,
		len(oldCCEC.Spec.Services) > 0,
		!isIngressKind(&oldCCEC.ObjectMeta),
	)
	if err != nil {
		scopedLog.WithError(err).Warn("Failed to update CiliumClusterwideEnvoyConfig: malformed old Envoy config")
		return err
	}
	newResources, err := envoy.ParseResources(
		newCCEC.GetNamespace(),
		newCCEC.GetName(),
		newCCEC.Spec.Resources,
		true,
		k.envoyConfigManager,
		len(newCCEC.Spec.Services) > 0,
		!isIngressKind(&newCCEC.ObjectMeta),
	)
	if err != nil {
		scopedLog.WithError(err).Warn("Failed to update CiliumClusterwideEnvoyConfig: malformed new Envoy config")
		return err
	}
	name := loadbalancer.ServiceName{Name: oldCCEC.ObjectMeta.Name, Namespace: oldCCEC.ObjectMeta.Namespace}
	if err = k.removeK8sServiceRedirects(name, &oldCCEC.Spec, &newCCEC.Spec, oldResources, newResources); err != nil {
		scopedLog.WithError(err).Warn("Failed to update K8s service redirections")
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), option.Config.EnvoyConfigTimeout)
	defer cancel()
	if err = k.envoyConfigManager.UpdateEnvoyResources(ctx, oldResources, newResources, k.envoyConfigManager); err != nil {
		scopedLog.WithError(err).Warn("Failed to update CiliumClusterwideEnvoyConfig")
		return err
	}

	if err := k.addK8sServiceRedirects(name, &newCCEC.Spec, newResources); err != nil {
		scopedLog.WithError(err).Warn("Failed to redirect K8s services to Envoy")
		return err
	}

	if oldResources.ListenersAddedOrDeleted(&newResources) {
		k.policyManager.TriggerPolicyUpdates(true, "Envoy Listeners added or deleted")
	}

	scopedLog.Debug("Updated CiliumClusterwideEnvoyConfig")
	return nil
}

func (k *K8sWatcher) deleteCiliumClusterwideEnvoyConfig(ccec *cilium_v2.CiliumClusterwideEnvoyConfig) error {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.CiliumClusterwideEnvoyConfigName: ccec.ObjectMeta.Name,
		logfields.K8sUID:        ccec.ObjectMeta.UID,
		logfields.K8sAPIVersion: ccec.TypeMeta.APIVersion,
	})

	resources, err := envoy.ParseResources(
		ccec.GetNamespace(),
		ccec.GetName(),
		ccec.Spec.Resources,
		false,
		k.envoyConfigManager,
		len(ccec.Spec.Services) > 0,
		!isIngressKind(&ccec.ObjectMeta),
	)
	if err != nil {
		scopedLog.WithError(err).Warn("Failed to delete CiliumClusterwideEnvoyConfig: parsing rersource names failed")
		return err
	}

	name := loadbalancer.ServiceName{Name: ccec.ObjectMeta.Name, Namespace: ccec.ObjectMeta.Namespace}
	if err = k.deleteK8sServiceRedirects(name, &ccec.Spec); err != nil {
		scopedLog.WithError(err).Warn("Failed to delete K8s service redirections")
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), option.Config.EnvoyConfigTimeout)
	defer cancel()
	if err = k.envoyConfigManager.DeleteEnvoyResources(ctx, resources, k.envoyConfigManager); err != nil {
		scopedLog.WithError(err).Warn("Failed to delete Envoy resources")
		return err
	}

	if len(resources.Listeners) > 0 {
		k.policyManager.TriggerPolicyUpdates(true, "Envoy Listeners deleted")
	}

	scopedLog.Debug("Deleted CiliumClusterwideEnvoyConfig")
	return nil
}
