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
	"context"
	"fmt"

	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
)

func (k *K8sWatcher) ciliumEnvoyConfigInit(ciliumNPClient *k8s.K8sCiliumClient) {
	cecStore := cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)

	cecController := informer.NewInformerWithStore(
		cache.NewListWatchFromClient(ciliumNPClient.CiliumV2alpha1().RESTClient(),
			cilium_v2alpha1.CECPluralName, v1.NamespaceAll, fields.Everything()),
		&cilium_v2alpha1.CiliumEnvoyConfig{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(metricCEC, metricCreate, valid, equal) }()
				if cec := k8s.ObjToCEC(obj); cec != nil {
					valid = true
					err := k.addCiliumEnvoyConfig(cec)
					k.K8sEventProcessed(metricCEC, metricCreate, err == nil)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(metricCEC, metricUpdate, valid, equal) }()

				if oldCEC := k8s.ObjToCEC(oldObj); oldCEC != nil {
					if newCEC := k8s.ObjToCEC(newObj); newCEC != nil {
						valid = true
						if newCEC.DeepEqual(oldCEC) {
							equal = true
							return
						}
						err := k.updateCiliumEnvoyConfig(oldCEC, newCEC)
						k.K8sEventProcessed(metricCEC, metricUpdate, err == nil)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(metricCEC, metricDelete, valid, equal) }()
				cec := k8s.ObjToCEC(obj)
				if cec == nil {
					return
				}
				valid = true
				err := k.deleteCiliumEnvoyConfig(cec)
				k.K8sEventProcessed(metricCEC, metricDelete, err == nil)
			},
		},
		k8s.ConvertToCiliumEnvoyConfig,
		cecStore,
	)

	k.blockWaitGroupToSyncResources(
		wait.NeverStop,
		nil,
		cecController.HasSynced,
		k8sAPIGroupCiliumEnvoyConfigV2Alpha1,
	)

	go cecController.Run(wait.NeverStop)
	k.k8sAPIGroups.AddAPI(k8sAPIGroupCiliumEnvoyConfigV2Alpha1)
}

func (k *K8sWatcher) addCiliumEnvoyConfig(cec *cilium_v2alpha1.CiliumEnvoyConfig) error {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.CiliumEnvoyConfigName: cec.ObjectMeta.Name,
		logfields.K8sUID:                cec.ObjectMeta.UID,
		logfields.K8sAPIVersion:         cec.TypeMeta.APIVersion,
	})

	resources, err := envoy.ParseResources(cec.ObjectMeta.Name, cec, true, k.envoyConfigManager)
	if err != nil {
		scopedLog.WithError(err).Warn("Failed to add CiliumEnvoyConfig: malformed Envoy config.")
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), option.Config.EnvoyConfigTimeout)
	defer cancel()
	if err := k.envoyConfigManager.UpsertEnvoyResources(ctx, resources, k.envoyConfigManager); err != nil {
		scopedLog.WithError(err).Warn("Failed to add CiliumEnvoyConfig.")
		return err
	}

	// Redirect k8s services to an Envoy listener
	for _, svc := range cec.Spec.Services {
		// Find the listener the service is to be redirected to
		var proxyPort uint16
		for _, l := range resources.Listeners {
			if svc.Listener == "" || l.Name == svc.Listener {
				if addr := l.GetAddress(); addr != nil {
					if sa := addr.GetSocketAddress(); sa != nil {
						proxyPort = uint16(sa.GetPortValue())
					}
				}
			}
		}
		if proxyPort == 0 {
			return fmt.Errorf("Listener %q not found in resources", svc.Listener)
		}

		// Tell service manager to redirect the service to the port
		err = k.svcManager.RegisterL7LBService(svc.Name, svc.Namespace, cec.ObjectMeta.Name, proxyPort)
		if err != nil {
			return err
		}
	}
	// Register services for Envoy backend sync
	for _, svc := range cec.Spec.BackendServices {
		// Tell service manager to sync backends for this service
		err = k.svcManager.RegisterL7LBService(svc.Name, svc.Namespace, cec.ObjectMeta.Name, 0)
		if err != nil {
			return err
		}
	}

	scopedLog.Debug("Added CiliumEnvoyConfig")
	return err
}

func (k *K8sWatcher) updateCiliumEnvoyConfig(oldCEC *cilium_v2alpha1.CiliumEnvoyConfig, newCEC *cilium_v2alpha1.CiliumEnvoyConfig) error {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.CiliumEnvoyConfigName: newCEC.ObjectMeta.Name,
		logfields.K8sUID:                newCEC.ObjectMeta.UID,
		logfields.K8sAPIVersion:         newCEC.TypeMeta.APIVersion,
	})

	oldResources, err := envoy.ParseResources(oldCEC.ObjectMeta.Name, oldCEC, false, k.envoyConfigManager)
	if err != nil {
		scopedLog.WithError(err).Warn("Failed to update CiliumEnvoyConfig: malformed old Envoy config.")
		return err
	}
	newResources, err := envoy.ParseResources(newCEC.ObjectMeta.Name, newCEC, true, k.envoyConfigManager)
	if err != nil {
		scopedLog.WithError(err).Warn("Failed to update CiliumEnvoyConfig: malformed new Envoy config.")
		return err
	}

	removedServices := []*cilium_v2alpha1.ServiceListener{}
	for _, oldSvc := range oldCEC.Spec.Services {
		found := false
		for _, newSvc := range newCEC.Spec.Services {
			if newSvc.Name == oldSvc.Name && newSvc.Namespace == oldSvc.Namespace {
				// Check if listener names match, but handle defaulting to the first listener first.
				oldListener := oldSvc.Listener
				if oldListener == "" && len(oldResources.Listeners) > 0 {
					oldListener = oldResources.Listeners[0].Name
				}
				newListener := newSvc.Listener
				if newListener == "" && len(newResources.Listeners) > 0 {
					newListener = newResources.Listeners[0].Name
				}
				if newListener != "" && newListener == oldListener {
					found = true
					break
				}
			}
		}
		if !found {
			removedServices = append(removedServices, oldSvc)
		}
	}
	for _, oldSvc := range removedServices {
		// Tell service manager to remove old service registration
		err := k.svcManager.RemoveL7LBService(oldSvc.Name, oldSvc.Namespace, oldCEC.ObjectMeta.Name)
		if err != nil {
			return err
		}
	}
	removedBackendServices := []*cilium_v2alpha1.Service{}
	for _, oldSvc := range oldCEC.Spec.BackendServices {
		found := false
		for _, newSvc := range newCEC.Spec.BackendServices {
			if newSvc.Name == oldSvc.Name && newSvc.Namespace == oldSvc.Namespace {
				found = true
				break
			}
		}
		if !found {
			removedBackendServices = append(removedBackendServices, oldSvc)
		}
	}
	for _, oldSvc := range removedBackendServices {
		// Tell service manager to remove old service registration
		err := k.svcManager.RemoveL7LBService(oldSvc.Name, oldSvc.Namespace, oldCEC.ObjectMeta.Name)
		if err != nil {
			return err
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), option.Config.EnvoyConfigTimeout)
	defer cancel()
	if err := k.envoyConfigManager.UpdateEnvoyResources(ctx, oldResources, newResources, k.envoyConfigManager); err != nil {
		scopedLog.WithError(err).Warn("Failed to update CiliumEnvoyConfig.")
		return err
	}

	for _, svc := range newCEC.Spec.Services {
		// Find the listener the service is to be redirected to
		var proxyPort uint16
		for _, l := range newResources.Listeners {
			if svc.Listener == "" || l.Name == svc.Listener {
				if addr := l.GetAddress(); addr != nil {
					if sa := addr.GetSocketAddress(); sa != nil {
						proxyPort = uint16(sa.GetPortValue())
					}
				}
			}
		}
		if proxyPort == 0 {
			return fmt.Errorf("Listener %s not found in new resources", svc.Listener)
		}

		// Tell service manager to redirect the service to the port
		err = k.svcManager.RegisterL7LBService(svc.Name, svc.Namespace, newCEC.ObjectMeta.Name, proxyPort)
		if err != nil {
			return err
		}
	}
	for _, svc := range newCEC.Spec.BackendServices {
		// Tell service manager to redirect the service to the port
		err = k.svcManager.RegisterL7LBService(svc.Name, svc.Namespace, newCEC.ObjectMeta.Name, 0)
		if err != nil {
			return err
		}
	}

	scopedLog.Info("Updated CiliumEnvoyConfig")
	return nil
}

func (k *K8sWatcher) deleteCiliumEnvoyConfig(cec *cilium_v2alpha1.CiliumEnvoyConfig) error {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.CiliumEnvoyConfigName: cec.ObjectMeta.Name,
		logfields.K8sUID:                cec.ObjectMeta.UID,
		logfields.K8sAPIVersion:         cec.TypeMeta.APIVersion,
	})

	resources, err := envoy.ParseResources(cec.ObjectMeta.Name, cec, false, k.envoyConfigManager)
	if err != nil {
		scopedLog.WithError(err).Warn("Failed to delete CiliumEnvoyConfig: parsing rersource names failed.")
		return err
	}

	for _, svc := range cec.Spec.Services {
		// Tell service manager to remove old service redirection
		err := k.svcManager.RemoveL7LBService(svc.Name, svc.Namespace, cec.ObjectMeta.Name)
		if err != nil {
			return err
		}
	}
	for _, svc := range cec.Spec.BackendServices {
		// Tell service manager to remove old service redirection
		err := k.svcManager.RemoveL7LBService(svc.Name, svc.Namespace, cec.ObjectMeta.Name)
		if err != nil {
			return err
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), option.Config.EnvoyConfigTimeout)
	defer cancel()
	if err := k.envoyConfigManager.DeleteEnvoyResources(ctx, resources, k.envoyConfigManager); err != nil {
		scopedLog.WithError(err).Warn("Failed to delete CiliumEnvoyResource.")
		return err
	}

	scopedLog.Info("Deleted CiliumEnvoyConfig")
	return nil
}
