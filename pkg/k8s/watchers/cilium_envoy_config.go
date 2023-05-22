// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
)

func (k *K8sWatcher) ciliumEnvoyConfigInit(ctx context.Context, ciliumNPClient client.Clientset) {
	apiGroup := k8sAPIGroupCiliumEnvoyConfigV2
	_, cecController := informer.NewInformer(
		cache.NewListWatchFromClient(ciliumNPClient.CiliumV2().RESTClient(),
			cilium_v2.CECPluralName, v1.NamespaceAll, fields.Everything()),
		&cilium_v2.CiliumEnvoyConfig{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(apiGroup, metricCEC, resources.MetricCreate, valid, equal) }()
				if cec := k8s.ObjToCEC(obj); cec != nil {
					valid = true
					err := k.addCiliumEnvoyConfig(cec)
					k.K8sEventProcessed(metricCEC, resources.MetricCreate, err == nil)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(apiGroup, metricCEC, resources.MetricUpdate, valid, equal) }()

				if oldCEC := k8s.ObjToCEC(oldObj); oldCEC != nil {
					if newCEC := k8s.ObjToCEC(newObj); newCEC != nil {
						valid = true
						if newCEC.DeepEqual(oldCEC) {
							equal = true
							return
						}
						err := k.updateCiliumEnvoyConfig(oldCEC, newCEC)
						k.K8sEventProcessed(metricCEC, resources.MetricUpdate, err == nil)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(apiGroup, metricCEC, resources.MetricDelete, valid, equal) }()
				cec := k8s.ObjToCEC(obj)
				if cec == nil {
					return
				}
				valid = true
				err := k.deleteCiliumEnvoyConfig(cec)
				k.K8sEventProcessed(metricCEC, resources.MetricDelete, err == nil)
			},
		},
		k8s.ConvertToCiliumEnvoyConfig,
	)

	k.blockWaitGroupToSyncResources(
		wait.NeverStop,
		nil,
		cecController.HasSynced,
		k8sAPIGroupCiliumEnvoyConfigV2,
	)

	go cecController.Run(ctx.Done())
	k.k8sAPIGroups.AddAPI(k8sAPIGroupCiliumEnvoyConfigV2)
}

// isIngressKind returns true if any of the OwnerReferences is Kind "Ingress"
func isIngressKind(meta *meta_v1.ObjectMeta) bool {
	for _, owner := range meta.OwnerReferences {
		if owner.Kind == "Ingress" {
			return true
		}
	}
	return false
}

func (k *K8sWatcher) addCiliumEnvoyConfig(cec *cilium_v2.CiliumEnvoyConfig) error {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.CiliumEnvoyConfigName: cec.ObjectMeta.Name,
		logfields.K8sNamespace:          cec.ObjectMeta.Namespace,
		logfields.K8sUID:                cec.ObjectMeta.UID,
		logfields.K8sAPIVersion:         cec.TypeMeta.APIVersion,
	})

	resources, err := envoy.ParseResources(
		cec.GetNamespace(),
		cec.GetName(),
		cec.Spec.Resources,
		true,
		k.envoyConfigManager,
		len(cec.Spec.Services) > 0,
		!isIngressKind(&cec.ObjectMeta),
	)
	if err != nil {
		scopedLog.WithError(err).Warn("Failed to add CiliumEnvoyConfig: malformed Envoy config")
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), option.Config.EnvoyConfigTimeout)
	defer cancel()
	if err := k.envoyConfigManager.UpsertEnvoyResources(ctx, resources, k.envoyConfigManager); err != nil {
		scopedLog.WithError(err).Warn("Failed to add CiliumEnvoyConfig")
		return err
	}

	name := loadbalancer.ServiceName{Name: cec.ObjectMeta.Name, Namespace: cec.ObjectMeta.Namespace}
	if err := k.addK8sServiceRedirects(name, &cec.Spec, resources); err != nil {
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

	scopedLog.Debug("Added CiliumEnvoyConfig")
	return err
}

// getServiceName enforces namespacing for service references in Cilium Envoy Configs
func getServiceName(resourceName loadbalancer.ServiceName, name, namespace string, isFrontend bool) loadbalancer.ServiceName {
	if resourceName.Namespace == "" {
		// nonNamespaced Cilium Clusterwide Envoy Config, default service references to
		// "default" namespace.
		if namespace == "" {
			namespace = "default"
		}
	} else {
		// Namespaced Cilium Envoy Config, enforce frontend service references to the
		// namespace of the CEC itself, and default the backend service reference namespace
		// to the namespace of the CEC itself.
		if isFrontend || namespace == "" {
			namespace = resourceName.Namespace
		}
	}
	return loadbalancer.ServiceName{Name: name, Namespace: namespace}
}

func (k *K8sWatcher) addK8sServiceRedirects(resourceName loadbalancer.ServiceName, spec *cilium_v2.CiliumEnvoyConfigSpec, resources envoy.Resources) error {
	// Redirect k8s services to an Envoy listener
	for _, svc := range spec.Services {
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
		serviceName := getServiceName(resourceName, svc.Name, svc.Namespace, true)
		err := k.svcManager.RegisterL7LBService(serviceName, resourceName, nil, proxyPort)
		if err != nil {
			return err
		}
	}
	// Register services for Envoy backend sync
	for _, svc := range spec.BackendServices {
		// Tell service manager to sync backends for this service
		serviceName := getServiceName(resourceName, svc.Name, svc.Namespace, false)
		err := k.svcManager.RegisterL7LBServiceBackendSync(serviceName, resourceName, svc.Ports)
		if err != nil {
			return err
		}
	}

	return nil
}

func (k *K8sWatcher) updateCiliumEnvoyConfig(oldCEC *cilium_v2.CiliumEnvoyConfig, newCEC *cilium_v2.CiliumEnvoyConfig) error {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.CiliumEnvoyConfigName: newCEC.ObjectMeta.Name,
		logfields.K8sNamespace:          newCEC.ObjectMeta.Namespace,
		logfields.K8sUID:                newCEC.ObjectMeta.UID,
		logfields.K8sAPIVersion:         newCEC.TypeMeta.APIVersion,
	})

	oldResources, err := envoy.ParseResources(
		oldCEC.GetNamespace(),
		oldCEC.GetName(),
		oldCEC.Spec.Resources,
		false,
		k.envoyConfigManager,
		len(oldCEC.Spec.Services) > 0,
		!isIngressKind(&oldCEC.ObjectMeta),
	)
	if err != nil {
		scopedLog.WithError(err).Warn("Failed to update CiliumEnvoyConfig: malformed old Envoy config")
		return err
	}
	newResources, err := envoy.ParseResources(
		newCEC.GetNamespace(),
		newCEC.GetName(),
		newCEC.Spec.Resources,
		true,
		k.envoyConfigManager,
		len(newCEC.Spec.Services) > 0,
		!isIngressKind(&newCEC.ObjectMeta),
	)
	if err != nil {
		scopedLog.WithError(err).Warn("Failed to update CiliumEnvoyConfig: malformed new Envoy config")
		return err
	}

	name := loadbalancer.ServiceName{Name: oldCEC.ObjectMeta.Name, Namespace: oldCEC.ObjectMeta.Namespace}
	if err = k.removeK8sServiceRedirects(name, &oldCEC.Spec, &newCEC.Spec, oldResources, newResources); err != nil {
		scopedLog.WithError(err).Warn("Failed to update K8s service redirections")
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), option.Config.EnvoyConfigTimeout)
	defer cancel()
	if err := k.envoyConfigManager.UpdateEnvoyResources(ctx, oldResources, newResources, k.envoyConfigManager); err != nil {
		scopedLog.WithError(err).Warn("Failed to update CiliumEnvoyConfig")
		return err
	}

	if err := k.addK8sServiceRedirects(name, &newCEC.Spec, newResources); err != nil {
		scopedLog.WithError(err).Warn("Failed to redirect K8s services to Envoy")
		return err
	}

	if oldResources.ListenersAddedOrDeleted(&newResources) {
		k.policyManager.TriggerPolicyUpdates(true, "Envoy Listeners added or deleted")
	}

	scopedLog.Debug("Updated CiliumEnvoyConfig")
	return nil
}

func (k *K8sWatcher) removeK8sServiceRedirects(resourceName loadbalancer.ServiceName, oldSpec, newSpec *cilium_v2.CiliumEnvoyConfigSpec, oldResources, newResources envoy.Resources) error {
	removedServices := []*cilium_v2.ServiceListener{}
	for _, oldSvc := range oldSpec.Services {
		found := false
		for _, newSvc := range newSpec.Services {
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
		serviceName := getServiceName(resourceName, oldSvc.Name, oldSvc.Namespace, true)
		err := k.svcManager.RemoveL7LBService(serviceName, resourceName)
		if err != nil {
			return err
		}
	}
	removedBackendServices := []*cilium_v2.Service{}
	for _, oldSvc := range oldSpec.BackendServices {
		found := false
		for _, newSvc := range newSpec.BackendServices {
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
		serviceName := getServiceName(resourceName, oldSvc.Name, oldSvc.Namespace, false)
		err := k.svcManager.RemoveL7LBService(serviceName, resourceName)
		if err != nil {
			return err
		}
	}

	return nil
}

func (k *K8sWatcher) deleteCiliumEnvoyConfig(cec *cilium_v2.CiliumEnvoyConfig) error {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.CiliumEnvoyConfigName: cec.ObjectMeta.Name,
		logfields.K8sNamespace:          cec.ObjectMeta.Namespace,
		logfields.K8sUID:                cec.ObjectMeta.UID,
		logfields.K8sAPIVersion:         cec.TypeMeta.APIVersion,
	})

	resources, err := envoy.ParseResources(
		cec.GetNamespace(),
		cec.GetName(),
		cec.Spec.Resources,
		false,
		k.envoyConfigManager,
		len(cec.Spec.Services) > 0,
		!isIngressKind(&cec.ObjectMeta),
	)
	if err != nil {
		scopedLog.WithError(err).Warn("Failed to delete CiliumEnvoyConfig: parsing rersource names failed")
		return err
	}

	name := loadbalancer.ServiceName{Name: cec.ObjectMeta.Name, Namespace: cec.ObjectMeta.Namespace}
	if err = k.deleteK8sServiceRedirects(name, &cec.Spec); err != nil {
		scopedLog.WithError(err).Warn("Failed to delete K8s service redirections")
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), option.Config.EnvoyConfigTimeout)
	defer cancel()
	if err := k.envoyConfigManager.DeleteEnvoyResources(ctx, resources, k.envoyConfigManager); err != nil {
		scopedLog.WithError(err).Warn("Failed to delete Envoy resources")
		return err
	}

	if len(resources.Listeners) > 0 {
		k.policyManager.TriggerPolicyUpdates(true, "Envoy Listeners deleted")
	}

	scopedLog.Debug("Deleted CiliumEnvoyConfig")
	return nil
}

func (k *K8sWatcher) deleteK8sServiceRedirects(resourceName loadbalancer.ServiceName, spec *cilium_v2.CiliumEnvoyConfigSpec) error {
	for _, svc := range spec.Services {
		// Tell service manager to remove old service redirection
		serviceName := getServiceName(resourceName, svc.Name, svc.Namespace, true)
		err := k.svcManager.RemoveL7LBService(serviceName, resourceName)
		if err != nil {
			return err
		}
	}
	for _, svc := range spec.BackendServices {
		// Tell service manager to remove old service redirection
		serviceName := getServiceName(resourceName, svc.Name, svc.Namespace, false)
		err := k.svcManager.RemoveL7LBService(serviceName, resourceName)
		if err != nil {
			return err
		}
	}

	return nil
}
