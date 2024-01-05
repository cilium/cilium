// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"fmt"
	"strconv"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/service"
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
				if cec := k8s.CastInformerEvent[cilium_v2.CiliumEnvoyConfig](obj); cec != nil {
					valid = true
					err := k.addCiliumEnvoyConfig(cec)
					k.K8sEventProcessed(metricCEC, resources.MetricCreate, err == nil)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(apiGroup, metricCEC, resources.MetricUpdate, valid, equal) }()

				if oldCEC := k8s.CastInformerEvent[cilium_v2.CiliumEnvoyConfig](oldObj); oldCEC != nil {
					if newCEC := k8s.CastInformerEvent[cilium_v2.CiliumEnvoyConfig](newObj); newCEC != nil {
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
				cec := k8s.CastInformerEvent[cilium_v2.CiliumEnvoyConfig](obj)
				if cec == nil {
					return
				}
				valid = true
				err := k.deleteCiliumEnvoyConfig(cec)
				k.K8sEventProcessed(metricCEC, resources.MetricDelete, err == nil)
			},
		},
		nil,
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

// useOriginalSourceAddress returns true if the given object metadata indicates that the owner needs the Envoy listener to assume the identity of Cilium Ingress.
// This can be an explicit label or the presence of an OwnerReference of Kind "Ingress" or "Gateway".
func useOriginalSourceAddress(meta *meta_v1.ObjectMeta) bool {
	for _, owner := range meta.OwnerReferences {
		if owner.Kind == "Ingress" || owner.Kind == "Gateway" {
			return false
		}
	}

	if meta.GetLabels() != nil {
		if v, ok := meta.GetLabels()[k8s.UseOriginalSourceAddressLabel]; ok {
			if boolValue, err := strconv.ParseBool(v); err == nil {
				return boolValue
			}
		}
	}

	return true
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
		k.proxyPortAllocator,
		len(cec.Spec.Services) > 0,
		useOriginalSourceAddress(&cec.ObjectMeta),
		true,
	)
	if err != nil {
		scopedLog.WithError(err).Warn("Failed to add CiliumEnvoyConfig: malformed Envoy config")
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), option.Config.EnvoyConfigTimeout)
	defer cancel()
	if err := k.envoyXdsServer.UpsertEnvoyResources(ctx, resources); err != nil {
		scopedLog.WithError(err).Warn("Failed to add CiliumEnvoyConfig")
		return err
	}

	name := service.L7LBResourceName{Name: cec.ObjectMeta.Name, Namespace: cec.ObjectMeta.Namespace}
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
func getServiceName(resourceName service.L7LBResourceName, name, namespace string, isFrontend bool) loadbalancer.ServiceName {
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

func (k *K8sWatcher) addK8sServiceRedirects(resourceName service.L7LBResourceName, spec *cilium_v2.CiliumEnvoyConfigSpec, resources envoy.Resources) error {
	// Redirect k8s services to an Envoy listener
	for _, svc := range spec.Services {
		svcListener := ""
		if svc.Listener != "" {
			// Listener names are qualified after parsing, so qualify the listener reference as well for it to match
			svcListener, _ = api.ResourceQualifiedName(resourceName.Namespace, resourceName.Name, svc.Listener, api.ForceNamespace)
		}
		// Find the listener the service is to be redirected to
		var proxyPort uint16
		for _, l := range resources.Listeners {
			if svc.Listener == "" || l.Name == svcListener {
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
		if err := k.svcManager.RegisterL7LBServiceRedirect(serviceName, resourceName, proxyPort); err != nil {
			return err
		}

		if err := k.registerServiceSync(serviceName, resourceName, nil /* all ports */); err != nil {
			return err
		}
	}
	// Register services for Envoy backend sync
	for _, svc := range spec.BackendServices {
		serviceName := getServiceName(resourceName, svc.Name, svc.Namespace, false)

		if err := k.registerServiceSync(serviceName, resourceName, svc.Ports); err != nil {
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
		k.proxyPortAllocator,
		len(oldCEC.Spec.Services) > 0,
		useOriginalSourceAddress(&oldCEC.ObjectMeta),
		false,
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
		k.proxyPortAllocator,
		len(newCEC.Spec.Services) > 0,
		useOriginalSourceAddress(&newCEC.ObjectMeta),
		true,
	)
	if err != nil {
		scopedLog.WithError(err).Warn("Failed to update CiliumEnvoyConfig: malformed new Envoy config")
		return err
	}

	name := service.L7LBResourceName{Name: oldCEC.ObjectMeta.Name, Namespace: oldCEC.ObjectMeta.Namespace}
	if err := k.removeK8sServiceRedirects(name, &oldCEC.Spec, &newCEC.Spec, oldResources, newResources); err != nil {
		scopedLog.WithError(err).Warn("Failed to update K8s service redirections")
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), option.Config.EnvoyConfigTimeout)
	defer cancel()
	if err := k.envoyXdsServer.UpdateEnvoyResources(ctx, oldResources, newResources); err != nil {
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

func (k *K8sWatcher) removeK8sServiceRedirects(resourceName service.L7LBResourceName, oldSpec, newSpec *cilium_v2.CiliumEnvoyConfigSpec, oldResources, newResources envoy.Resources) error {
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
		serviceName := getServiceName(resourceName, oldSvc.Name, oldSvc.Namespace, true)

		// Tell service manager to remove old service registration
		if err := k.svcManager.DeregisterL7LBServiceRedirect(serviceName, resourceName); err != nil {
			return err
		}

		// Deregister Service from Secret Sync
		if err := k.deregisterServiceSync(serviceName, resourceName); err != nil {
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
		serviceName := getServiceName(resourceName, oldSvc.Name, oldSvc.Namespace, false)

		// Deregister Service from Secret Sync
		if err := k.deregisterServiceSync(serviceName, resourceName); err != nil {
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
		k.proxyPortAllocator,
		len(cec.Spec.Services) > 0,
		useOriginalSourceAddress(&cec.ObjectMeta),
		false,
	)
	if err != nil {
		scopedLog.WithError(err).Warn("Failed to delete CiliumEnvoyConfig: parsing rersource names failed")
		return err
	}

	name := service.L7LBResourceName{Name: cec.ObjectMeta.Name, Namespace: cec.ObjectMeta.Namespace}
	if err := k.deleteK8sServiceRedirects(name, &cec.Spec); err != nil {
		scopedLog.WithError(err).Warn("Failed to delete K8s service redirections")
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), option.Config.EnvoyConfigTimeout)
	defer cancel()
	if err := k.envoyXdsServer.DeleteEnvoyResources(ctx, resources); err != nil {
		scopedLog.WithError(err).Warn("Failed to delete Envoy resources")
		return err
	}

	if len(resources.Listeners) > 0 {
		k.policyManager.TriggerPolicyUpdates(true, "Envoy Listeners deleted")
	}

	scopedLog.Debug("Deleted CiliumEnvoyConfig")
	return nil
}

func (k *K8sWatcher) deleteK8sServiceRedirects(resourceName service.L7LBResourceName, spec *cilium_v2.CiliumEnvoyConfigSpec) error {
	for _, svc := range spec.Services {
		serviceName := getServiceName(resourceName, svc.Name, svc.Namespace, true)

		// Tell service manager to remove old service redirection
		if err := k.svcManager.DeregisterL7LBServiceRedirect(serviceName, resourceName); err != nil {
			return err
		}

		// Deregister Service from Secret Sync
		if err := k.deregisterServiceSync(serviceName, resourceName); err != nil {
			return err
		}
	}

	for _, svc := range spec.BackendServices {
		serviceName := getServiceName(resourceName, svc.Name, svc.Namespace, false)

		// Deregister Service from Secret Sync
		if err := k.deregisterServiceSync(serviceName, resourceName); err != nil {
			return err
		}
	}

	return nil
}

func (k *K8sWatcher) registerServiceSync(serviceName loadbalancer.ServiceName, resourceName service.L7LBResourceName, ports []string) error {
	// Register service usage in Envoy backend sync
	k.envoyL7LBBackendSyncer.RegisterServiceUsageInCEC(serviceName, resourceName, ports)

	// Register Envoy Backend Sync for the specific service in the service manager.
	// A re-registration will trigger an implicit re-synchronization.
	if err := k.svcManager.RegisterL7LBServiceBackendSync(serviceName, k.envoyL7LBBackendSyncer); err != nil {
		return err
	}

	return nil
}

func (k *K8sWatcher) deregisterServiceSync(serviceName loadbalancer.ServiceName, resourceName service.L7LBResourceName) error {
	// Deregister usage of Service from Envoy Backend Sync
	isLastDeregistration := k.envoyL7LBBackendSyncer.DeregisterServiceUsageInCEC(serviceName, resourceName)

	if isLastDeregistration {
		// Tell service manager to remove backend sync for this service
		if err := k.svcManager.DeregisterL7LBServiceBackendSync(serviceName, k.envoyL7LBBackendSyncer); err != nil {
			return err
		}

		return nil
	}

	// There are other CECs using the same service as backend.
	// Re-Register the backend-sync to enforce a synchronization.
	if err := k.svcManager.RegisterL7LBServiceBackendSync(serviceName, k.envoyL7LBBackendSyncer); err != nil {
		return err
	}

	return nil
}
