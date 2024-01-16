// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"fmt"
	"strconv"

	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/proxy"
	"github.com/cilium/cilium/pkg/service"
)

type ciliumEnvoyConfigWatcher struct {
	logger logrus.FieldLogger

	policyUpdater  *policy.Updater
	serviceManager service.ServiceManager

	proxy         *proxy.Proxy
	xdsServer     envoy.XDSServer
	backendSyncer *envoy.EnvoyServiceBackendSyncer

	appliedCECsMutex lock.Mutex
	appliedCECs      map[resource.Key]*ciliumv2.CiliumEnvoyConfig
	appliedCCECs     map[resource.Key]*ciliumv2.CiliumClusterwideEnvoyConfig
}

func newCiliumEnvoyConfigWatcher(logger logrus.FieldLogger,
	policyUpdater *policy.Updater,
	serviceManager service.ServiceManager,
	proxy *proxy.Proxy,
	xdsServer envoy.XDSServer,
	backendSyncer *envoy.EnvoyServiceBackendSyncer,
) *ciliumEnvoyConfigWatcher {
	return &ciliumEnvoyConfigWatcher{
		logger:         logger,
		policyUpdater:  policyUpdater,
		serviceManager: serviceManager,
		proxy:          proxy,
		xdsServer:      xdsServer,
		backendSyncer:  backendSyncer,
		appliedCECs:    map[resource.Key]*ciliumv2.CiliumEnvoyConfig{},
		appliedCCECs:   map[resource.Key]*ciliumv2.CiliumClusterwideEnvoyConfig{},
	}
}

func (r *ciliumEnvoyConfigWatcher) handleCECEvent(ctx context.Context, event resource.Event[*ciliumv2.CiliumEnvoyConfig]) error {
	scopedLogger := r.logger.
		WithField(logfields.K8sNamespace, event.Key.Namespace).
		WithField(logfields.CiliumEnvoyConfigName, event.Key.Name)

	var err error

	switch event.Kind {
	case resource.Upsert:
		scopedLogger.Debug("Received CiliumEnvoyConfig upsert event")
		err = r.cecUpserted(ctx, event.Key, event.Object)
		if err != nil {
			scopedLogger.WithError(err).Error("failed to handle CEC upsert")
			err = fmt.Errorf("failed to handle CEC upsert: %w", err)
		}
	case resource.Delete:
		scopedLogger.Debug("Received CiliumEnvoyConfig delete event")
		err = r.cecDeleted(ctx, event.Key)
		if err != nil {
			scopedLogger.WithError(err).Error("failed to handle CEC delete")
			err = fmt.Errorf("failed to handle CEC delete: %w", err)
		}
	}

	event.Done(err)

	return nil
}

func (r *ciliumEnvoyConfigWatcher) handleCCECEvent(ctx context.Context, event resource.Event[*ciliumv2.CiliumClusterwideEnvoyConfig]) error {
	scopedLogger := r.logger.
		WithField(logfields.K8sNamespace, event.Key.Namespace).
		WithField(logfields.CiliumClusterwideEnvoyConfigName, event.Key.Name)

	var err error

	switch event.Kind {
	case resource.Upsert:
		scopedLogger.Debug("Received CiliumClusterwideEnvoyConfig upsert event")
		err = r.ccecUpserted(ctx, event.Key, event.Object)
		if err != nil {
			scopedLogger.WithError(err).Error("failed to handle CCEC upsert")
			err = fmt.Errorf("failed to handle CCEC upsert: %w", err)
		}
	case resource.Delete:
		scopedLogger.Debug("Received CiliumClusterwideEnvoyConfig delete event")
		err = r.ccecDeleted(ctx, event.Key)
		if err != nil {
			scopedLogger.WithError(err).Error("failed to handle CCEC delete")
			err = fmt.Errorf("failed to handle CCEC delete: %w", err)
		}
	}

	event.Done(err)

	return nil
}

func (r *ciliumEnvoyConfigWatcher) cecUpserted(ctx context.Context, key resource.Key, cec *ciliumv2.CiliumEnvoyConfig) error {
	r.appliedCECsMutex.Lock()
	defer r.appliedCECsMutex.Unlock()

	appliedCEC, exists := r.appliedCECs[key]
	if exists {
		return r.updateCiliumEnvoyConfig(appliedCEC.ObjectMeta, appliedCEC.Spec, cec.ObjectMeta, cec.Spec)
	}

	if err := r.addCiliumEnvoyConfig(cec.ObjectMeta, cec.Spec); err != nil {
		return err
	}

	r.appliedCECs[key] = cec

	return nil
}

func (r *ciliumEnvoyConfigWatcher) cecDeleted(ctx context.Context, key resource.Key) error {
	r.appliedCECsMutex.Lock()
	defer r.appliedCECsMutex.Unlock()

	appliedCEC, exists := r.appliedCECs[key]
	if !exists {
		return fmt.Errorf("applied CEC with key %q doesn't exist", key)
	}

	if err := r.deleteCiliumEnvoyConfig(appliedCEC.ObjectMeta, appliedCEC.Spec); err != nil {
		return err
	}

	delete(r.appliedCECs, key)

	return nil
}

func (r *ciliumEnvoyConfigWatcher) ccecUpserted(ctx context.Context, key resource.Key, ccec *ciliumv2.CiliumClusterwideEnvoyConfig) error {
	r.appliedCECsMutex.Lock()
	defer r.appliedCECsMutex.Unlock()

	appliedCCEC, exists := r.appliedCCECs[key]
	if exists {
		return r.updateCiliumEnvoyConfig(appliedCCEC.ObjectMeta, appliedCCEC.Spec, ccec.ObjectMeta, ccec.Spec)
	}

	if err := r.addCiliumEnvoyConfig(ccec.ObjectMeta, ccec.Spec); err != nil {
		return err
	}

	r.appliedCCECs[key] = ccec

	return nil
}

func (r *ciliumEnvoyConfigWatcher) ccecDeleted(ctx context.Context, key resource.Key) error {
	r.appliedCECsMutex.Lock()
	defer r.appliedCECsMutex.Unlock()

	appliedCCEC, exists := r.appliedCCECs[key]
	if !exists {
		return fmt.Errorf("applied CCEC with key %q doesn't exist", key)
	}

	if err := r.deleteCiliumEnvoyConfig(appliedCCEC.ObjectMeta, appliedCCEC.Spec); err != nil {
		return err
	}

	delete(r.appliedCCECs, key)

	return nil
}

// useOriginalSourceAddress returns true if the given object metadata indicates that the owner needs the Envoy listener to assume the identity of Cilium Ingress.
// This can be an explicit label or the presence of an OwnerReference of Kind "Ingress" or "Gateway".
func useOriginalSourceAddress(meta *metav1.ObjectMeta) bool {
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

func (r *ciliumEnvoyConfigWatcher) addCiliumEnvoyConfig(cecObjectMeta metav1.ObjectMeta, cecSpec ciliumv2.CiliumEnvoyConfigSpec) error {
	resources, err := envoy.ParseResources(
		cecObjectMeta.GetNamespace(),
		cecObjectMeta.GetName(),
		cecSpec.Resources,
		true,
		r.proxy,
		len(cecSpec.Services) > 0,
		useOriginalSourceAddress(&cecObjectMeta),
		true,
	)
	if err != nil {
		return fmt.Errorf("malformed Envoy config: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), option.Config.EnvoyConfigTimeout)
	defer cancel()
	if err := r.xdsServer.UpsertEnvoyResources(ctx, resources); err != nil {
		return fmt.Errorf("failed to upsert envoy resources: %w", err)
	}

	name := service.L7LBResourceName{Name: cecObjectMeta.Name, Namespace: cecObjectMeta.Namespace}
	if err := r.addK8sServiceRedirects(name, &cecSpec, resources); err != nil {
		return fmt.Errorf("failed to redirect k8s services to Envoy: %w", err)
	}

	if len(resources.Listeners) > 0 {
		// TODO: Policy does not need to be recomputed for this, but if we do not 'force'
		// the bpf maps are not updated with the new proxy ports either. Move from the
		// simple boolean to an enum that can more selectively skip regeneration steps (like
		// we do for the datapath recompilations already?)
		r.policyUpdater.TriggerPolicyUpdates(true, "Envoy Listeners added")
	}

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

func (r *ciliumEnvoyConfigWatcher) addK8sServiceRedirects(resourceName service.L7LBResourceName, spec *ciliumv2.CiliumEnvoyConfigSpec, resources envoy.Resources) error {
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
			return fmt.Errorf("listener %q not found in resources", svc.Listener)
		}

		// Tell service manager to redirect the service to the port
		serviceName := getServiceName(resourceName, svc.Name, svc.Namespace, true)
		if err := r.serviceManager.RegisterL7LBServiceRedirect(serviceName, resourceName, proxyPort); err != nil {
			return err
		}

		if err := r.registerServiceSync(serviceName, resourceName, nil /* all ports */); err != nil {
			return err
		}
	}
	// Register services for Envoy backend sync
	for _, svc := range spec.BackendServices {
		serviceName := getServiceName(resourceName, svc.Name, svc.Namespace, false)

		if err := r.registerServiceSync(serviceName, resourceName, svc.Ports); err != nil {
			return err
		}
	}

	return nil
}

func (r *ciliumEnvoyConfigWatcher) updateCiliumEnvoyConfig(
	oldCECObjectMeta metav1.ObjectMeta, oldCECSpec ciliumv2.CiliumEnvoyConfigSpec,
	newCECObjectMeta metav1.ObjectMeta, newCECSpec ciliumv2.CiliumEnvoyConfigSpec,
) error {
	oldResources, err := envoy.ParseResources(
		oldCECObjectMeta.GetNamespace(),
		oldCECObjectMeta.GetName(),
		oldCECSpec.Resources,
		false,
		r.proxy,
		len(oldCECSpec.Services) > 0,
		useOriginalSourceAddress(&oldCECObjectMeta),
		false,
	)
	if err != nil {
		return fmt.Errorf("malformed old Envoy Config: %w", err)
	}
	newResources, err := envoy.ParseResources(
		newCECObjectMeta.GetNamespace(),
		newCECObjectMeta.GetName(),
		newCECSpec.Resources,
		true,
		r.proxy,
		len(newCECSpec.Services) > 0,
		useOriginalSourceAddress(&newCECObjectMeta),
		true,
	)
	if err != nil {
		return fmt.Errorf("malformed new Envoy config: %w", err)
	}

	name := service.L7LBResourceName{Name: oldCECObjectMeta.Name, Namespace: oldCECObjectMeta.Namespace}
	if err := r.removeK8sServiceRedirects(name, &oldCECSpec, &newCECSpec, oldResources, newResources); err != nil {
		return fmt.Errorf("failed to update k8s service redirects: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), option.Config.EnvoyConfigTimeout)
	defer cancel()
	if err := r.xdsServer.UpdateEnvoyResources(ctx, oldResources, newResources); err != nil {
		return fmt.Errorf("failed to update Envoy resources: %w", err)
	}

	if err := r.addK8sServiceRedirects(name, &newCECSpec, newResources); err != nil {
		return fmt.Errorf("failed to redirect k8s services to Envoy: %w", err)
	}

	if oldResources.ListenersAddedOrDeleted(&newResources) {
		r.policyUpdater.TriggerPolicyUpdates(true, "Envoy Listeners added or deleted")
	}

	return nil
}

func (r *ciliumEnvoyConfigWatcher) removeK8sServiceRedirects(resourceName service.L7LBResourceName, oldSpec, newSpec *ciliumv2.CiliumEnvoyConfigSpec, oldResources, newResources envoy.Resources) error {
	removedServices := []*ciliumv2.ServiceListener{}
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
		if err := r.serviceManager.DeregisterL7LBServiceRedirect(serviceName, resourceName); err != nil {
			return err
		}

		// Deregister Service from Secret Sync
		if err := r.deregisterServiceSync(serviceName, resourceName); err != nil {
			return err
		}
	}
	removedBackendServices := []*ciliumv2.Service{}
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
		if err := r.deregisterServiceSync(serviceName, resourceName); err != nil {
			return err
		}
	}

	return nil
}

func (r *ciliumEnvoyConfigWatcher) deleteCiliumEnvoyConfig(cecObjectMeta metav1.ObjectMeta, cecSpec ciliumv2.CiliumEnvoyConfigSpec) error {
	resources, err := envoy.ParseResources(
		cecObjectMeta.GetNamespace(),
		cecObjectMeta.GetName(),
		cecSpec.Resources,
		false,
		r.proxy,
		len(cecSpec.Services) > 0,
		useOriginalSourceAddress(&cecObjectMeta),
		false,
	)
	if err != nil {
		return fmt.Errorf("parsing resources names failed: %w", err)
	}

	name := service.L7LBResourceName{Name: cecObjectMeta.Name, Namespace: cecObjectMeta.Namespace}
	if err := r.deleteK8sServiceRedirects(name, &cecSpec); err != nil {
		return fmt.Errorf("failed to delete k8s service redirects: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), option.Config.EnvoyConfigTimeout)
	defer cancel()
	if err := r.xdsServer.DeleteEnvoyResources(ctx, resources); err != nil {
		return fmt.Errorf("failed to delete Envoy resources: %w", err)
	}

	if len(resources.Listeners) > 0 {
		r.policyUpdater.TriggerPolicyUpdates(true, "Envoy Listeners deleted")
	}

	return nil
}

func (r *ciliumEnvoyConfigWatcher) deleteK8sServiceRedirects(resourceName service.L7LBResourceName, spec *ciliumv2.CiliumEnvoyConfigSpec) error {
	for _, svc := range spec.Services {
		serviceName := getServiceName(resourceName, svc.Name, svc.Namespace, true)

		// Tell service manager to remove old service redirection
		if err := r.serviceManager.DeregisterL7LBServiceRedirect(serviceName, resourceName); err != nil {
			return err
		}

		// Deregister Service from Secret Sync
		if err := r.deregisterServiceSync(serviceName, resourceName); err != nil {
			return err
		}
	}

	for _, svc := range spec.BackendServices {
		serviceName := getServiceName(resourceName, svc.Name, svc.Namespace, false)

		// Deregister Service from Secret Sync
		if err := r.deregisterServiceSync(serviceName, resourceName); err != nil {
			return err
		}
	}

	return nil
}

func (r *ciliumEnvoyConfigWatcher) registerServiceSync(serviceName loadbalancer.ServiceName, resourceName service.L7LBResourceName, ports []string) error {
	// Register service usage in Envoy backend sync
	r.backendSyncer.RegisterServiceUsageInCEC(serviceName, resourceName, ports)

	// Register Envoy Backend Sync for the specific service in the service manager.
	// A re-registration will trigger an implicit re-synchronization.
	if err := r.serviceManager.RegisterL7LBServiceBackendSync(serviceName, r.backendSyncer); err != nil {
		return err
	}

	return nil
}

func (r *ciliumEnvoyConfigWatcher) deregisterServiceSync(serviceName loadbalancer.ServiceName, resourceName service.L7LBResourceName) error {
	// Deregister usage of Service from Envoy Backend Sync
	isLastDeregistration := r.backendSyncer.DeregisterServiceUsageInCEC(serviceName, resourceName)

	if isLastDeregistration {
		// Tell service manager to remove backend sync for this service
		if err := r.serviceManager.DeregisterL7LBServiceBackendSync(serviceName, r.backendSyncer); err != nil {
			return err
		}

		return nil
	}

	// There are other CECs using the same service as backend.
	// Re-Register the backend-sync to enforce a synchronization.
	if err := r.serviceManager.RegisterL7LBServiceBackendSync(serviceName, r.backendSyncer); err != nil {
		return err
	}

	return nil
}
