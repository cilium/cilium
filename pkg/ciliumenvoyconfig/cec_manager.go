// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"context"
	"fmt"
	"slices"
	"strconv"

	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/service"
	"github.com/cilium/cilium/pkg/time"
)

type ciliumEnvoyConfigManager interface {
	addCiliumEnvoyConfig(cecObjectMeta metav1.ObjectMeta, cecSpec *ciliumv2.CiliumEnvoyConfigSpec) error
	updateCiliumEnvoyConfig(oldCECObjectMeta metav1.ObjectMeta, oldCECSpec *ciliumv2.CiliumEnvoyConfigSpec, newCECObjectMeta metav1.ObjectMeta, newCECSpec *ciliumv2.CiliumEnvoyConfigSpec) error
	deleteCiliumEnvoyConfig(cecObjectMeta metav1.ObjectMeta, cecSpec *ciliumv2.CiliumEnvoyConfigSpec) error
	syncHeadlessService(name string, namespace string, cecSpec *ciliumv2.CiliumEnvoyConfigSpec) error
}

type cecManager struct {
	logger logrus.FieldLogger

	policyUpdater  *policy.Updater
	serviceManager service.ServiceManager

	xdsServer      envoy.XDSServer
	backendSyncer  *envoyServiceBackendSyncer
	resourceParser *cecResourceParser

	envoyConfigTimeout time.Duration

	services  resource.Resource[*slim_corev1.Service]
	endpoints resource.Resource[*k8s.Endpoints]
}

func newCiliumEnvoyConfigManager(logger logrus.FieldLogger,
	policyUpdater *policy.Updater,
	serviceManager service.ServiceManager,
	xdsServer envoy.XDSServer,
	backendSyncer *envoyServiceBackendSyncer,
	resourceParser *cecResourceParser,
	envoyConfigTimeout time.Duration,
	services resource.Resource[*slim_corev1.Service],
	endpoints resource.Resource[*k8s.Endpoints],
) *cecManager {
	return &cecManager{
		logger:             logger,
		policyUpdater:      policyUpdater,
		serviceManager:     serviceManager,
		xdsServer:          xdsServer,
		backendSyncer:      backendSyncer,
		resourceParser:     resourceParser,
		envoyConfigTimeout: envoyConfigTimeout,
		services:           services,
		endpoints:          endpoints,
	}
}

func (r *cecManager) addCiliumEnvoyConfig(cecObjectMeta metav1.ObjectMeta, cecSpec *ciliumv2.CiliumEnvoyConfigSpec) error {
	resources, err := r.resourceParser.parseResources(
		cecObjectMeta.GetNamespace(),
		cecObjectMeta.GetName(),
		cecSpec.Resources,
		len(cecSpec.Services) > 0,
		useOriginalSourceAddress(&cecObjectMeta),
		true,
	)
	if err != nil {
		return fmt.Errorf("malformed Envoy config: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), r.envoyConfigTimeout)
	defer cancel()
	if err := r.xdsServer.UpsertEnvoyResources(ctx, resources); err != nil {
		return fmt.Errorf("failed to upsert envoy resources: %w", err)
	}

	name := service.L7LBResourceName{Name: cecObjectMeta.Name, Namespace: cecObjectMeta.Namespace}
	if err := r.addK8sServiceRedirects(name, cecSpec, resources); err != nil {
		return fmt.Errorf("failed to redirect k8s services to Envoy in CEC Add: %w", err)
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

func (r *cecManager) addK8sServiceRedirects(resourceName service.L7LBResourceName, spec *ciliumv2.CiliumEnvoyConfigSpec, resources envoy.Resources) error {
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
			// Do not return (and later on log) error in case of a service with an empty listener reference.
			// This is the case for the shared CEC in the Cilium namespace, if there is no shared Ingress
			// present in the cluster.
			if svc.Listener == "" {
				r.logger.Infof("Skipping L7LB k8s service redirect for service %s/%s. No Listener found in CEC resources", svc.Namespace, svc.Name)
				continue
			}

			return fmt.Errorf("listener %q not found in resources", svc.Listener)
		}

		// Add any relevant Nodeport values into the list of Ports to redirect.
		nodePorts, err := r.getServiceNodeports(svc.Name, svc.Namespace, svc.Ports)
		if err != nil {
			return err
		}
		svc.Ports = append(svc.Ports, nodePorts...)

		// Tell service manager to redirect the service to the port
		serviceName := getServiceName(resourceName, svc.Name, svc.Namespace, true)
		if err := r.serviceManager.RegisterL7LBServiceRedirect(serviceName, resourceName, proxyPort, svc.Ports); err != nil {
			return err
		}

		if err := r.registerServiceSync(serviceName, resourceName, nil /* all ports */); err != nil {
			return err
		}
	}
	return r.syncHeadlessService(resourceName.Name, resourceName.Namespace, spec)
}

func (r *cecManager) syncHeadlessService(name string, namespace string, spec *ciliumv2.CiliumEnvoyConfigSpec) error {
	resourceName := service.L7LBResourceName{Name: name, Namespace: namespace}

	// Register services for Envoy backend sync
	for _, svc := range spec.BackendServices {
		serviceName := getServiceName(resourceName, svc.Name, svc.Namespace, false)

		if err := r.registerServiceSync(serviceName, resourceName, svc.Ports); err != nil {
			return err
		}

		kSvc, err := r.getK8sService(svc.Name, svc.Namespace)
		if err != nil {
			return err
		}

		if kSvc == nil {
			return fmt.Errorf("could not retrieve service details for service %s/%s", svc.Namespace, svc.Name)
		}

		// Skip non-headless services as they are already supported in Cilium datapath LB service.
		if kSvc.Spec.ClusterIP != slim_corev1.ClusterIPNone {
			continue
		}

		ep, err := r.getEndpoint(svc.Name, svc.Namespace)
		if err != nil {
			return err
		}
		if ep == nil {
			return fmt.Errorf("could not retrieve endpoint details for service %s/%s", svc.Namespace, svc.Name)
		}

		r.logger.WithField("TAM", "TAM CEC Manager 3").
			WithField("resource_name", resourceName).
			WithField("endpoint_name", ep.Name).
			WithField("endpoint_namespace", ep.Namespace).
			Debug("Synced headless services for CEC, ALL GOOD")

		// Explicitly call backendSyncer.Sync for headless service
		for _, s := range convertToLBService(kSvc, ep) {
			if err = r.backendSyncer.Sync(s); err != nil {
				return err
			}
		}
	}
	return nil
}

// getServiceNodeports returns any relevant Nodeport numbers for the provided
// Service ports. If the provided servicePorts do not have any nodeports set, returns
// an empty list.
func (r *cecManager) getServiceNodeports(name, namespace string, servicePorts []uint16) ([]uint16, error) {
	var nodePorts []uint16
	kSvc, err := r.getK8sService(name, namespace)
	if err != nil {
		return nodePorts, fmt.Errorf("could not retrieve service details for service %s/%s", namespace, name)
	}

	for _, servicePort := range servicePorts {
		for _, port := range kSvc.Spec.Ports {
			if servicePort == uint16(port.Port) {
				if port.NodePort != 0 {
					nodePorts = append(nodePorts, uint16(port.NodePort))
				}
			}
		}
	}

	return nodePorts, nil
}

// getK8sService retrieves k8s service from the store
func (r *cecManager) getK8sService(name string, namespace string) (*slim_corev1.Service, error) {
	store, err := r.services.Store(context.Background())
	if err != nil {
		return nil, err
	}
	svc, exists, err := store.GetByKey(resource.Key{
		Name:      name,
		Namespace: namespace,
	})
	if svc == nil {
		return nil, fmt.Errorf("retrieved nil details for Service %s/%s", namespace, name)
	}
	if !exists || err != nil {
		return nil, err
	}
	return svc, nil
}

// getEndpoint retrieves k8s endpoint from the store.
// Endpoint might not have the same name as the service name if EndpointSlice is enabled,
// so we need to loop through all endpoints to find the correct one.
func (r *cecManager) getEndpoint(serviceName string, serviceNamespace string) (*k8s.Endpoints, error) {
	store, err := r.endpoints.Store(context.Background())
	if err != nil {
		return nil, err
	}

	iter := store.IterKeys()
	for iter.Next() {
		e, _, _ := store.GetByKey(iter.Key())
		if e.EndpointSliceID.ServiceID.Name == serviceName &&
			e.EndpointSliceID.ServiceID.Namespace == serviceNamespace {
			return e, nil
		}
	}
	return nil, nil
}

func convertToLBService(svc *slim_corev1.Service, ep *k8s.Endpoints) []*loadbalancer.SVC {
	var res []*loadbalancer.SVC
	fePorts := map[loadbalancer.FEPortName]*loadbalancer.L4Addr{}
	var sortedPorts []loadbalancer.FEPortName

	for _, port := range svc.Spec.Ports {
		portName := loadbalancer.FEPortName(port.Name)
		if _, ok := fePorts[portName]; !ok {
			fePorts[portName] = loadbalancer.NewL4Addr(loadbalancer.L4Type(port.Protocol), uint16(port.Port))
			sortedPorts = append(sortedPorts, portName)
		}
	}
	// Sort the ports to ensure deterministic order
	slices.Sort(sortedPorts)

	for _, fePortName := range sortedPorts {
		fePort := fePorts[fePortName]
		s := &loadbalancer.SVC{
			Name: loadbalancer.ServiceName{
				Name:      svc.Name,
				Namespace: svc.Namespace,
			},
			Frontend: loadbalancer.L3n4AddrID{
				L3n4Addr: loadbalancer.L3n4Addr{
					L4Addr: loadbalancer.L4Addr{
						Protocol: fePort.Protocol,
						Port:     fePort.Port,
					},
				},
			},
		}

		for addrCluster, be := range ep.Backends {
			if l4Addr := be.Ports[string(fePortName)]; l4Addr != nil {
				s.Backends = append(s.Backends, &loadbalancer.Backend{
					FEPortName: string(fePortName),
					L3n4Addr:   *loadbalancer.NewL3n4Addr(l4Addr.Protocol, addrCluster, l4Addr.Port, 0),
				})
			}
		}

		res = append(res, s)
	}

	return res
}

func (r *cecManager) updateCiliumEnvoyConfig(
	oldCECObjectMeta metav1.ObjectMeta, oldCECSpec *ciliumv2.CiliumEnvoyConfigSpec,
	newCECObjectMeta metav1.ObjectMeta, newCECSpec *ciliumv2.CiliumEnvoyConfigSpec,
) error {
	oldResources, err := r.resourceParser.parseResources(
		oldCECObjectMeta.GetNamespace(),
		oldCECObjectMeta.GetName(),
		oldCECSpec.Resources,
		len(oldCECSpec.Services) > 0,
		useOriginalSourceAddress(&oldCECObjectMeta),
		false,
	)
	if err != nil {
		return fmt.Errorf("malformed old Envoy Config: %w", err)
	}
	newResources, err := r.resourceParser.parseResources(
		newCECObjectMeta.GetNamespace(),
		newCECObjectMeta.GetName(),
		newCECSpec.Resources,
		len(newCECSpec.Services) > 0,
		useOriginalSourceAddress(&newCECObjectMeta),
		true,
	)
	if err != nil {
		return fmt.Errorf("malformed new Envoy config: %w", err)
	}

	name := service.L7LBResourceName{Name: oldCECObjectMeta.Name, Namespace: oldCECObjectMeta.Namespace}
	if err := r.removeK8sServiceRedirects(name, oldCECSpec, newCECSpec, oldResources, newResources); err != nil {
		return fmt.Errorf("failed to update k8s service redirects: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), r.envoyConfigTimeout)
	defer cancel()
	if err := r.xdsServer.UpdateEnvoyResources(ctx, oldResources, newResources); err != nil {
		return fmt.Errorf("failed to update Envoy resources: %w", err)
	}

	if err := r.addK8sServiceRedirects(name, newCECSpec, newResources); err != nil {
		return fmt.Errorf("failed to redirect k8s services to Envoy in CEC Update: %w", err)
	}

	if oldResources.ListenersAddedOrDeleted(&newResources) {
		r.policyUpdater.TriggerPolicyUpdates(true, "Envoy Listeners added or deleted")
	}

	return nil
}

func (r *cecManager) removeK8sServiceRedirects(resourceName service.L7LBResourceName, oldSpec, newSpec *ciliumv2.CiliumEnvoyConfigSpec, oldResources, newResources envoy.Resources) error {
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

func (r *cecManager) deleteCiliumEnvoyConfig(cecObjectMeta metav1.ObjectMeta, cecSpec *ciliumv2.CiliumEnvoyConfigSpec) error {
	resources, err := r.resourceParser.parseResources(
		cecObjectMeta.GetNamespace(),
		cecObjectMeta.GetName(),
		cecSpec.Resources,
		len(cecSpec.Services) > 0,
		useOriginalSourceAddress(&cecObjectMeta),
		false,
	)
	if err != nil {
		return fmt.Errorf("parsing resources names failed: %w", err)
	}

	name := service.L7LBResourceName{Name: cecObjectMeta.Name, Namespace: cecObjectMeta.Namespace}
	if err := r.deleteK8sServiceRedirects(name, cecSpec); err != nil {
		return fmt.Errorf("failed to delete k8s service redirects: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), r.envoyConfigTimeout)
	defer cancel()
	if err := r.xdsServer.DeleteEnvoyResources(ctx, resources); err != nil {
		return fmt.Errorf("failed to delete Envoy resources: %w", err)
	}

	if len(resources.Listeners) > 0 {
		r.policyUpdater.TriggerPolicyUpdates(true, "Envoy Listeners deleted")
	}

	return nil
}

func (r *cecManager) deleteK8sServiceRedirects(resourceName service.L7LBResourceName, spec *ciliumv2.CiliumEnvoyConfigSpec) error {
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

func (r *cecManager) registerServiceSync(serviceName loadbalancer.ServiceName, resourceName service.L7LBResourceName, ports []string) error {
	// Register service usage in Envoy backend sync
	r.backendSyncer.RegisterServiceUsageInCEC(serviceName, resourceName, ports)

	// Register Envoy Backend Sync for the specific service in the service manager.
	// A re-registration will trigger an implicit re-synchronization.
	if err := r.serviceManager.RegisterL7LBServiceBackendSync(serviceName, r.backendSyncer); err != nil {
		return err
	}

	return nil
}

func (r *cecManager) deregisterServiceSync(serviceName loadbalancer.ServiceName, resourceName service.L7LBResourceName) error {
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
