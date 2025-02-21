// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"fmt"
	"slices"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/operator/pkg/model/translation"
	"github.com/cilium/cilium/pkg/annotation"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/shortener"
)

var _ translation.Translator = (*gatewayAPITranslator)(nil)

const (
	ciliumGatewayPrefix = "cilium-gateway-"
	// Deprecated: owningGatewayLabel will be removed later in favour of gatewayNameLabel
	owningGatewayLabel = "io.cilium.gateway/owning-gateway"
	gatewayNameLabel   = "gateway.networking.k8s.io/gateway-name"
)

type gatewayAPITranslator struct {
	cecTranslator translation.CECTranslator
	cfg           translation.Config
}

func NewTranslator(cecTranslator translation.CECTranslator, cfg translation.Config) translation.Translator {
	return &gatewayAPITranslator{
		cecTranslator: cecTranslator,
		cfg:           cfg,
	}
}

func (t *gatewayAPITranslator) Translate(m *model.Model) (*ciliumv2.CiliumEnvoyConfig, *corev1.Service, *corev1.Endpoints, error) {
	listeners := m.GetListeners()
	if len(listeners) == 0 || len(listeners[0].GetSources()) == 0 {
		return nil, nil, nil, fmt.Errorf("model source can't be empty")
	}

	// source is the main object that is the source of the model.Model
	var source *model.FullyQualifiedResource
	// owner is the object that will be the owner of the created CEC
	// for Gateways, source == owner == the created LB service
	// for Services (that is, GAMMA), source is the parent Service, and owner
	// is the HTTPRoute.
	var owner *model.FullyQualifiedResource

	var ports []uint32
	for _, l := range listeners {
		sources := l.GetSources()
		source = &sources[0]
		owner = source
		// If there's more than one source in the listener, then this model is a GAMMA one,
		// and includes a HTTPRoute source as the second one.
		if len(sources) > 1 {
			owner = &sources[1]
		}

		ports = append(ports, l.GetPort())
	}

	if source == nil || source.Name == "" {
		return nil, nil, nil, fmt.Errorf("model source name can't be empty")
	}

	// generatedName is the name of the generated objects.
	// for Gateways, this is "cilium-gateway-<servicename>"
	// for GAMMA, this is just "<servicename>"
	generatedName := ciliumGatewayPrefix + source.Name

	// TODO: remove this hack
	if source.Kind == "Service" {
		generatedName = source.Name
	}
	cec, err := t.cecTranslator.Translate(source.Namespace, generatedName, m)
	if err != nil {
		return nil, nil, nil, err
	}

	var allLabels, allAnnotations map[string]string
	// Merge all the labels and annotations from the listeners.
	// Normally, the labels and annotations are the same for all the listeners having same gateway.
	for _, l := range listeners {
		allAnnotations = mergeMap(allAnnotations, l.GetAnnotations())
		allLabels = mergeMap(allLabels, l.GetLabels())
	}

	if err = decorateCEC(cec, owner, allLabels, allAnnotations); err != nil {
		return nil, nil, nil, err
	}

	ep := t.desiredEndpoints(source, allLabels, allAnnotations)
	lbSvc := t.desiredService(listeners[0].GetService(), source, ports, allLabels, allAnnotations)

	return cec, lbSvc, ep, err
}

func (t *gatewayAPITranslator) desiredService(params *model.Service, owner *model.FullyQualifiedResource,
	ports []uint32, labels, annotations map[string]string) *corev1.Service {
	if owner == nil {
		return nil
	}

	uniquePorts := map[uint32]struct{}{}
	for _, p := range ports {
		uniquePorts[p] = struct{}{}
	}

	servicePorts := make([]corev1.ServicePort, 0, len(uniquePorts))
	for p := range uniquePorts {
		servicePorts = append(servicePorts, corev1.ServicePort{
			Name:     fmt.Sprintf("port-%d", p),
			Port:     int32(p),
			Protocol: corev1.ProtocolTCP,
		})
	}
	slices.SortFunc(servicePorts, func(a, b corev1.ServicePort) int {
		return int(a.Port) - int(b.Port)
	})

	shortenName := shortener.ShortenK8sResourceName(owner.Name)

	res := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      shortener.ShortenK8sResourceName(ciliumGatewayPrefix + owner.Name),
			Namespace: owner.Namespace,
			Labels: mergeMap(map[string]string{
				owningGatewayLabel: shortenName,
				gatewayNameLabel:   shortenName,
			}, labels),
			Annotations: t.toServiceAnnotations(annotations, params),
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: gatewayv1beta1.GroupVersion.String(),
					Kind:       owner.Kind,
					Name:       owner.Name,
					UID:        types.UID(owner.UID),
					Controller: ptr.To(true),
				},
			},
		},
		Spec: corev1.ServiceSpec{
			Ports:                         t.toServicePorts(ports),
			Type:                          t.toServiceType(params),
			ExternalTrafficPolicy:         t.toExternalTrafficPolicy(params),
			LoadBalancerClass:             t.toLoadBalancerClass(params),
			LoadBalancerSourceRanges:      t.toLoadBalancerSourceRanges(params),
			IPFamilies:                    t.toIPFamilies(params),
			IPFamilyPolicy:                t.toIPFamilyPolicy(params),
			AllocateLoadBalancerNodePorts: t.toAllocateLoadBalancerNodePorts(params),
			TrafficDistribution:           t.toTrafficDistribution(params),
		},
	}

	return res
}

// toServicePorts returns a list of ServicePort objects from the given list of ports.
func (t *gatewayAPITranslator) toServicePorts(ports []uint32) []corev1.ServicePort {
	uniquePorts := map[uint32]struct{}{}
	for _, p := range ports {
		uniquePorts[p] = struct{}{}
	}

	servicePorts := make([]corev1.ServicePort, 0, len(uniquePorts))
	for p := range uniquePorts {
		servicePorts = append(servicePorts, corev1.ServicePort{
			Name:     fmt.Sprintf("port-%d", p),
			Port:     int32(p),
			Protocol: corev1.ProtocolTCP,
		})
	}
	slices.SortFunc(servicePorts, func(a, b corev1.ServicePort) int {
		return int(a.Port) - int(b.Port)
	})

	return servicePorts
}

// toServiceType returns the ServiceType from the given Service object.
// If hostNetwork is enabled, it returns ServiceTypeClusterIP. The default value is ServiceTypeLoadBalancer.
func (t *gatewayAPITranslator) toServiceType(params *model.Service) corev1.ServiceType {
	if t.cfg.HostNetworkConfig.Enabled {
		return corev1.ServiceTypeClusterIP
	}
	if params == nil {
		return corev1.ServiceTypeLoadBalancer
	}
	return corev1.ServiceType(params.Type)
}

// toExternalTrafficPolicy returns the ExternalTrafficPolicy from the given Service object.
// If hostNetwork is enabled, no external traffic policy is return.
// The default value is the one from the configuration flag.
func (t *gatewayAPITranslator) toExternalTrafficPolicy(params *model.Service) corev1.ServiceExternalTrafficPolicy {
	if t.cfg.HostNetworkConfig.Enabled {
		return corev1.ServiceExternalTrafficPolicy("")
	}

	if params == nil || len(params.ExternalTrafficPolicy) == 0 {
		return corev1.ServiceExternalTrafficPolicy(t.cfg.ServiceConfig.ExternalTrafficPolicy)
	}

	return corev1.ServiceExternalTrafficPolicy(params.ExternalTrafficPolicy)
}

// toLoadBalancerClass returns the LoadBalancerClass from the given Service object.
// Applicable for LoadBalancer type services only.
func (t *gatewayAPITranslator) toLoadBalancerClass(params *model.Service) *string {
	if params == nil || params.LoadBalancerClass == nil {
		return nil
	}
	if t.toServiceType(params) != corev1.ServiceTypeLoadBalancer {
		return nil
	}
	return params.LoadBalancerClass
}

// toLoadBalancerSourceRanges returns the LoadBalancerSourceRanges from the given Service object.
// Applicable for LoadBalancer type services only.
func (t *gatewayAPITranslator) toLoadBalancerSourceRanges(params *model.Service) []string {
	if params == nil || params.LoadBalancerSourceRanges == nil {
		return nil
	}

	// Only return the source ranges if the service type is LoadBalancer
	if t.toServiceType(params) != corev1.ServiceTypeLoadBalancer {
		return nil
	}

	return params.LoadBalancerSourceRanges
}

// toIPFamilies returns the IPFamilies from the given Service object.
// The default value is the one from the configuration flags (e.g. IPv4 and IPv6 enabled).
func (t *gatewayAPITranslator) toIPFamilies(params *model.Service) []corev1.IPFamily {
	if params == nil || params.IPFamilies == nil {
		if t.cfg.IPConfig.IPv4Enabled && t.cfg.IPConfig.IPv6Enabled {
			return []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol}
		}

		if t.cfg.IPConfig.IPv4Enabled {
			return []corev1.IPFamily{corev1.IPv4Protocol}
		}

		if t.cfg.IPConfig.IPv6Enabled {
			return []corev1.IPFamily{corev1.IPv6Protocol}
		}
		return nil
	}

	var families []corev1.IPFamily
	for _, f := range params.IPFamilies {
		families = append(families, corev1.IPFamily(f))
	}

	return families
}

// toIPFamilyPolicy returns the IPFamilyPolicy from the given Service object.
func (t *gatewayAPITranslator) toIPFamilyPolicy(params *model.Service) *corev1.IPFamilyPolicy {
	if params == nil || params.IPFamilyPolicy == nil {
		if t.cfg.IPConfig.IPv4Enabled && t.cfg.IPConfig.IPv6Enabled {
			return ptr.To(corev1.IPFamilyPolicyPreferDualStack)
		}
		return nil
	}
	return ptr.To(corev1.IPFamilyPolicy(*params.IPFamilyPolicy))
}

// toAllocateLoadBalancerNodePorts returns the AllocateLoadBalancerNodePorts from the given Service object.
// Applicable for LoadBalancer type services only.
func (t *gatewayAPITranslator) toAllocateLoadBalancerNodePorts(params *model.Service) *bool {
	if params == nil || params.AllocateLoadBalancerNodePorts == nil {
		return nil
	}
	if t.toServiceType(params) != corev1.ServiceTypeLoadBalancer {
		return nil
	}
	return params.AllocateLoadBalancerNodePorts
}

// toTrafficDistribution returns the TrafficDistribution from the given Service object.
func (t *gatewayAPITranslator) toTrafficDistribution(params *model.Service) *string {
	if params == nil || params.TrafficDistribution == nil {
		return nil
	}
	return params.TrafficDistribution
}

func (t *gatewayAPITranslator) desiredEndpoints(owner *model.FullyQualifiedResource, labels, annotations map[string]string) *corev1.Endpoints {
	if owner == nil {
		return nil
	}
	shortedName := shortener.ShortenK8sResourceName(owner.Name)

	return &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name:      shortener.ShortenK8sResourceName(ciliumGatewayPrefix + owner.Name),
			Namespace: owner.Namespace,
			Labels: mergeMap(map[string]string{
				owningGatewayLabel: shortedName,
				gatewayNameLabel:   shortedName,
			}, labels),
			Annotations: annotations,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: gatewayv1beta1.GroupVersion.String(),
					Kind:       owner.Kind,
					Name:       owner.Name,
					UID:        types.UID(owner.UID),
					Controller: ptr.To(true),
				},
			},
		},
		Subsets: []corev1.EndpointSubset{
			{
				// This dummy endpoint is required as agent refuses to push service entry
				// to the lb map when the service has no backends.
				// Related github issue https://github.com/cilium/cilium/issues/19262
				Addresses: []corev1.EndpointAddress{{IP: "192.192.192.192"}}, // dummy
				Ports:     []corev1.EndpointPort{{Port: 9999}},               // dummy
			},
		},
	}
}

func (t *gatewayAPITranslator) toServiceAnnotations(annotations map[string]string, params *model.Service) map[string]string {
	if params == nil {
		return annotations
	}
	if annotations == nil {
		annotations = make(map[string]string)
	}
	annotations[annotation.ServiceSourceRangesPolicy] = params.LoadBalancerSourceRangesPolicy
	return annotations
}

func decorateCEC(cec *ciliumv2.CiliumEnvoyConfig, resource *model.FullyQualifiedResource, labels, annotations map[string]string) error {
	if cec == nil || resource == nil {
		return fmt.Errorf("CEC or resource can't be nil")
	}

	// Set the owner reference to the CEC object.
	cec.OwnerReferences = []metav1.OwnerReference{
		{
			APIVersion: resource.Group + "/" + resource.Version,
			Kind:       resource.Kind,
			Name:       resource.Name,
			UID:        types.UID(resource.UID),
			Controller: ptr.To(true),
		},
	}

	if cec.Labels == nil {
		cec.Labels = make(map[string]string)
	}
	cec.Labels = mergeMap(cec.Labels, labels)
	cec.Labels[gatewayNameLabel] = shortener.ShortenK8sResourceName(resource.Name)
	cec.Annotations = mergeMap(cec.Annotations, annotations)

	return nil
}

func mergeMap(left, right map[string]string) map[string]string {
	if left == nil {
		return right
	}
	for key, value := range right {
		left[key] = value
	}
	return left
}
