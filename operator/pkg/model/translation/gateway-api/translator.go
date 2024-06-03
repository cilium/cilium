// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/operator/pkg/model/translation"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

var _ translation.Translator = (*gatewayAPITranslator)(nil)

const (
	ciliumGatewayPrefix = "cilium-gateway-"
	owningGatewayLabel  = "io.cilium.gateway/owning-gateway"
)

type gatewayAPITranslator struct {
	cecTranslator translation.CECTranslator

	hostNetworkEnabled    bool
	externalTrafficPolicy string
}

func NewTranslator(cecTranslator translation.CECTranslator, hostNetworkEnabled bool, externalTrafficPolicy string) translation.Translator {
	return &gatewayAPITranslator{
		cecTranslator:         cecTranslator,
		hostNetworkEnabled:    hostNetworkEnabled,
		externalTrafficPolicy: externalTrafficPolicy,
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

	// Set the owner reference to the CEC object.
	cec.OwnerReferences = []metav1.OwnerReference{
		{
			APIVersion: owner.Group + "/" + owner.Version,
			Kind:       owner.Kind,
			Name:       owner.Name,
			UID:        types.UID(owner.UID),
			Controller: model.AddressOf(true),
		},
	}

	allLabels, allAnnotations := map[string]string{}, map[string]string{}
	// Merge all the labels and annotations from the listeners.
	// Normally, the labels and annotations are the same for all the listeners having same gateway.
	for _, l := range listeners {
		allAnnotations = mergeMap(allAnnotations, l.GetAnnotations())
		allLabels = mergeMap(allLabels, l.GetLabels())
	}

	lbSvc := getService(source, ports, allLabels, allAnnotations, t.externalTrafficPolicy)

	if t.hostNetworkEnabled {
		lbSvc.Spec.Type = corev1.ServiceTypeClusterIP
	}

	return cec, lbSvc, getEndpoints(*source), err
}

func getService(resource *model.FullyQualifiedResource, allPorts []uint32, labels, annotations map[string]string, externalTrafficPolicy string) *corev1.Service {
	uniquePorts := map[uint32]struct{}{}
	for _, p := range allPorts {
		uniquePorts[p] = struct{}{}
	}

	ports := make([]corev1.ServicePort, 0, len(uniquePorts))
	for p := range uniquePorts {
		ports = append(ports, corev1.ServicePort{
			Name:     fmt.Sprintf("port-%d", p),
			Port:     int32(p),
			Protocol: corev1.ProtocolTCP,
		})
	}

	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        model.Shorten(ciliumGatewayPrefix + resource.Name),
			Namespace:   resource.Namespace,
			Labels:      mergeMap(map[string]string{owningGatewayLabel: model.Shorten(resource.Name)}, labels),
			Annotations: annotations,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: gatewayv1beta1.GroupVersion.String(),
					Kind:       resource.Kind,
					Name:       resource.Name,
					UID:        types.UID(resource.UID),
					Controller: model.AddressOf(true),
				},
			},
		},
		Spec: corev1.ServiceSpec{
			Type:                  corev1.ServiceTypeLoadBalancer,
			ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicy(externalTrafficPolicy),
			Ports:                 ports,
		},
	}
}

func getEndpoints(resource model.FullyQualifiedResource) *corev1.Endpoints {
	return &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name:      model.Shorten(ciliumGatewayPrefix + resource.Name),
			Namespace: resource.Namespace,
			Labels:    map[string]string{owningGatewayLabel: model.Shorten(resource.Name)},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: gatewayv1beta1.GroupVersion.String(),
					Kind:       resource.Kind,
					Name:       resource.Name,
					UID:        types.UID(resource.UID),
					Controller: model.AddressOf(true),
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

func mergeMap(left, right map[string]string) map[string]string {
	if left == nil {
		return right
	}
	for key, value := range right {
		left[key] = value
	}
	return left
}
