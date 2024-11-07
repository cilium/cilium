// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingress

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/operator/pkg/model/translation"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	ciliumIngressPrefix   = "cilium-ingress"
	ciliumIngressLabelKey = "cilium.io/ingress"
)

var _ translation.Translator = (*dedicatedIngressTranslator)(nil)

type dedicatedIngressTranslator struct {
	cecTranslator      translation.CECTranslator
	hostNetworkEnabled bool
}

func NewDedicatedIngressTranslator(cecTranslator translation.CECTranslator, hostNetworkEnabled bool) *dedicatedIngressTranslator {
	return &dedicatedIngressTranslator{
		cecTranslator:      cecTranslator,
		hostNetworkEnabled: hostNetworkEnabled,
	}
}

func (d *dedicatedIngressTranslator) Translate(m *model.Model) (*ciliumv2.CiliumEnvoyConfig, *corev1.Service, *corev1.Endpoints, error) {
	if m == nil || (len(m.HTTP) == 0 && len(m.TLSPassthrough) == 0) {
		return nil, nil, nil, fmt.Errorf("model source can't be empty")
	}

	var name string
	var namespace string
	var sourceResource model.FullyQualifiedResource
	var modelService *model.Service
	var cecName string
	var tlsOnly bool

	if len(m.HTTP) == 0 {
		name = fmt.Sprintf("%s-%s", ciliumIngressPrefix, m.TLSPassthrough[0].Sources[0].Name)
		namespace = m.TLSPassthrough[0].Sources[0].Namespace
		sourceResource = m.TLSPassthrough[0].Sources[0]
		modelService = m.TLSPassthrough[0].Service
		cecName = fmt.Sprintf("%s-%s-%s", ciliumIngressPrefix, namespace, m.TLSPassthrough[0].Sources[0].Name)
		tlsOnly = true
	} else {
		name = fmt.Sprintf("%s-%s", ciliumIngressPrefix, m.HTTP[0].Sources[0].Name)
		namespace = m.HTTP[0].Sources[0].Namespace
		sourceResource = m.HTTP[0].Sources[0]
		modelService = m.HTTP[0].Service
		cecName = fmt.Sprintf("%s-%s-%s", ciliumIngressPrefix, namespace, m.HTTP[0].Sources[0].Name)
	}

	// The logic is same as what we have with default cecTranslator, but with a different model
	// (i.e. the HTTP listeners are just belonged to one Ingress resource).
	cec, err := d.cecTranslator.Translate(namespace, name, m)
	if err != nil {
		return nil, nil, nil, err
	}

	// Set the name to avoid any breaking change during upgrade.
	cec.Name = cecName

	dedicatedService := d.getService(sourceResource, modelService, tlsOnly)

	return cec, dedicatedService, getEndpoints(sourceResource), err
}

func (d *dedicatedIngressTranslator) getService(resource model.FullyQualifiedResource, service *model.Service, tlsOnly bool) *corev1.Service {
	serviceType := corev1.ServiceTypeLoadBalancer
	clusterIP := ""
	if d.hostNetworkEnabled {
		serviceType = corev1.ServiceTypeClusterIP
	}

	var ports []corev1.ServicePort
	if tlsOnly {
		ports = []corev1.ServicePort{
			{
				Name:     "https",
				Protocol: "TCP",
				Port:     443,
			},
		}
	} else {
		ports = []corev1.ServicePort{
			{
				Name:     "http",
				Protocol: "TCP",
				Port:     80,
			},
			{
				Name:     "https",
				Protocol: "TCP",
				Port:     443,
			},
		}
	}

	if service != nil {
		switch service.Type {
		case string(corev1.ServiceTypeNodePort):
			serviceType = corev1.ServiceTypeNodePort
			if service.InsecureNodePort != nil {
				ports[0].NodePort = int32(*service.InsecureNodePort)
			}
			if service.SecureNodePort != nil {
				ports[1].NodePort = int32(*service.SecureNodePort)
			}
		case string(corev1.ServiceTypeLoadBalancer):
			// Do nothing as the port number is allocated by the cloud provider.
		default:
			log.WithField(logfields.ServiceType, service.Type).
				Warn("only LoadBalancer and NodePort are supported. Defaulting to LoadBalancer")
		}
	}

	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%s", ciliumIngressPrefix, resource.Name),
			Namespace: resource.Namespace,
			Labels:    map[string]string{ciliumIngressLabelKey: "true"},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: slim_networkingv1.SchemeGroupVersion.String(),
					Kind:       "Ingress",
					Name:       resource.Name,
					UID:        types.UID(resource.UID),
					Controller: ptr.To(true),
				},
			},
		},
		Spec: corev1.ServiceSpec{
			Type:      serviceType,
			ClusterIP: clusterIP,
			Ports:     ports,
		},
	}
}

func getEndpoints(resource model.FullyQualifiedResource) *corev1.Endpoints {
	return &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%s", ciliumIngressPrefix, resource.Name),
			Namespace: resource.Namespace,
			Labels:    map[string]string{ciliumIngressLabelKey: "true"},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: slim_networkingv1.SchemeGroupVersion.String(),
					Kind:       "Ingress",
					Name:       resource.Name,
					UID:        types.UID(resource.UID),
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
