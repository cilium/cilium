// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"crypto/sha256"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/operator/pkg/model/translation"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

var _ translation.Translator = (*translator)(nil)

const (
	ciliumGatewayPrefix = "cilium-gateway-"
	owningGatewayLabel  = "io.cilium.gateway/owning-gateway"
)

type translator struct {
	secretsNamespace string

	idleTimeoutSeconds int
}

// NewTranslator returns a new translator for Gateway API.
func NewTranslator(secretsNamespace string, idleTimeoutSeconds int) translation.Translator {
	return &translator{
		secretsNamespace:   secretsNamespace,
		idleTimeoutSeconds: idleTimeoutSeconds,
	}
}

func (t *translator) Translate(m *model.Model) (*ciliumv2.CiliumEnvoyConfig, *corev1.Service, *corev1.Endpoints, error) {
	listeners := m.GetListeners()
	if len(listeners) == 0 || len(listeners[0].GetSources()) == 0 {
		return nil, nil, nil, fmt.Errorf("model source can't be empty")
	}

	var source *model.FullyQualifiedResource
	var ports []uint32
	for _, l := range listeners {
		source = &l.GetSources()[0]

		ports = append(ports, l.GetPort())
	}

	if source == nil || source.Name == "" {
		return nil, nil, nil, fmt.Errorf("model source name can't be empty")
	}

	trans := translation.NewTranslator(ciliumGatewayPrefix+source.Name, source.Namespace, t.secretsNamespace, false, false, true, t.idleTimeoutSeconds)
	cec, _, _, err := trans.Translate(m)
	if err != nil {
		return nil, nil, nil, err
	}

	// Set the owner reference to the CEC object.
	cec.OwnerReferences = []metav1.OwnerReference{
		{
			APIVersion: gatewayv1beta1.GroupVersion.String(),
			Kind:       source.Kind,
			Name:       source.Name,
			UID:        types.UID(source.UID),
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
	return cec, getService(source, ports, allLabels, allAnnotations), getEndpoints(*source), err
}

func getService(resource *model.FullyQualifiedResource, allPorts []uint32, labels, annotations map[string]string) *corev1.Service {
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
			Name:        shorten(ciliumGatewayPrefix + resource.Name),
			Namespace:   resource.Namespace,
			Labels:      mergeMap(map[string]string{owningGatewayLabel: resource.Name}, labels),
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
			Type:  corev1.ServiceTypeLoadBalancer,
			Ports: ports,
		},
	}
}

func getEndpoints(resource model.FullyQualifiedResource) *corev1.Endpoints {
	return &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name:      shorten(ciliumGatewayPrefix + resource.Name),
			Namespace: resource.Namespace,
			Labels:    map[string]string{owningGatewayLabel: resource.Name},
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

// shorten shortens the string to 63 characters.
// this is the implicit required for all the resource naming in k8s.
func shorten(s string) string {
	if len(s) > 63 {
		return s[:52] + "-" + encodeHash(hash(s))
	}
	return s
}

// encodeHash encodes the first 10 characters of the hex string.
// https://github.com/kubernetes/kubernetes/blob/f0dcf0614036d8c3cd1c9f3b3cf8df4bb1d8e44e/staging/src/k8s.io/kubectl/pkg/util/hash/hash.go#L105
func encodeHash(hex string) string {
	enc := []rune(hex[:10])
	for i := range enc {
		switch enc[i] {
		case '0':
			enc[i] = 'g'
		case '1':
			enc[i] = 'h'
		case '3':
			enc[i] = 'k'
		case 'a':
			enc[i] = 'm'
		case 'e':
			enc[i] = 't'
		}
	}
	return string(enc)
}

// hash hashes `data` with sha256 and returns the hex string
func hash(data string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(data)))
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
