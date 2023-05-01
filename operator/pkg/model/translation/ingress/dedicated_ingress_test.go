// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingress

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/operator/pkg/model"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func Test_getService(t *testing.T) {
	resource := model.FullyQualifiedResource{
		Name:      "dummy-ingress",
		Namespace: "dummy-namespace",
		Version:   "v1",
		Kind:      "Ingress",
		UID:       "d4bd3dc3-2ac5-4ab4-9dca-89c62c60177e",
	}

	t.Run("Default LB service", func(t *testing.T) {
		res := getService(resource, nil)
		require.Equal(t, &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "cilium-ingress-dummy-ingress",
				Namespace: "dummy-namespace",
				Labels:    map[string]string{"cilium.io/ingress": "true"},
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion: "networking.k8s.io/v1",
						Kind:       "Ingress",
						Name:       "dummy-ingress",
						UID:        "d4bd3dc3-2ac5-4ab4-9dca-89c62c60177e",
					},
				},
			},
			Spec: corev1.ServiceSpec{
				Type: corev1.ServiceTypeLoadBalancer,
				Ports: []corev1.ServicePort{
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
				},
			},
		}, res)
	})

	t.Run("Invalid LB service annotation, defaults to LoadBalancer", func(t *testing.T) {
		res := getService(resource, &model.Service{
			Type: "InvalidServiceType",
		})
		require.Equal(t, &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "cilium-ingress-dummy-ingress",
				Namespace: "dummy-namespace",
				Labels:    map[string]string{"cilium.io/ingress": "true"},
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion: "networking.k8s.io/v1",
						Kind:       "Ingress",
						Name:       "dummy-ingress",
						UID:        "d4bd3dc3-2ac5-4ab4-9dca-89c62c60177e",
					},
				},
			},
			Spec: corev1.ServiceSpec{
				Type: corev1.ServiceTypeLoadBalancer,
				Ports: []corev1.ServicePort{
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
				},
			},
		}, res)
	})

	t.Run("Node Port service", func(t *testing.T) {
		var insecureNodePort uint32 = 3000
		var secureNodePort uint32 = 3001
		res := getService(resource, &model.Service{
			Type:             "NodePort",
			InsecureNodePort: &insecureNodePort,
			SecureNodePort:   &secureNodePort,
		})
		require.Equal(t, &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "cilium-ingress-dummy-ingress",
				Namespace: "dummy-namespace",
				Labels:    map[string]string{"cilium.io/ingress": "true"},
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion: "networking.k8s.io/v1",
						Kind:       "Ingress",
						Name:       "dummy-ingress",
						UID:        "d4bd3dc3-2ac5-4ab4-9dca-89c62c60177e",
					},
				},
			},
			Spec: corev1.ServiceSpec{
				Type: corev1.ServiceTypeNodePort,
				Ports: []corev1.ServicePort{
					{
						Name:     "http",
						Protocol: "TCP",
						Port:     80,
						NodePort: 3000,
					},
					{
						Name:     "https",
						Protocol: "TCP",
						Port:     443,
						NodePort: 3001,
					},
				},
			},
		}, res)
	})
}

func Test_getEndpointForIngress(t *testing.T) {
	res := getEndpoints(model.FullyQualifiedResource{
		Name:      "dummy-ingress",
		Namespace: "dummy-namespace",
		Version:   "v1",
		Kind:      "Ingress",
		UID:       "d4bd3dc3-2ac5-4ab4-9dca-89c62c60177e",
	})

	require.Equal(t, &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cilium-ingress-dummy-ingress",
			Namespace: "dummy-namespace",
			Labels:    map[string]string{"cilium.io/ingress": "true"},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "networking.k8s.io/v1",
					Kind:       "Ingress",
					Name:       "dummy-ingress",
					UID:        "d4bd3dc3-2ac5-4ab4-9dca-89c62c60177e",
				},
			},
		},
		Subsets: []corev1.EndpointSubset{
			{
				Addresses: []corev1.EndpointAddress{{IP: "192.192.192.192"}},
				Ports:     []corev1.EndpointPort{{Port: 9999}},
			},
		},
	}, res)
}

func Test_translator_Translate(t *testing.T) {
	type args struct {
		m            *model.Model
		enforceHTTPs bool
	}
	tests := []struct {
		name    string
		args    args
		want    *ciliumv2.CiliumEnvoyConfig
		wantErr bool
	}{
		{
			name: "Conformance/DefaultBackend",
			args: args{
				m: &model.Model{
					HTTP: defaultBackendListeners,
				},
				enforceHTTPs: true,
			},
			want: defaultBackendListenersCiliumEnvoyConfig,
		},
		{
			name: "Conformance/HostRules",
			args: args{
				m: &model.Model{
					HTTP: hostRulesListeners,
				},
				enforceHTTPs: true,
			},
			want: hostRulesListenersCiliumEnvoyConfig,
		},
		{
			name: "Conformance/PathRules",
			args: args{
				m: &model.Model{
					HTTP: pathRulesListeners,
				},
				enforceHTTPs: true,
			},
			want: pathRulesListenersCiliumEnvoyConfig,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trans := &DedicatedIngressTranslator{
				secretsNamespace:   "cilium-secrets",
				enforceHTTPs:       tt.args.enforceHTTPs,
				idleTimeoutSeconds: 60,
			}

			cec, _, _, err := trans.Translate(tt.args.m)
			require.Equal(t, tt.wantErr, err != nil, "Error mismatch")
			require.Equal(t, tt.want, cec, "CiliumEnvoyConfig did not match")
		})
	}
}
