// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingress

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8syaml "sigs.k8s.io/yaml"

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
		res := getService(resource, nil, false)
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
						Controller: model.AddressOf(true),
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

	t.Run("Default LB service with TLS only", func(t *testing.T) {
		res := getService(resource, nil, true)
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
						Controller: model.AddressOf(true),
					},
				},
			},
			Spec: corev1.ServiceSpec{
				Type: corev1.ServiceTypeLoadBalancer,
				Ports: []corev1.ServicePort{
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
		}, false)
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
						Controller: model.AddressOf(true),
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
		}, false)
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
						Controller: model.AddressOf(true),
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
					Controller: model.AddressOf(true),
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
		enforceHTTPs     bool
		useProxyProtocol bool
	}
	tests := []struct {
		name    string
		args    args
		want    *ciliumv2.CiliumEnvoyConfig
		wantErr bool
	}{
		{
			name: "conformance/default_backend",
			args: args{
				enforceHTTPs: true,
			},
		},
		{
			name: "conformance/host_rules",
			args: args{
				enforceHTTPs: true,
			},
		},
		{
			name: "conformance/host_rules/no_force_https",
			args: args{},
		},
		{
			name: "conformance/path_rules",
			args: args{
				enforceHTTPs: true,
			},
		},
		{
			name: "conformance/proxy_protocol",
			args: args{
				useProxyProtocol: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trans := &DedicatedIngressTranslator{
				secretsNamespace:   "cilium-secrets",
				enforceHTTPs:       tt.args.enforceHTTPs,
				useProxyProtocol:   tt.args.useProxyProtocol,
				idleTimeoutSeconds: 60,
				enableIpv4:         true,
				enableIpv6:         true,
			}
			input := &model.Model{}
			readInput(t, fmt.Sprintf("testdata/%s/input.yaml", tt.name), input)

			cec, _, _, err := trans.Translate(input)
			require.Equal(t, tt.wantErr, err != nil, "Error mismatch")

			output := &ciliumv2.CiliumEnvoyConfig{}
			readOutput(t, fmt.Sprintf("testdata/%s/output-cec.yaml", tt.name), output)

			diffOutput := cmp.Diff(output, cec, protocmp.Transform())
			if len(diffOutput) != 0 {
				t.Errorf("CiliumEnvoyConfigs did not match:\n%s\n", diffOutput)
			}
		})
	}
}

func readInput(t *testing.T, file string, obj any) {
	inputYaml, err := os.ReadFile(file)
	require.NoError(t, err)

	require.NoError(t, k8syaml.Unmarshal(inputYaml, obj))
}

func readOutput(t *testing.T, file string, obj any) string {
	// unmarshal and marshal to prevent formatting diffs
	outputYaml, err := os.ReadFile(file)
	require.NoError(t, err)

	if strings.TrimSpace(string(outputYaml)) == "" {
		return strings.TrimSpace(string(outputYaml))
	}

	require.NoError(t, k8syaml.Unmarshal(outputYaml, obj))

	yamlText := toYaml(t, obj)

	return strings.TrimSpace(yamlText)
}

func toYaml(t *testing.T, obj any) string {
	yamlText, err := k8syaml.Marshal(obj)
	require.NoError(t, err)

	return strings.TrimSpace(string(yamlText))
}
