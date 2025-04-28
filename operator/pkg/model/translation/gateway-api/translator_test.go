// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1"
	k8syaml "sigs.k8s.io/yaml"

	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/operator/pkg/model/translation"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func Test_translator_Translate(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		// Gateway API related tests
		{name: "basic_http_listener"},
		{name: "basic_tls_sni_listener"},
		{name: "conformance/httproute_simple_same_namespace"},
		{name: "conformance/httproute_backend_protocol_h_2_c"},
		{name: "conformance/httproute_cross_namespace"},
		{name: "conformance/httpexact_path_matching"},
		{name: "conformance/httproute_header_matching"},
		{name: "conformance/httproute_hostname_intersection"},
		{name: "conformance/httproute_listener_hostname_matching"},
		{name: "conformance/httproute_matching_across_routes"},
		{name: "conformance/httproute_matching"},
		{name: "conformance/httproute_method_matching"},
		{name: "conformance/httproute_query_param_matching"},
		{name: "conformance/httproute_request_header_modifier"},
		{name: "conformance/httproute_backend_refs_request_header_modifier"},
		{name: "conformance/httproute_request_redirect"},
		{name: "conformance/httproute_response_header_modifier"},
		{name: "conformance/httproute_backend_refs_response_header_modifier"},
		{name: "conformance/httproute_rewrite_host"},
		{name: "conformance/httproute_rewrite_path"},
		{name: "conformance/httproute_request_mirror"},
		{name: "conformance/httproute_request_redirect_with_multi_httplisteners"},

		// GAMMA related tests
		{name: "conformance/gamma/mesh_frontend"},
		{name: "conformance/gamma/mesh_ports"},
		{name: "conformance/gamma/mesh_splits"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trans := &gatewayAPITranslator{
				cecTranslator: translation.NewCECTranslator("cilium-secrets", false, false, true, 60, false, nil, true, true, 0),
			}

			input := &model.Model{}
			readInput(t, fmt.Sprintf("testdata/%s/input.yaml", tt.name), input)
			output := &ciliumv2.CiliumEnvoyConfig{}
			readOutput(t, fmt.Sprintf("testdata/%s/cec-output.yaml", tt.name), output)

			cec, _, _, err := trans.Translate(input)

			require.Equal(t, tt.wantErr, err != nil, "Error mismatch")
			diffOutput := cmp.Diff(output, cec, protocmp.Transform())
			if len(diffOutput) != 0 {
				t.Errorf("CiliumEnvoyConfigs did not match:\n%s\n", diffOutput)
			}
		})
	}
}

func Test_translator_Translate_AppProtocol(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{name: "conformance/httproute_backend_protocol_h_2_c_app_protocol"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trans := &gatewayAPITranslator{
				cecTranslator: translation.NewCECTranslator("cilium-secrets", false, true, true, 60, false, nil, true, true, 0),
			}

			input := &model.Model{}
			readInput(t, fmt.Sprintf("testdata/%s/input.yaml", tt.name), input)
			output := &ciliumv2.CiliumEnvoyConfig{}
			readOutput(t, fmt.Sprintf("testdata/%s/cec-output.yaml", tt.name), output)

			cec, _, _, err := trans.Translate(input)

			require.Equal(t, tt.wantErr, err != nil, "Error mismatch")
			diffOutput := cmp.Diff(output, cec, protocmp.Transform())
			if len(diffOutput) != 0 {
				t.Errorf("CiliumEnvoyConfigs did not match:\n%s\n", diffOutput)
			}
		})
	}
}

func Test_translator_Translate_HostNetwork(t *testing.T) {
	tests := []struct {
		name              string
		nodeLabelSelector *slim_metav1.LabelSelector
		ipv4Enabled       bool
		ipv6Enabled       bool
		wantErr           bool
	}{
		{
			name:        "host_network/basic_http_listener",
			ipv4Enabled: true,
		},
		{
			name:        "host_network/basic_http_listener_with_different_port",
			ipv4Enabled: true,
		},
		{
			name:        "host_network/basic_http_listener_with_different_port_and_ipv_6",
			ipv4Enabled: false,
			ipv6Enabled: true,
		},
		{
			name:        "host_network/basic_http_listener_with_label_selector",
			ipv4Enabled: true,
			nodeLabelSelector: &slim_metav1.LabelSelector{
				MatchLabels: map[string]slim_metav1.MatchLabelsValue{
					"a": "b",
				},
			},
		},
	}
	for _, tt := range tests {
		translatorCases := []struct {
			name                 string
			gatewayAPITranslator *gatewayAPITranslator
		}{
			{
				name: "without_external_traffic_policy",
				gatewayAPITranslator: &gatewayAPITranslator{
					cecTranslator:      translation.NewCECTranslator("cilium-secrets", false, false, true, 60, true, tt.nodeLabelSelector, tt.ipv4Enabled, tt.ipv6Enabled, 0),
					hostNetworkEnabled: true,
				},
			},
			{
				name: "with_external_traffic_policy",
				gatewayAPITranslator: &gatewayAPITranslator{
					cecTranslator:         translation.NewCECTranslator("cilium-secrets", false, false, true, 60, true, tt.nodeLabelSelector, tt.ipv4Enabled, tt.ipv6Enabled, 0),
					hostNetworkEnabled:    true,
					externalTrafficPolicy: "Cluster",
				},
			},
		}

		t.Run(tt.name, func(t *testing.T) {
			for _, translatorCase := range translatorCases {
				t.Run(translatorCase.name, func(t *testing.T) {
					input := &model.Model{}
					readInput(t, fmt.Sprintf("testdata/%s/%s/input.yaml", tt.name, translatorCase.name), input)
					output := &ciliumv2.CiliumEnvoyConfig{}
					readOutput(t, fmt.Sprintf("testdata/%s/%s/cec-output.yaml", tt.name, translatorCase.name), output)

					cec, svc, ep, err := translatorCase.gatewayAPITranslator.Translate(input)

					require.Equal(t, tt.wantErr, err != nil, "Error mismatch")

					diffOutput := cmp.Diff(output, cec, protocmp.Transform())
					if len(diffOutput) != 0 {
						t.Errorf("CiliumEnvoyConfigs did not match:\n%s\n", diffOutput)
					}

					require.NotNil(t, svc)
					assert.Equal(t, corev1.ServiceTypeClusterIP, svc.Spec.Type)
					require.Emptyf(t, svc.Spec.ExternalTrafficPolicy, "ClusterIP Services must not have an ExternalTrafficPolicy")

					require.NotNil(t, ep)
				})
			}
		})
	}
}

func Test_translator_Translate_WithXffNumTrustedHops(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{name: "basic_http_listener_with_xff_num_trusted_hops"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trans := &gatewayAPITranslator{
				cecTranslator:      translation.NewCECTranslator("cilium-secrets", false, false, true, 60, false, nil, true, true, 2),
				hostNetworkEnabled: true,
			}

			input := &model.Model{}
			readInput(t, fmt.Sprintf("testdata/%s/input.yaml", tt.name), input)
			output := &ciliumv2.CiliumEnvoyConfig{}
			readOutput(t, fmt.Sprintf("testdata/%s/cec-output.yaml", tt.name), output)

			cec, svc, ep, err := trans.Translate(input)
			require.Equal(t, tt.wantErr, err != nil, "Error mismatch")

			diffOutput := cmp.Diff(output, cec, protocmp.Transform())
			if len(diffOutput) != 0 {
				t.Errorf("CiliumEnvoyConfigs did not match:\n%s\n", diffOutput)
			}

			require.NotNil(t, svc)
			assert.Equal(t, corev1.ServiceTypeClusterIP, svc.Spec.Type)

			require.NotNil(t, ep)
		})
	}
}

func Test_getService(t *testing.T) {
	type args struct {
		resource              *model.FullyQualifiedResource
		allPorts              []uint32
		labels                map[string]string
		annotations           map[string]string
		externalTrafficPolicy string
	}
	tests := []struct {
		name string
		args args
		want *corev1.Service
	}{
		{
			name: "long name - more than 64 characters",
			args: args{
				resource: &model.FullyQualifiedResource{
					Name:      "test-long-long-long-long-long-long-long-long-long-long-long-long-name",
					Namespace: "default",
					Version:   "v1",
					Kind:      "Gateway",
					UID:       "57889650-380b-4c05-9a2e-3baee7fd5271",
				},
				allPorts:              []uint32{80},
				externalTrafficPolicy: "Cluster",
			},
			want: &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cilium-gateway-test-long-long-long-long-long-long-lo-8tfth549c6",
					Namespace: "default",
					Labels: map[string]string{
						owningGatewayLabel:                       "test-long-long-long-long-long-long-long-long-long-lo-4bftbgh5ht",
						"gateway.networking.k8s.io/gateway-name": "test-long-long-long-long-long-long-long-long-long-lo-4bftbgh5ht",
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: gatewayv1beta1.GroupVersion.String(),
							Kind:       "Gateway",
							Name:       "test-long-long-long-long-long-long-long-long-long-long-long-long-name",
							UID:        types.UID("57889650-380b-4c05-9a2e-3baee7fd5271"),
							Controller: ptr.To(true),
						},
					},
				},
				Spec: corev1.ServiceSpec{
					Ports: []corev1.ServicePort{
						{
							Name:     fmt.Sprintf("port-%d", 80),
							Port:     80,
							Protocol: corev1.ProtocolTCP,
						},
					},
					Type:                  corev1.ServiceTypeLoadBalancer,
					ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyCluster,
				},
			},
		},
		{
			name: "externaltrafficpolicy set to local",
			args: args{
				resource: &model.FullyQualifiedResource{
					Name:      "test-externaltrafficpolicy-local",
					Namespace: "default",
					Version:   "v1",
					Kind:      "Gateway",
					UID:       "41b82697-2d8d-4776-81b6-44d0bbac7faa",
				},
				allPorts:              []uint32{80},
				externalTrafficPolicy: "Local",
			},
			want: &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cilium-gateway-test-externaltrafficpolicy-local",
					Namespace: "default",
					Labels: map[string]string{
						owningGatewayLabel:                       "test-externaltrafficpolicy-local",
						"gateway.networking.k8s.io/gateway-name": "test-externaltrafficpolicy-local",
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: gatewayv1beta1.GroupVersion.String(),
							Kind:       "Gateway",
							Name:       "test-externaltrafficpolicy-local",
							UID:        types.UID("41b82697-2d8d-4776-81b6-44d0bbac7faa"),
							Controller: ptr.To(true),
						},
					},
				},
				Spec: corev1.ServiceSpec{
					Ports: []corev1.ServicePort{
						{
							Name:     fmt.Sprintf("port-%d", 80),
							Port:     80,
							Protocol: corev1.ProtocolTCP,
						},
					},
					Type:                  corev1.ServiceTypeLoadBalancer,
					ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyLocal,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getService(tt.args.resource, tt.args.allPorts, tt.args.labels, tt.args.annotations, tt.args.externalTrafficPolicy)
			assert.Equalf(t, tt.want, got, "getService(%v, %v, %v, %v)", tt.args.resource, tt.args.allPorts, tt.args.labels, tt.args.annotations)
			assert.LessOrEqual(t, len(got.Name), 63, "Service name is too long")
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
