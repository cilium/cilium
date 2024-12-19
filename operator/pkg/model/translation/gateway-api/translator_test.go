// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	k8syaml "sigs.k8s.io/yaml"

	"github.com/cilium/cilium/operator/pkg/model"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func Test_translator_Translate(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trans := &translator{
				idleTimeoutSeconds: 60,
				secretsNamespace:   "cilium-secrets",
			}

			input := &model.Model{}
			readInput(t, fmt.Sprintf("testdata/%s/input.yaml", tt.name), input)

			cec, _, _, err := trans.Translate(input)

			output := &ciliumv2.CiliumEnvoyConfig{}
			readOutput(t, fmt.Sprintf("testdata/%s/cec-output.yaml", tt.name), output)

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
			trans := &translator{
				idleTimeoutSeconds: 60,
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
