// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// This file was not reviewed by a human before submission

package client

import (
	"encoding/json"
	"testing"

	"cel.dev/cel-go/cel"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
)

func TestBGPAutoDiscoveryValidation(t *testing.T) {
	tests := []struct {
		name   string
		config string
		valid  bool
	}{
		{"explicit interface", `{"mode":"Unnumbered","unnumbered":{"interface":"eth0"}}`, true},
		{"IPv4 default route", `{"mode":"Unnumbered","defaultGateway":{"addressFamily":"ipv4"}}`, true},
		{"IPv6 default route", `{"mode":"Unnumbered","defaultGateway":{"addressFamily":"ipv6"}}`, true},
		{"default gateway", `{"mode":"DefaultGateway","defaultGateway":{"addressFamily":"ipv4"}}`, true},
		{"missing configuration", `{"mode":"Unnumbered"}`, false},
		{"both configurations", `{"mode":"Unnumbered","unnumbered":{"interface":"eth0"},"defaultGateway":{"addressFamily":"ipv4"}}`, false},
		{"default gateway with interface", `{"mode":"DefaultGateway","unnumbered":{"interface":"eth0"}}`, false},
		{"missing address family", `{"mode":"Unnumbered","defaultGateway":{}}`, false},
		{"invalid address family", `{"mode":"Unnumbered","defaultGateway":{"addressFamily":"ipv5"}}`, false},
		{"empty interface", `{"mode":"Unnumbered","unnumbered":{"interface":""}}`, false},
	}

	for _, name := range []string{BGPClusterConfigCRDName, BGPNodeConfigCRDName} {
		t.Run(name, func(t *testing.T) {
			crd := GetPregeneratedCRD(hivetest.Logger(t), name)
			root := crd.Spec.Versions[0].Schema.OpenAPIV3Schema
			discovery := root.Properties["spec"].Properties["bgpInstances"].Items.Schema.Properties["peers"].Items.Schema.Properties["autoDiscovery"]
			var schema apiextensions.JSONSchemaProps
			require.NoError(t, apiextensionsv1.Convert_v1_JSONSchemaProps_To_apiextensions_JSONSchemaProps(&discovery, &schema, nil))
			validator, _, err := validation.NewSchemaValidator(&schema)
			require.NoError(t, err)

			// These rules use ordinary CEL field access and has(). Evaluate the
			// generated rules as well as OpenAPI's oneOf and field constraints.
			env, err := cel.NewEnv(cel.Variable("self", cel.DynType))
			require.NoError(t, err)
			var rules []cel.Program
			for _, rule := range discovery.XValidations {
				ast, issues := env.Compile(rule.Rule)
				require.NoError(t, issues.Err())
				program, err := env.Program(ast)
				require.NoError(t, err)
				rules = append(rules, program)
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					var object map[string]any
					require.NoError(t, json.Unmarshal([]byte(tt.config), &object))
					valid := len(validation.ValidateCustomResource(nil, object, validator)) == 0
					for _, rule := range rules {
						result, _, err := rule.Eval(map[string]any{"self": object})
						require.NoError(t, err)
						valid = valid && result.Value() == true
					}
					require.Equal(t, tt.valid, valid)
				})
			}
		})
	}
}
