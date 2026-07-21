// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testutils

import (
	"log/slog"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestValidateCRD(t *testing.T) {
	tests := []struct {
		name    string
		object  string
		wantErr bool
		// wantErrNoSchema is the expectation with schema validation off.
		wantErrNoSchema bool
	}{
		{
			name: "valid CNP",
			object: `apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: valid-cnp
  namespace: default
spec:
  endpointSelector:
    matchLabels:
      app: foo
  egress:
  - toEndpoints:
    - matchLabels:
        app: bar
`,
			wantErr: false,
		},
		{
			name: "CNP with unknown field is rejected",
			object: `apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: bogus-field
  namespace: default
spec:
  endpointSelector:
    matchLabels:
      app: foo
  totallyBogusUnknownField: true
`,
			wantErr:         true,
			wantErrNoSchema: true,
		},
		{
			name: "CNP with misspelled selector is rejected",
			object: `apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: typo
  namespace: default
spec:
  endpointSelectr:
    matchLabels:
      app: foo
`,
			wantErr:         true,
			wantErrNoSchema: true,
		},
		{
			name: "CNP with bad L4 protocol enum is rejected",
			object: `apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: bad-proto
  namespace: default
spec:
  endpointSelector: {}
  egress:
  - toPorts:
    - ports:
      - port: "80"
        protocol: NOTAPROTOCOL
`,
			wantErr: true,
		},
		{
			name: "validation is generic: valid CiliumEnvoyConfig",
			object: `apiVersion: cilium.io/v2
kind: CiliumEnvoyConfig
metadata:
  name: cec
  namespace: default
spec:
  services:
  - name: foo
  resources:
  - "@type": type.googleapis.com/envoy.config.listener.v3.Listener
    name: listener
`,
			wantErr: false,
		},
		{
			name: "validation is generic: CiliumEnvoyConfig with unknown field is rejected",
			object: `apiVersion: cilium.io/v2
kind: CiliumEnvoyConfig
metadata:
  name: cec
  namespace: default
spec:
  bogusUnknownFieldHere: true
  services:
  - name: foo
  resources:
  - "@type": type.googleapis.com/envoy.config.listener.v3.Listener
    name: listener
`,
			wantErr:         true,
			wantErrNoSchema: true,
		},
		{
			name: "validation is generic: CiliumEnvoyConfig missing required resources is rejected",
			object: `apiVersion: cilium.io/v2
kind: CiliumEnvoyConfig
metadata:
  name: cec
  namespace: default
spec:
  services:
  - name: foo
`,
			wantErr: true,
		},
		{
			name: "core kind without a CRD schema is skipped",
			object: `apiVersion: v1
kind: Service
metadata:
  name: echo
  namespace: test
spec:
  clusterIP: 10.96.50.104
`,
			wantErr: false,
		},
		{
			name:            "malformed YAML is rejected",
			object:          "this: is: not: valid: yaml:\n\t- ][",
			wantErr:         true,
			wantErrNoSchema: true,
		},
	}

	log := hivetest.Logger(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, schemaValidation := range []bool{true, false} {
				err := ValidateCRD(log, []byte(tt.object), schemaValidation)
				wantErr := tt.wantErr
				if !schemaValidation {
					wantErr = tt.wantErrNoSchema
				}
				if wantErr {
					require.Error(t, err, "schemaValidation=%v", schemaValidation)
				} else {
					require.NoError(t, err, "schemaValidation=%v", schemaValidation)
				}
			}
		})
	}
}

func init() {
	RegisterCRDSchemas(func(*slog.Logger) []apiextensionsv1.CustomResourceDefinition {
		return []apiextensionsv1.CustomResourceDefinition{testCRD}
	})
}

var testCRD = apiextensionsv1.CustomResourceDefinition{
	Spec: apiextensionsv1.CustomResourceDefinitionSpec{
		Group: "example.com",
		Names: apiextensionsv1.CustomResourceDefinitionNames{Kind: "Example"},
		Versions: []apiextensionsv1.CustomResourceDefinitionVersion{
			{
				Name: "v1",
				Schema: &apiextensionsv1.CustomResourceValidation{
					OpenAPIV3Schema: &apiextensionsv1.JSONSchemaProps{Type: "object"},
				},
			},
		},
	},
}

func TestRegisterCRDSchemas(t *testing.T) {
	validators := getCRDSchemaValidators(hivetest.Logger(t))

	// The registered CRDs are validated alongside the pregenerated ones.
	require.Contains(t, validators, schema.GroupVersionKind{
		Group: "example.com", Version: "v1", Kind: "Example",
	})
	require.Contains(t, validators, schema.GroupVersionKind{
		Group: "cilium.io", Version: "v2", Kind: "CiliumNetworkPolicy",
	})
}
