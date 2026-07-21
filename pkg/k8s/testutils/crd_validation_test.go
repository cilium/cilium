// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testutils

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
)

func TestValidateCRD(t *testing.T) {
	tests := []struct {
		name          string
		object        string
		wantSupported bool
		wantErr       bool
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
			wantSupported: true,
			wantErr:       false,
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
			wantSupported: true,
			wantErr:       true,
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
			wantSupported: true,
			wantErr:       true,
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
			wantSupported: true,
			wantErr:       true,
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
			wantSupported: true,
			wantErr:       false,
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
			wantSupported: true,
			wantErr:       true,
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
			wantSupported: true,
			wantErr:       true,
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
			wantSupported: false,
			wantErr:       false,
		},
		{
			name: "non-Cilium object is skipped",
			object: `apiVersion: v1
kind: ConfigMap
metadata:
  name: cm
  namespace: default
data:
  foo: bar
`,
			wantSupported: false,
			wantErr:       false,
		},
		{
			name:          "malformed YAML is rejected",
			object:        "this: is: not: valid: yaml:\n\t- ][",
			wantSupported: false,
			wantErr:       true,
		},
	}

	log := hivetest.Logger(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			supported, err := ValidateCRD(log, []byte(tt.object))
			require.Equal(t, tt.wantSupported, supported)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
