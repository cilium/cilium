// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"testing"

	"github.com/stretchr/testify/require"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func TestScopeServiceNamespaces(t *testing.T) {
	tests := []struct {
		name           string
		clusterwide    bool
		service        string
		backendService string
		wantService    string
		wantBackend    string
		wantCopy       bool
	}{
		{
			name:        "CEC, namespaces omitted",
			wantService: "ns",
			wantBackend: "ns",
			wantCopy:    true,
		},
		{
			name:           "CEC, other namespace given",
			service:        "other",
			backendService: "other",
			wantService:    "ns",
			wantBackend:    "other",
			wantCopy:       true,
		},
		{
			name:           "CEC, own namespace given",
			service:        "ns",
			backendService: "ns",
			wantService:    "ns",
			wantBackend:    "ns",
		},
		{
			name:        "CEC, only backend namespace omitted",
			service:     "ns",
			wantService: "ns",
			wantBackend: "ns",
			wantCopy:    true,
		},
		{
			name:        "CCEC, namespaces omitted",
			clusterwide: true,
			wantService: "default",
			wantBackend: "default",
			wantCopy:    true,
		},
		{
			name:           "CCEC, namespaces given",
			clusterwide:    true,
			service:        "other",
			backendService: "other",
			wantService:    "other",
			wantBackend:    "other",
		},
		{
			name:           "CCEC, default namespace given",
			clusterwide:    true,
			service:        "default",
			backendService: "default",
			wantService:    "default",
			wantBackend:    "default",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := &ciliumv2.CiliumEnvoyConfigSpec{
				Services:        []*ciliumv2.ServiceListener{{Name: "svc", Namespace: tt.service}},
				BackendServices: []*ciliumv2.Service{{Name: "backend", Namespace: tt.backendService}},
			}

			var got *ciliumv2.CiliumEnvoyConfigSpec
			if tt.clusterwide {
				got = scopeServiceNamespaces(spec, "default", false)
			} else {
				got = scopeServiceNamespaces(spec, "ns", true)
			}

			require.Equal(t, tt.wantService, got.Services[0].Namespace)
			require.Equal(t, tt.wantBackend, got.BackendServices[0].Namespace)
			// The spec comes from the informer cache and must not be modified,
			// and it is only copied when a namespace changes.
			require.Equal(t, tt.service, spec.Services[0].Namespace)
			require.Equal(t, tt.backendService, spec.BackendServices[0].Namespace)
			if tt.wantCopy {
				require.NotSame(t, spec, got)
			} else {
				require.Same(t, spec, got)
			}
		})
	}
}
