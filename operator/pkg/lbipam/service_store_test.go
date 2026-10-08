// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbipam

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

func TestIsCompatibleReasons(t *testing.T) {
	selectorA := map[string]string{"app": "a"}
	selectorB := map[string]string{"app": "b"}

	local := slim_core_v1.ServiceExternalTrafficPolicyLocal
	cluster := slim_core_v1.ServiceExternalTrafficPolicyCluster

	tests := []struct {
		name           string
		sv             ServiceView
		osv            ServiceView
		wantCompatible bool
		wantReason     string
	}{
		{
			name:       "different sharing keys",
			sv:         ServiceView{SharingKey: "key-a"},
			osv:        ServiceView{SharingKey: "key-b"},
			wantReason: "different sharing key",
		},
		{
			name:       "namespaces differ without mutual permission",
			sv:         ServiceView{Namespace: "ns-a"},
			osv:        ServiceView{Namespace: "ns-b", SharingCrossNamespace: []string{"ns-a"}},
			wantReason: "different and not permitted namespace",
		},
		{
			name: "same port and protocol",
			sv: ServiceView{
				Ports: []slim_core_v1.ServicePort{{Port: 80, Protocol: slim_core_v1.ProtocolTCP}},
			},
			osv: ServiceView{
				Ports: []slim_core_v1.ServicePort{{Port: 80, Protocol: slim_core_v1.ProtocolTCP}},
			},
			wantReason: "same port and protocol",
		},
		{
			name:       "different external traffic policies",
			sv:         ServiceView{ExternalTrafficPolicy: local},
			osv:        ServiceView{ExternalTrafficPolicy: cluster},
			wantReason: "different ExternalTrafficPolicy",
		},
		// The next two reasons must stay distinct. They were a single string, which left a user
		// unable to tell a rejection they can lift with an annotation from one they cannot.
		{
			name: "local policy and one service has no selector",
			sv: ServiceView{
				ExternalTrafficPolicy:      local,
				Selector:                   selectorA,
				SharingPermitDifferentPods: true,
			},
			osv: ServiceView{
				ExternalTrafficPolicy:      local,
				SharingPermitDifferentPods: true,
			},
			wantReason: "ExternalTrafficPolicy local but a service has no selector",
		},
		{
			name: "local policy and selectors differ without the opt-in",
			sv:   ServiceView{ExternalTrafficPolicy: local, Selector: selectorA},
			osv:  ServiceView{ExternalTrafficPolicy: local, Selector: selectorB},
			wantReason: "ExternalTrafficPolicy local but selecting different set of pods " +
				"without lbipam.cilium.io/sharing-permit-different-pods on both services",
		},
		{
			name: "local policy and selectors differ with the opt-in on one side only",
			sv: ServiceView{
				ExternalTrafficPolicy:      local,
				Selector:                   selectorA,
				SharingPermitDifferentPods: true,
			},
			osv: ServiceView{ExternalTrafficPolicy: local, Selector: selectorB},
			wantReason: "ExternalTrafficPolicy local but selecting different set of pods " +
				"without lbipam.cilium.io/sharing-permit-different-pods on both services",
		},
		{
			name: "local policy and selectors differ with the opt-in on both",
			sv: ServiceView{
				ExternalTrafficPolicy:      local,
				Selector:                   selectorA,
				SharingPermitDifferentPods: true,
			},
			osv: ServiceView{
				ExternalTrafficPolicy:      local,
				Selector:                   selectorB,
				SharingPermitDifferentPods: true,
			},
			wantCompatible: true,
		},
		{
			name:           "identical services",
			sv:             ServiceView{ExternalTrafficPolicy: local, Selector: selectorA},
			osv:            ServiceView{ExternalTrafficPolicy: local, Selector: selectorA},
			wantCompatible: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			compatible, reason := tc.sv.isCompatible(&tc.osv)
			require.Equal(t, tc.wantCompatible, compatible)
			assert.Equal(t, tc.wantReason, reason)
		})
	}
}
