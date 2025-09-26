// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vteppolicy

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/types"

	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/policy/api"
)

func TestPolicyConfig_updateMatchedEndpointIDs(t *testing.T) {
	type fields struct {
		id                types.NamespacedName
		endpointSelectors []api.EndpointSelector
		podSelectors      []api.EndpointSelector
		dstCIDRs          []netip.Prefix
		matchedEndpoints  map[endpointID]*endpointMetadata
	}
	type args struct {
		epDataStore map[endpointID]*endpointMetadata
	}
	tests := []struct {
		name           string
		fields         fields
		args           args
		want           int
		wantEndpointID endpointID
	}{
		{
			name: "Test updateMatchedEndpointIDs with endpoints",
			fields: fields{
				id: types.NamespacedName{
					Name: "test",
				},
				endpointSelectors: []api.EndpointSelector{
					{
						LabelSelector: &slimv1.LabelSelector{
							MatchLabels: map[string]string{
								"app": "test",
							},
						},
					},
				},
				podSelectors: []api.EndpointSelector{
					{
						LabelSelector: &slimv1.LabelSelector{
							MatchLabels: map[string]string{
								"app": "test",
							},
						},
					},
				},
			},
			args: args{
				epDataStore: map[endpointID]*endpointMetadata{
					"123456": {
						id: "123456",
						labels: map[string]string{
							"app": "test",
						},
					},
				},
			},
			want:           1,
			wantEndpointID: endpointID("123456"),
		},
		{
			name: "Test updateMatchedEndpointIDs endpoints with no match",
			fields: fields{
				id: types.NamespacedName{
					Name: "test",
				},
				endpointSelectors: []api.EndpointSelector{
					{
						LabelSelector: &slimv1.LabelSelector{
							MatchLabels: map[string]string{
								"app": "test",
							},
						},
					},
				},
				podSelectors: []api.EndpointSelector{
					{
						LabelSelector: &slimv1.LabelSelector{
							MatchLabels: map[string]string{
								"pod-name": "pod1",
							},
						},
					},
				},
			},
			args: args{
				epDataStore: map[endpointID]*endpointMetadata{
					"123456": {
						id: "123456",
						labels: map[string]string{
							"app": "test",
						},
					},
				},
			},
			want:           0,
			wantEndpointID: "",
		},
		{
			name: "Test updateMatchedEndpointIDs endpoints with no match label",
			fields: fields{
				id: types.NamespacedName{
					Name: "test",
				},
				endpointSelectors: []api.EndpointSelector{
					{
						LabelSelector: &slimv1.LabelSelector{
							MatchLabels: map[string]string{
								"app": "test",
							},
						},
					},
				},
				podSelectors: []api.EndpointSelector{
					{
						LabelSelector: &slimv1.LabelSelector{
							MatchLabels: map[string]string{
								"pod-name": "pod1",
							},
						},
					},
				},
			},
			args: args{
				epDataStore: map[endpointID]*endpointMetadata{
					"123456": {
						id: "123456",
						labels: map[string]string{
							"app": "test",
						},
					},
				},
			},
			want:           0,
			wantEndpointID: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &PolicyConfig{
				id:               tt.fields.id,
				podSelectors:     tt.fields.podSelectors,
				dstCIDRs:         tt.fields.dstCIDRs,
				matchedEndpoints: tt.fields.matchedEndpoints,
			}
			config.updateMatchedEndpointIDs(tt.args.epDataStore)
			assert.Len(t, config.matchedEndpoints, tt.want)
			if tt.want > 0 {
				assert.Contains(t, config.matchedEndpoints, endpointID(tt.wantEndpointID))
			}
		})
	}
}
