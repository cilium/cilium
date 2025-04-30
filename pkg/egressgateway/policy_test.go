// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

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
		nodeSelectors     []api.EndpointSelector
		dstCIDRs          []netip.Prefix
		excludedCIDRs     []netip.Prefix
		policyGwConfigs   []policyGatewayConfig
		matchedEndpoints  map[endpointID]*endpointMetadata
		gatewayConfigs    []gatewayConfig
	}
	type args struct {
		epDataStore           map[endpointID]*endpointMetadata
		nodesAddresses2Labels map[string]map[string]string
	}
	tests := []struct {
		name           string
		fields         fields
		args           args
		want           int
		wantEndpointID endpointID
	}{
		{
			name: "Test updateMatchedEndpointIDs with endpoints and nodes",
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
				nodeSelectors: []api.EndpointSelector{
					{
						LabelSelector: &slimv1.LabelSelector{
							MatchLabels: map[string]string{
								"node-name": "node1",
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
						nodeIP: "192.168.1.10",
					},
				},
				nodesAddresses2Labels: map[string]map[string]string{
					"192.168.1.10": {
						"node-name": "node1",
					},
				},
			},
			want:           1,
			wantEndpointID: endpointID("123456"),
		},
		{
			name: "Test updateMatchedEndpointIDs endpoints and nodes with no match",
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
				nodeSelectors: []api.EndpointSelector{
					{
						LabelSelector: &slimv1.LabelSelector{
							MatchLabels: map[string]string{
								"node-name": "node1",
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
						nodeIP: "192.168.1.10",
					},
				},
				nodesAddresses2Labels: map[string]map[string]string{
					"192.168.1.11": {
						"node-name": "node1",
					},
				},
			},
			want:           0,
			wantEndpointID: "",
		},
		{
			name: "Test updateMatchedEndpointIDs endpoints and nodes with no match label",
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
				nodeSelectors: []api.EndpointSelector{
					{
						LabelSelector: &slimv1.LabelSelector{
							MatchLabels: map[string]string{
								"node-name": "node1",
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
						nodeIP: "192.168.1.10",
					},
				},
				nodesAddresses2Labels: map[string]map[string]string{
					"192.168.1.10": {
						"bar": "bar",
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
				id:                tt.fields.id,
				endpointSelectors: tt.fields.endpointSelectors,
				nodeSelectors:     tt.fields.nodeSelectors,
				dstCIDRs:          tt.fields.dstCIDRs,
				excludedCIDRs:     tt.fields.excludedCIDRs,
				policyGwConfigs:   tt.fields.policyGwConfigs,
				matchedEndpoints:  tt.fields.matchedEndpoints,
				gatewayConfigs:    tt.fields.gatewayConfigs,
			}
			config.updateMatchedEndpointIDs(tt.args.epDataStore, tt.args.nodesAddresses2Labels)
			assert.Len(t, config.matchedEndpoints, tt.want)
			if tt.want > 0 {
				assert.Contains(t, config.matchedEndpoints, endpointID(tt.wantEndpointID))
			}
		})
	}
}
