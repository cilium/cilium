// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"net"
	"net/netip"
	"testing"

	"k8s.io/apimachinery/pkg/types"

	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/policy/api"
)

func TestPolicyConfig_updateMatchedEndpointIDs(t *testing.T) {
	type fields struct {
		id                types.NamespacedName
		endpointSelectors []api.EndpointSelector
		nodeSelectors     []api.EndpointSelector
		dstCIDRs          []netip.Prefix
		excludedCIDRs     []netip.Prefix
		policyGwConfig    *policyGatewayConfig
		matchedEndpoints  map[endpointID]*endpointMetadata
		gatewayConfig     gatewayConfig
	}
	type args struct {
		epDataStore map[endpointID]*endpointMetadata
		nodes       []nodeTypes.Node
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
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
						labels: map[string]string{
							"app": "test",
						},
						nodeIP: "192.168.1.10",
					},
				},
				nodes: []nodeTypes.Node{
					{
						Labels: map[string]string{
							"node-name": "node1",
						},
						IPAddresses: []nodeTypes.Address{
							{
								Type: addressing.NodeInternalIP,
								IP:   net.IPv4(192, 168, 1, 10),
							},
						},
					},
				},
			},
			want: 1,
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
						labels: map[string]string{
							"app": "test",
						},
						nodeIP: "192.168.1.11",
					},
				},
				nodes: []nodeTypes.Node{
					{
						Labels: map[string]string{
							"node-name": "node1",
						},
						IPAddresses: []nodeTypes.Address{
							{
								Type: addressing.NodeInternalIP,
								IP:   net.IPv4(192, 168, 1, 10),
							},
						},
					},
				},
			},
			want: 0,
		},
		{
			name: "Test updateMatchedEndpointIDs endpoints without nodeIP",
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
						labels: map[string]string{
							"app": "test",
						},
					},
				},
				nodes: []nodeTypes.Node{
					{
						Labels: map[string]string{
							"node-name": "node1",
						},
						IPAddresses: []nodeTypes.Address{
							{
								Type: addressing.NodeInternalIP,
								IP:   net.IPv4(192, 168, 1, 10),
							},
						},
					},
				},
			},
			want: 0,
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
				policyGwConfig:    tt.fields.policyGwConfig,
				matchedEndpoints:  tt.fields.matchedEndpoints,
				gatewayConfig:     tt.fields.gatewayConfig,
			}
			config.updateMatchedEndpointIDs(tt.args.epDataStore, tt.args.nodes)
			if len(config.matchedEndpoints) == tt.want {
				t.Logf("Test %s passed", tt.name)
			} else {
				t.Errorf("Test %s failed, got %d, want %d", tt.name, len(config.matchedEndpoints), tt.want)
			}
		})
	}
}
