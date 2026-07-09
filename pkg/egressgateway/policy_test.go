// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/types"

	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
)

func getAsPolicyLabelSelectors(k8sLss []*slimv1.LabelSelector) (lss []*policyTypes.LabelSelector) {
	for _, ls := range k8sLss {
		lss = append(lss, policyTypes.NewLabelSelector(api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, ls)))
	}
	return lss
}

func TestPolicyConfig_updateMatchedEndpointKeys(t *testing.T) {
	type fields struct {
		id                types.NamespacedName
		endpointSelectors []*slimv1.LabelSelector
		nodeSelectors     []*slimv1.LabelSelector
		dstCIDRs          []netip.Prefix
		excludedCIDRs     []netip.Prefix
		policyGwConfigs   []policyGatewayConfig
		matchedEndpoints  map[endpointKey]*endpointMetadata
		gatewayConfigs    []gatewayConfig
	}
	type args struct {
		epDataStore           map[endpointKey]*endpointMetadata
		nodesAddresses2Labels map[string]map[string]string
	}
	tests := []struct {
		name            string
		fields          fields
		args            args
		want            int
		wantEndpointKey endpointKey
	}{
		{
			name: "Test updateMatchedEndpointKeys with endpoints and nodes",
			fields: fields{
				id: types.NamespacedName{
					Name: "test",
				},
				endpointSelectors: []*slimv1.LabelSelector{{
					MatchLabels: map[string]string{
						"app": "test",
					},
				}},
				nodeSelectors: []*slimv1.LabelSelector{{
					MatchLabels: map[string]string{
						"node-name": "node1",
					},
				}},
			},
			args: args{
				epDataStore: map[endpointKey]*endpointMetadata{
					"123456": {
						key: "123456",
						labels: labels.Map2LabelArray(map[string]string{
							"app": "test",
						}, labels.LabelSourceK8s),
						nodeIP: "192.168.1.10",
					},
				},
				nodesAddresses2Labels: map[string]map[string]string{
					"192.168.1.10": {
						"node-name": "node1",
					},
				},
			},
			want:            1,
			wantEndpointKey: endpointKey("123456"),
		},
		{
			name: "Test updateMatchedEndpointKeys with namespaced endpoints and nodes",
			fields: fields{
				id: types.NamespacedName{
					Name: "test",
				},
				endpointSelectors: []*slimv1.LabelSelector{{
					MatchLabels: map[string]string{
						"io.kubernetes.pod.namespace": "default",
						"app":                         "test",
					},
				}},
				nodeSelectors: []*slimv1.LabelSelector{{
					MatchLabels: map[string]string{
						"node-name": "node1",
					},
				}},
			},
			args: args{
				epDataStore: map[endpointKey]*endpointMetadata{
					"123456": {
						key: "123456",
						labels: labels.Map2LabelArray(map[string]string{
							"io.kubernetes.pod.namespace": "default",
							"app":                         "test",
						}, labels.LabelSourceK8s),
						nodeIP: "192.168.1.10",
					},
				},
				nodesAddresses2Labels: map[string]map[string]string{
					"192.168.1.10": {
						"node-name": "node1",
					},
				},
			},
			want:            1,
			wantEndpointKey: endpointKey("123456"),
		},
		{
			name: "Test updateMatchedEndpointKeys endpoints and nodes with no match",
			fields: fields{
				id: types.NamespacedName{
					Name: "test",
				},
				endpointSelectors: []*slimv1.LabelSelector{{
					MatchLabels: map[string]string{
						"app": "test",
					},
				}},
				nodeSelectors: []*slimv1.LabelSelector{{
					MatchLabels: map[string]string{
						"node-name": "node1",
					},
				}},
			},
			args: args{
				epDataStore: map[endpointKey]*endpointMetadata{
					"123456": {
						key: "123456",
						labels: labels.Map2LabelArray(map[string]string{
							"app": "test",
						}, labels.LabelSourceK8s),
						nodeIP: "192.168.1.10",
					},
				},
				nodesAddresses2Labels: map[string]map[string]string{
					"192.168.1.11": {
						"node-name": "node1",
					},
				},
			},
			want:            0,
			wantEndpointKey: "",
		},
		{
			name: "Test updateMatchedEndpointKeys endpoints and nodes with no match label",
			fields: fields{
				id: types.NamespacedName{
					Name: "test",
				},
				endpointSelectors: []*slimv1.LabelSelector{{
					MatchLabels: map[string]string{
						"app": "test",
					},
				}},
				nodeSelectors: []*slimv1.LabelSelector{{
					MatchLabels: map[string]string{
						"node-name": "node1",
					},
				}},
			},
			args: args{
				epDataStore: map[endpointKey]*endpointMetadata{
					"123456": {
						key: "123456",
						labels: labels.Map2LabelArray(map[string]string{
							"app": "test",
						}, labels.LabelSourceK8s),
						nodeIP: "192.168.1.10",
					},
				},
				nodesAddresses2Labels: map[string]map[string]string{
					"192.168.1.10": {
						"bar": "bar",
					},
				},
			},
			want:            0,
			wantEndpointKey: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &PolicyConfig{
				id:                tt.fields.id,
				endpointSelectors: getAsPolicyLabelSelectors(tt.fields.endpointSelectors),
				nodeSelectors:     getAsPolicyLabelSelectors(tt.fields.nodeSelectors),
				dstCIDRs:          tt.fields.dstCIDRs,
				excludedCIDRs:     tt.fields.excludedCIDRs,
				policyGwConfigs:   tt.fields.policyGwConfigs,
				matchedEndpoints:  tt.fields.matchedEndpoints,
				gatewayConfigs:    tt.fields.gatewayConfigs,
			}
			config.updateMatchedEndpointKeys(tt.args.epDataStore, tt.args.nodesAddresses2Labels)
			assert.Len(t, config.matchedEndpoints, tt.want)
			if tt.want > 0 {
				assert.Contains(t, config.matchedEndpoints, endpointKey(tt.wantEndpointKey))
			}
		})
	}
}
