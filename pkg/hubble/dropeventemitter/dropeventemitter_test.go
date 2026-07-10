// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dropeventemitter

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/identity"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

const (
	fakePodName = "pod"
	fakePodUid  = "79f04581-a0e7-4a42-a020-db51cf21a605"
)

func TestEndpointToString(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		endpoint *flowpb.Endpoint
		expect   string
	}{
		{
			name:     fakePodName,
			ip:       "1.2.3.4",
			endpoint: &flowpb.Endpoint{PodName: fakePodName, Namespace: "namespace"},
			expect:   "namespace/pod (1.2.3.4)",
		},
		{
			name:     "node",
			ip:       "1.2.3.4",
			endpoint: &flowpb.Endpoint{Identity: identity.ReservedIdentityRemoteNode.Uint32()},
			expect:   identity.ReservedIdentityRemoteNode.String() + " (1.2.3.4)",
		},
		{
			name:     "unknown",
			ip:       "1.2.3.4",
			endpoint: &flowpb.Endpoint{Identity: identity.MaxLocalIdentity.Uint32() + 1},
			expect:   "1.2.3.4",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			str := endpointToString(tt.ip, tt.endpoint)
			assert.Equal(t, str, tt.expect)
		})
	}
}

func TestL4protocolToString(t *testing.T) {
	tests := []struct {
		name   string
		l4     *flowpb.Layer4
		expect string
	}{
		{
			name:   "udp/512",
			l4:     &flowpb.Layer4{Protocol: &flowpb.Layer4_UDP{UDP: &flowpb.UDP{DestinationPort: 512}}},
			expect: "UDP/512",
		},
		{
			name:   "tcp/443",
			l4:     &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 443}}},
			expect: "TCP/443",
		},
		{
			name:   "unknown",
			l4:     &flowpb.Layer4{},
			expect: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			str := l4protocolToString(tt.l4)
			assert.Equal(t, str, tt.expect)
		})
	}
}

func TestProcessFlow(t *testing.T) {
	tests := []struct {
		name   string
		flow   *flowpb.Flow
		expect string
	}{
		{
			name: "valid ingress drop event",
			flow: &flowpb.Flow{
				Verdict:          flowpb.Verdict_DROPPED,
				DropReasonDesc:   flowpb.DropReason_POLICY_DENIED,
				TrafficDirection: flowpb.TrafficDirection_INGRESS,
				IP:               &flowpb.IP{Source: "1.2.3.4", Destination: "5.6.7.8"},
				Source:           &flowpb.Endpoint{},
				Destination:      &flowpb.Endpoint{Namespace: "namespace", PodName: fakePodName},
				L4:               &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 443}}},
			},
			expect: "Incoming packet dropped (policy_denied) from unknown (1.2.3.4) TCP/443",
		},
		{
			name: "valid egress drop event to node",
			flow: &flowpb.Flow{
				Verdict:          flowpb.Verdict_DROPPED,
				DropReasonDesc:   flowpb.DropReason_POLICY_DENIED,
				TrafficDirection: flowpb.TrafficDirection_EGRESS,
				IP:               &flowpb.IP{Source: "1.2.3.4", Destination: "5.6.7.8"},
				Source:           &flowpb.Endpoint{Namespace: "namespace", PodName: fakePodName},
				Destination:      &flowpb.Endpoint{Identity: identity.ReservedIdentityRemoteNode.Uint32()},
				L4:               &flowpb.Layer4{Protocol: &flowpb.Layer4_UDP{UDP: &flowpb.UDP{DestinationPort: 512}}},
			},
			expect: "Outgoing packet dropped (policy_denied) to remote-node (5.6.7.8) UDP/512",
		},
		{
			name: "ingress drop event not matching reason",
			flow: &flowpb.Flow{
				Verdict:          flowpb.Verdict_DROPPED,
				DropReasonDesc:   flowpb.DropReason_AUTH_REQUIRED,
				TrafficDirection: flowpb.TrafficDirection_INGRESS,
				IP:               &flowpb.IP{Source: "1.2.3.4", Destination: "5.6.7.8"},
				Source:           &flowpb.Endpoint{},
				Destination:      &flowpb.Endpoint{Namespace: "namespace", PodName: fakePodName},
				L4:               &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 443}}},
			},
			expect: "",
		},
		{
			name: "ingress verdict is not dropped",
			flow: &flowpb.Flow{
				Verdict:          flowpb.Verdict_ERROR,
				DropReasonDesc:   flowpb.DropReason_POLICY_DENIED,
				TrafficDirection: flowpb.TrafficDirection_INGRESS,
				IP:               &flowpb.IP{Source: "1.2.3.4", Destination: "5.6.7.8"},
				Source:           &flowpb.Endpoint{},
				Destination:      &flowpb.Endpoint{Namespace: "namespace", PodName: fakePodName},
				L4:               &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 443}}},
			},
			expect: "",
		},
		{
			name: "ingress but no destination pod",
			flow: &flowpb.Flow{
				Verdict:          flowpb.Verdict_DROPPED,
				DropReasonDesc:   flowpb.DropReason_POLICY_DENIED,
				TrafficDirection: flowpb.TrafficDirection_INGRESS,
				IP:               &flowpb.IP{Source: "1.2.3.4", Destination: "5.6.7.8"},
				Source:           &flowpb.Endpoint{Namespace: "namespace", PodName: fakePodName},
				Destination:      &flowpb.Endpoint{},
				L4:               &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 443}}},
			},
			expect: "",
		},
		{
			name: "egress but no source pod",
			flow: &flowpb.Flow{
				Verdict:          flowpb.Verdict_DROPPED,
				DropReasonDesc:   flowpb.DropReason_POLICY_DENIED,
				TrafficDirection: flowpb.TrafficDirection_EGRESS,
				IP:               &flowpb.IP{Source: "1.2.3.4", Destination: "5.6.7.8"},
				Source:           &flowpb.Endpoint{},
				Destination:      &flowpb.Endpoint{},
				L4:               &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 443}}},
			},
			expect: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeRecorder := &FakeRecorder{
				Events:        make(chan string, 3),
				IncludeObject: true,
			}
			e := &dropEventEmitter{
				reasons:    []flowpb.DropReason{flowpb.DropReason_POLICY_DENIED},
				recorder:   fakeRecorder,
				k8sWatcher: &fakeK8SWatcher{},
			}
			if err := e.ProcessFlow(t.Context(), tt.flow); err != nil {
				t.Errorf("DropEventEmitter.ProcessFlow() error = %v", err)
			}
			if tt.expect == "" {
				assert.Empty(t, fakeRecorder.Events)
			} else {
				assert.Len(t, fakeRecorder.Events, 1)
				event := <-fakeRecorder.Events
				assert.Contains(t, event, tt.expect)
				if tt.flow.Destination.PodName == fakePodName && tt.flow.TrafficDirection == flowpb.TrafficDirection_EGRESS {
					assert.Contains(t, event, fakePodUid)
				}
			}
		})
	}
}

func TestGetLocalEndpoint(t *testing.T) {
	tests := []struct {
		name   string
		flow   *flowpb.Flow
		expect *endpoint.Endpoint
	}{
		{
			name: "ingress",
			flow: &flowpb.Flow{
				TrafficDirection: flowpb.TrafficDirection_INGRESS,
				Destination:      &flowpb.Endpoint{ID: 1},
			},
			expect: &endpoint.Endpoint{ID: 1},
		},
		{
			name: "egress",
			flow: &flowpb.Flow{
				TrafficDirection: flowpb.TrafficDirection_EGRESS,
				Source:           &flowpb.Endpoint{ID: 2},
			},
			expect: &endpoint.Endpoint{ID: 2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &dropEventEmitter{
				endpointsLookup: &fakeEndpointsLookup{},
			}
			ep := e.getLocalEndpoint(tt.flow)
			assert.Equal(t, tt.expect, ep)
		})
	}
}

func TestGetPolicyRulesFromEndpoint(t *testing.T) {
	tests := []struct {
		name           string
		direction      flowpb.TrafficDirection
		endpoint       endpointInterface
		expect         []*models.PolicyRule
		expectRevision uint64
		expectErr      error
	}{
		{
			name:      "ingress",
			direction: flowpb.TrafficDirection_INGRESS,
			endpoint:  &fakeEndpoint{},
			expect: []*models.PolicyRule{
				{
					DerivedFromRules: [][]string{{
						"ingress-rule",
					}},
				},
			},
			expectRevision: 1,
			expectErr:      nil,
		},
		{
			name:      "egress",
			direction: flowpb.TrafficDirection_EGRESS,
			endpoint:  &fakeEndpoint{},
			expect: []*models.PolicyRule{
				{
					DerivedFromRules: [][]string{{
						"egress-rule",
					}},
				},
			},
			expectRevision: 1,
			expectErr:      nil,
		},
		{
			name:           "Endpoint is nil",
			endpoint:       nil,
			expect:         nil,
			expectRevision: 0,
			expectErr:      nil,
		},
		{
			name:           "GetRealizedL4PolicyRuleOriginModel returns error",
			endpoint:       &fakeEndpointError{},
			expect:         nil,
			expectRevision: 0,
			expectErr:      fmt.Errorf("error"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, revision, err := getPolicyRulesFromEndpoint(tt.direction, tt.endpoint)
			assert.Equal(t, tt.expectErr, err)
			assert.Equal(t, tt.expect, rules)
			assert.Equal(t, tt.expectRevision, revision)
		})
	}
}

func TestParsePolicyRules(t *testing.T) {
	tests := []struct {
		name                  string
		rules                 []*models.PolicyRule
		expectPolicies        set.Set[string]
		expectClusterPolicies set.Set[string]
	}{
		{
			name: "Rules with namespaced network policies",
			rules: []*models.PolicyRule{
				{
					DerivedFromRules: [][]string{{
						"k8s:io.cilium.k8s.policy.name=foo",
						"k8s:io.cilium.k8s.policy.namespace=bar",
						"k8s:io.cilium.k8s.policy.derived-from=CiliumNetworkPolicy",
					}},
				},
			},
			expectPolicies: set.NewSet("CiliumNetworkPolicy/foo"),
		},
		{
			name: "Rules with clusterwide network policies",
			rules: []*models.PolicyRule{
				{
					DerivedFromRules: [][]string{{
						"k8s:io.cilium.k8s.policy.name=foo",
						"k8s:io.cilium.k8s.policy.derived-from=CiliumClusterwideNetworkPolicy",
					}},
				},
			},
			expectClusterPolicies: set.NewSet("CiliumClusterwideNetworkPolicy/foo"),
		},
		{
			name: "Rules with both namespaced and clusterwide network policies",
			rules: []*models.PolicyRule{
				{
					DerivedFromRules: [][]string{{
						"k8s:io.cilium.k8s.policy.name=foo",
						"k8s:io.cilium.k8s.policy.namespace=bar",
						"k8s:io.cilium.k8s.policy.derived-from=CiliumNetworkPolicy",
					}},
				},
				{
					DerivedFromRules: [][]string{{
						"k8s:io.cilium.k8s.policy.name=foowide",
						"k8s:io.cilium.k8s.policy.derived-from=CiliumClusterwideNetworkPolicy",
					}},
				},
			},
			expectPolicies:        set.NewSet("CiliumNetworkPolicy/foo"),
			expectClusterPolicies: set.NewSet("CiliumClusterwideNetworkPolicy/foowide"),
		},
		{
			name:                  "Rules is nil",
			rules:                 nil,
			expectPolicies:        set.NewSet[string](),
			expectClusterPolicies: set.NewSet[string](),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualPolicies, actualClusterPolicies := parsePolicyRules(tt.rules, 1)
			assert.Equal(t, tt.expectPolicies, actualPolicies)
			assert.Equal(t, tt.expectClusterPolicies, actualClusterPolicies)
		})
	}
}

func TestParsePolicyCorrelation(t *testing.T) {
	tests := []struct {
		name                  string
		direction             flowpb.TrafficDirection
		ingressDeniedBy       []*flowpb.Policy
		egressDeniedBy        []*flowpb.Policy
		expectPolicies        set.Set[string]
		expectClusterPolicies set.Set[string]
	}{
		{
			name:      "Egress with network policy",
			direction: flowpb.TrafficDirection_EGRESS,
			egressDeniedBy: []*flowpb.Policy{
				{
					Name:      "foo",
					Namespace: "bar",
					Kind:      "CiliumNetworkPolicy",
				},
			},
			expectPolicies: set.NewSet("CiliumNetworkPolicy/foo"),
		},
		{
			name:      "Ingress with network policy",
			direction: flowpb.TrafficDirection_INGRESS,
			ingressDeniedBy: []*flowpb.Policy{
				{
					Name:      "foo",
					Namespace: "bar",
					Kind:      "CiliumNetworkPolicy",
				},
			},
			expectPolicies: set.NewSet("CiliumNetworkPolicy/foo"),
		},
		{
			name:      "Egress with clusterwide network policy",
			direction: flowpb.TrafficDirection_EGRESS,
			egressDeniedBy: []*flowpb.Policy{
				{
					Name: "foo",
					Kind: "CiliumClusterwideNetworkPolicy",
				},
			},
			expectClusterPolicies: set.NewSet("CiliumClusterwideNetworkPolicy/foo"),
		},
		{
			name:      "Egress with both namespaced and clusterwide network policies",
			direction: flowpb.TrafficDirection_EGRESS,
			egressDeniedBy: []*flowpb.Policy{
				{
					Name: "foowide",
					Kind: "CiliumClusterwideNetworkPolicy",
				},
				{
					Name:      "foo",
					Namespace: "bar",
					Kind:      "CiliumNetworkPolicy",
				},
			},
			expectPolicies:        set.NewSet("CiliumNetworkPolicy/foo"),
			expectClusterPolicies: set.NewSet("CiliumClusterwideNetworkPolicy/foowide"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualPolicies, actualClusterPolicies := parsePolicyCorrelation(tt.direction, tt.ingressDeniedBy, tt.egressDeniedBy)
			assert.Equal(t, tt.expectPolicies, actualPolicies)
			assert.Equal(t, tt.expectClusterPolicies, actualClusterPolicies)
		})
	}
}

type fakeK8SWatcher struct{}

func (k *fakeK8SWatcher) GetCachedNamespace(namespace string) (*slim_corev1.Namespace, error) {
	return nil, nil
}
func (k *fakeK8SWatcher) GetCachedPod(namespace, name string) (*slim_corev1.Pod, error) {
	if name == fakePodName {
		return &slim_corev1.Pod{
			ObjectMeta: slim_metav1.ObjectMeta{
				Name: fakePodName,
				UID:  fakePodUid,
			},
		}, nil
	}
	return nil, fmt.Errorf("pod not found in cache : %s", name)
}

type fakeEndpointsLookup struct{}

func (e *fakeEndpointsLookup) LookupCiliumID(id uint16) *endpoint.Endpoint {
	return &endpoint.Endpoint{
		ID: id,
	}
}

type fakeEndpoint struct{}

func (e *fakeEndpoint) GetRealizedL4PolicyRuleOriginModel() (*models.L4Policy, uint64, error) {
	return &models.L4Policy{
		Ingress: []*models.PolicyRule{
			{
				DerivedFromRules: [][]string{{
					"ingress-rule",
				}},
			},
		},
		Egress: []*models.PolicyRule{
			{
				DerivedFromRules: [][]string{{
					"egress-rule",
				}},
			},
		},
	}, 1, nil
}

type fakeEndpointError struct{}

func (e *fakeEndpointError) GetRealizedL4PolicyRuleOriginModel() (*models.L4Policy, uint64, error) {
	return nil, 0, fmt.Errorf("error")
}
