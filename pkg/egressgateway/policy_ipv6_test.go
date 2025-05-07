// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func TestIPv6Support(t *testing.T) {
	// Test that a policy with IPv6 destination CIDRs is correctly parsed
	policy := &v2.CiliumEgressGatewayPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-ipv6-policy",
		},
		Spec: v2.CiliumEgressGatewayPolicySpec{
			Selectors: []v2.EgressRule{
				{
					PodSelector: &slimv1.LabelSelector{
						MatchLabels: map[string]string{
							"app": "test",
						},
					},
				},
			},
			DestinationCIDRs: []v2.CIDR{
				"2001:db8::/32",
			},
			EgressGateway: &v2.EgressGateway{
				NodeSelector: &slimv1.LabelSelector{
					MatchLabels: map[string]string{
						"node-role.kubernetes.io/gateway": "true",
					},
				},
				Interface: "eth0",
			},
		},
	}

	// Parse the policy
	config, err := ParseCEGP(policy)

	// We expect no error
	assert.NoError(t, err)

	// Check that v6needed is set to true
	assert.True(t, config.policyGwConfig.v6needed)

	// Test that a policy with IPv6 egress IP is correctly parsed
	policy = &v2.CiliumEgressGatewayPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-ipv6-egress-ip-policy",
		},
		Spec: v2.CiliumEgressGatewayPolicySpec{
			Selectors: []v2.EgressRule{
				{
					PodSelector: &slimv1.LabelSelector{
						MatchLabels: map[string]string{
							"app": "test",
						},
					},
				},
			},
			DestinationCIDRs: []v2.CIDR{
				"2001:db8::/32",
			},
			EgressGateway: &v2.EgressGateway{
				NodeSelector: &slimv1.LabelSelector{
					MatchLabels: map[string]string{
						"node-role.kubernetes.io/gateway": "true",
					},
				},
				EgressIP: "2001:db8::1",
			},
		},
	}

	// Parse the policy
	config, err = ParseCEGP(policy)

	// We expect no error
	assert.NoError(t, err)

	// Check that v6needed is set to true
	assert.True(t, config.policyGwConfig.v6needed)

	// Check that the egress IP is correctly parsed
	assert.True(t, config.policyGwConfig.egressIP.Is6())
}

func TestMismatchedIPFamilies(t *testing.T) {
	// Test that a policy with mismatched IP families (IPv6 egress IP with IPv4 destination CIDRs) is rejected
	policy := &v2.CiliumEgressGatewayPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-mismatched-policy",
		},
		Spec: v2.CiliumEgressGatewayPolicySpec{
			Selectors: []v2.EgressRule{
				{
					PodSelector: &slimv1.LabelSelector{
						MatchLabels: map[string]string{
							"app": "test",
						},
					},
				},
			},
			DestinationCIDRs: []v2.CIDR{
				"192.168.0.0/16",
			},
			EgressGateway: &v2.EgressGateway{
				NodeSelector: &slimv1.LabelSelector{
					MatchLabels: map[string]string{
						"node-role.kubernetes.io/gateway": "true",
					},
				},
				EgressIP: "2001:db8::1",
			},
		},
	}

	// Parse the policy
	_, err := ParseCEGP(policy)

	// We expect an error because the IP families don't match
	assert.Error(t, err)

	// The error should mention mismatched IP families
	assert.Contains(t, err.Error(), "mismatched IP families")
}
