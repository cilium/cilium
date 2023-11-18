// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent_test

import (
	"context"
	"errors"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"

	"github.com/cilium/cilium/pkg/bgpv1/agent"
	"github.com/cilium/cilium/pkg/bgpv1/mock"
	v2api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// TestControllerSanity ensures that the controller calls the correct methods,
// with the correct arguments, during its Reconcile loop.
func TestControllerSanity(t *testing.T) {
	var wantPolicy = &v2alpha1api.CiliumBGPPeeringPolicy{
		Spec: v2alpha1api.CiliumBGPPeeringPolicySpec{
			NodeSelector: &v1.LabelSelector{
				MatchLabels: map[string]string{
					"bgp-policy": "a",
				},
			},
		},
	}
	var table = []struct {
		// name of test case
		name string
		// mock functions to provide to fakeNodeSpecer
		labels      map[string]string
		annotations map[string]string
		// a mock List method for the controller's PolicyLister
		plist func() ([]*v2alpha1api.CiliumBGPPeeringPolicy, error)
		// a mock ConfigurePeers method for the controller's BGPRouterManager
		configurePeers func(context.Context, *v2alpha1api.CiliumBGPPeeringPolicy, *v2api.CiliumNode) error
		// error nil or not
		err error
	}{
		// test the normal control flow of a policy being selected and applied.
		{
			name: "successful reconcile",
			labels: map[string]string{
				"bgp-policy": "a",
			},
			annotations: map[string]string{},
			plist: func() ([]*v2alpha1api.CiliumBGPPeeringPolicy, error) {
				return []*v2alpha1api.CiliumBGPPeeringPolicy{wantPolicy}, nil
			},
			configurePeers: func(_ context.Context, p *v2alpha1api.CiliumBGPPeeringPolicy, ciliumNode *v2api.CiliumNode) error {
				if !p.DeepEqual(wantPolicy) {
					t.Fatalf("got: %+v, want: %+v", p, wantPolicy)
				}
				return nil
			},
			err: nil,
		},
		// test policy defaulting
		{
			name: "policy defaulting on successful reconcile",
			labels: map[string]string{
				"bgp-policy": "a",
			},
			annotations: map[string]string{},
			plist: func() ([]*v2alpha1api.CiliumBGPPeeringPolicy, error) {
				p := wantPolicy.DeepCopy()
				p.Spec.VirtualRouters = []v2alpha1api.CiliumBGPVirtualRouter{
					{
						LocalASN: 65001,
						Neighbors: []v2alpha1api.CiliumBGPNeighbor{
							{
								PeerASN:     65000,
								PeerAddress: "172.0.0.1/32",
								GracefulRestart: &v2alpha1api.CiliumBGPNeighborGracefulRestart{
									Enabled: true,
								},
							},
						},
					},
				}
				return []*v2alpha1api.CiliumBGPPeeringPolicy{p}, nil
			},
			configurePeers: func(_ context.Context, p *v2alpha1api.CiliumBGPPeeringPolicy, _ *v2api.CiliumNode) error {
				for _, r := range p.Spec.VirtualRouters {
					for _, n := range r.Neighbors {
						if n.PeerPort == nil ||
							n.EBGPMultihopTTL == nil ||
							n.ConnectRetryTimeSeconds == nil ||
							n.HoldTimeSeconds == nil ||
							n.KeepAliveTimeSeconds == nil ||
							n.GracefulRestart.RestartTimeSeconds == nil {
							t.Fatalf("policy: %v not defaulted properly", p)
						}
					}
				}
				return nil
			},
			err: nil,
		},
		{
			name: "configure peers error",
			plist: func() ([]*v2alpha1api.CiliumBGPPeeringPolicy, error) {
				return []*v2alpha1api.CiliumBGPPeeringPolicy{wantPolicy}, nil
			},
			labels: map[string]string{
				"bgp-policy": "a",
			},
			annotations: map[string]string{},
			configurePeers: func(_ context.Context, p *v2alpha1api.CiliumBGPPeeringPolicy, _ *v2api.CiliumNode) error {
				return errors.New("")
			},
			err: errors.New(""),
		},
		{
			name: "timer validation error",
			plist: func() ([]*v2alpha1api.CiliumBGPPeeringPolicy, error) {
				p := wantPolicy.DeepCopy()
				p.Spec.VirtualRouters = []v2alpha1api.CiliumBGPVirtualRouter{
					{
						LocalASN: 65001,
						Neighbors: []v2alpha1api.CiliumBGPNeighbor{
							{
								PeerASN:     65000,
								PeerAddress: "172.0.0.1/32",
								// KeepAliveTimeSeconds larger than HoldTimeSeconds = error
								KeepAliveTimeSeconds: pointer.Int32(10),
								HoldTimeSeconds:      pointer.Int32(5),
							},
						},
					},
				}
				return []*v2alpha1api.CiliumBGPPeeringPolicy{p}, nil
			},
			labels: map[string]string{
				"bgp-policy": "a",
			},
			annotations: map[string]string{},
			configurePeers: func(_ context.Context, p *v2alpha1api.CiliumBGPPeeringPolicy, _ *v2api.CiliumNode) error {
				return nil
			},
			err: errors.New(""),
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			policyLister := &agent.MockCiliumBGPPeeringPolicyLister{
				List_: tt.plist,
			}
			rtmgr := &mock.MockBGPRouterManager{
				ConfigurePeers_: tt.configurePeers,
			}

			// create test cilium node
			node := &v2api.CiliumNode{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "Test Node",
					Annotations: tt.annotations,
					Labels:      tt.labels,
				},
			}

			c := agent.Controller{
				PolicyLister:    policyLister,
				BGPMgr:          rtmgr,
				LocalCiliumNode: node,
			}

			err := c.Reconcile(context.Background())
			if (tt.err == nil) != (err == nil) {
				t.Fatalf("want: %v, got: %v", tt.err, err)
			}
		})
	}
}

// TestPolicySelection ensure the selection of a policy is performed correctly
// and enforces the rule set documented by the PolicySelection function.
func TestPolicySelection(t *testing.T) {
	var table = []struct {
		// name of test case
		name string
		// labels for Node object created during test
		nodeLabels map[string]string
		// struct expanded into a CiliumBGPPeeringPolicy during test
		policies []struct {
			// if true this is the selected policy the test expects
			want bool
			// expanded into a CiliumBGPPeeringPolicy during test
			selector *v1.LabelSelector
		}
		// error nil or not
		err error
	}{
		{
			name: "no policies",
			nodeLabels: map[string]string{
				"bgp-peering-policy": "a",
			},
			policies: []struct {
				want     bool
				selector *v1.LabelSelector
			}{},
			err: nil,
		},
		{
			name: "nil node label selector",
			nodeLabels: map[string]string{
				"bgp-peering-policy": "a",
			},
			policies: []struct {
				want     bool
				selector *v1.LabelSelector
			}{
				{
					want:     true,
					selector: nil,
				},
			},
			err: nil,
		},
		{
			name: "empty node label selector",
			nodeLabels: map[string]string{
				"bgp-peering-policy": "a",
			},
			policies: []struct {
				want     bool
				selector *v1.LabelSelector
			}{
				{
					want: true,
					selector: &v1.LabelSelector{
						MatchLabels:      map[string]string{},
						MatchExpressions: []v1.LabelSelectorRequirement{},
					},
				},
			},
			err: nil,
		},
		{
			name: "nil values in MatchExpressions for node label selector",
			nodeLabels: map[string]string{
				"bgp-peering-policy": "a",
			},
			policies: []struct {
				want     bool
				selector *v1.LabelSelector
			}{
				{
					want: false,
					selector: &v1.LabelSelector{
						MatchExpressions: []v1.LabelSelectorRequirement{
							{
								Key:      "bgp-peering-policy",
								Operator: "In",
								Values:   nil,
							},
						},
					},
				},
			},
			err: nil,
		},
		{
			name: "valid value in MatchExpressions for node label selector",
			nodeLabels: map[string]string{
				"bgp-peering-policy": "a",
			},
			policies: []struct {
				want     bool
				selector *v1.LabelSelector
			}{
				{
					want: true,
					selector: &v1.LabelSelector{
						MatchExpressions: []v1.LabelSelectorRequirement{
							{
								Key:      "bgp-peering-policy",
								Operator: "In",
								Values:   []string{"a"},
							},
						},
					},
				},
			},
			err: nil,
		},
		{
			// expect first policy returned, error nil
			name: "policy match",
			nodeLabels: map[string]string{
				"bgp-peering-policy": "a",
			},
			policies: []struct {
				want     bool
				selector *v1.LabelSelector
			}{
				{
					want: true,
					selector: &v1.LabelSelector{
						MatchLabels: map[string]string{
							"bgp-peering-policy": "a",
						},
					},
				},
			},
			err: nil,
		},
		{
			// expect nil policy returned, error nil
			name: "policy no match",
			nodeLabels: map[string]string{
				"bgp-peering-policy": "a",
			},
			policies: []struct {
				want     bool
				selector *v1.LabelSelector
			}{
				{
					want: false,
					selector: &v1.LabelSelector{
						MatchLabels: map[string]string{
							"bgp-peering-policy": "b",
						},
					},
				},
			},
			err: nil,
		},
		{
			// expect first policy returned, error nil
			name: "multi policy match, no conflict",
			nodeLabels: map[string]string{
				"bgp-peering-policy": "a",
			},
			policies: []struct {
				want     bool
				selector *v1.LabelSelector
			}{
				{
					want: true,
					selector: &v1.LabelSelector{
						MatchLabels: map[string]string{
							"bgp-peering-policy": "a",
						},
					},
				},
				{
					selector: &v1.LabelSelector{
						MatchLabels: map[string]string{
							"bgp-peering-policy": "b",
						},
					},
				},
				{
					selector: &v1.LabelSelector{
						MatchLabels: map[string]string{
							"bgp-peering-policy": "c",
						},
					},
				},
			},
			err: nil,
		},
		{
			// expect nil policy returned, error not nil
			name: "multi policy match, conflict",
			nodeLabels: map[string]string{
				"bgp-peering-policy": "a",
			},
			policies: []struct {
				want     bool
				selector *v1.LabelSelector
			}{
				{
					selector: &v1.LabelSelector{
						MatchLabels: map[string]string{
							"bgp-peering-policy": "a",
						},
					},
				},
				{
					selector: &v1.LabelSelector{
						MatchLabels: map[string]string{
							"bgp-peering-policy": "a",
						},
					},
				},
				{
					selector: &v1.LabelSelector{
						MatchLabels: map[string]string{
							"bgp-peering-policy": "b",
						},
					},
				},
			},
			err: errors.New(""),
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			// expand policies into CiliumBGPPeeringPolicies, make note of wanted
			var policies []*v2alpha1api.CiliumBGPPeeringPolicy
			var want *v2alpha1api.CiliumBGPPeeringPolicy
			for _, p := range tt.policies {
				policy := &v2alpha1api.CiliumBGPPeeringPolicy{
					Spec: v2alpha1api.CiliumBGPPeeringPolicySpec{
						NodeSelector: p.selector,
					},
				}
				policies = append(policies, policy)
				if p.want {
					want = policy
				}
			}
			// call function under test
			policy, err := agent.PolicySelection(context.Background(), tt.nodeLabels, policies)
			if (tt.err == nil) != (err == nil) {
				t.Fatalf("expected err: %v", (tt.err == nil))
			}
			if want != nil {
				if policy == nil {
					t.Fatalf("got: <nil>, want: %+v", *want)
				}

				// pointer comparison, not a deep equal.
				if policy != want {
					t.Fatalf("got: %+v, want: %+v", *policy, *want)
				}
			}
		})
	}
}
