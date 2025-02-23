// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/bgpv1/agent"
	"github.com/cilium/cilium/pkg/bgpv1/agent/mode"
	"github.com/cilium/cilium/pkg/bgpv1/manager/store"
	"github.com/cilium/cilium/pkg/bgpv1/mock"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// TestControllerSanity ensures that the controller calls the correct methods,
// with the correct arguments, during its Reconcile loop.
func TestControllerSanity(t *testing.T) {
	var wantPolicy = &v2alpha1.CiliumBGPPeeringPolicy{
		Spec: v2alpha1.CiliumBGPPeeringPolicySpec{
			NodeSelector: &v1.LabelSelector{
				MatchLabels: map[string]string{
					"bgp-policy": "a",
				},
			},
		},
	}

	// Reset to false after each test case
	fullWithdrawalObserved := false

	var table = []struct {
		// name of test case
		name string
		// mock functions to provide to fakeNodeSpecer
		labels      map[string]string
		annotations map[string]string
		// a mock List method for the controller's PolicyLister
		plist func() ([]*v2alpha1.CiliumBGPPeeringPolicy, error)
		// a mock ConfigurePeers method for the controller's BGPRouterManager
		configurePeers func(context.Context, *v2alpha1.CiliumBGPPeeringPolicy, *v2.CiliumNode) error
		// error nil or not
		err error
		// expect route full withdrawal observed
		fullWithdrawalExpected bool
	}{
		// test the normal control flow of a policy being selected and applied.
		{
			name: "successful reconcile",
			labels: map[string]string{
				"bgp-policy": "a",
			},
			annotations: map[string]string{},
			plist: func() ([]*v2alpha1.CiliumBGPPeeringPolicy, error) {
				return []*v2alpha1.CiliumBGPPeeringPolicy{wantPolicy}, nil
			},
			configurePeers: func(_ context.Context, p *v2alpha1.CiliumBGPPeeringPolicy, ciliumNode *v2.CiliumNode) error {
				if !p.DeepEqual(wantPolicy) {
					t.Fatalf("got: %+v, want: %+v", p, wantPolicy)
				}
				return nil
			},
			err: nil,
		},
		{
			name: "multiple policies selects node",
			labels: map[string]string{
				"bgp-policy": "a",
			},
			annotations: map[string]string{},
			plist: func() ([]*v2alpha1.CiliumBGPPeeringPolicy, error) {
				p0 := wantPolicy.DeepCopy()
				p0.Name = "policy0"
				p1 := wantPolicy.DeepCopy()
				p1.Name = "policy1"
				return []*v2alpha1.CiliumBGPPeeringPolicy{p0, p1}, nil
			},
			configurePeers: func(_ context.Context, p *v2alpha1.CiliumBGPPeeringPolicy, n *v2.CiliumNode) error {
				if p == nil && n == nil {
					fullWithdrawalObserved = true
				}
				return nil
			},
			err:                    errors.New(""),
			fullWithdrawalExpected: false,
		},
		// test policy defaulting
		{
			name: "policy defaulting on successful reconcile",
			labels: map[string]string{
				"bgp-policy": "a",
			},
			annotations: map[string]string{},
			plist: func() ([]*v2alpha1.CiliumBGPPeeringPolicy, error) {
				p := wantPolicy.DeepCopy()
				p.Spec.VirtualRouters = []v2alpha1.CiliumBGPVirtualRouter{
					{
						LocalASN: 65001,
						Neighbors: []v2alpha1.CiliumBGPNeighbor{
							{
								PeerASN:     65000,
								PeerAddress: "172.0.0.1/32",
								GracefulRestart: &v2alpha1.CiliumBGPNeighborGracefulRestart{
									Enabled: true,
								},
							},
						},
					},
				}
				return []*v2alpha1.CiliumBGPPeeringPolicy{p}, nil
			},
			configurePeers: func(_ context.Context, p *v2alpha1.CiliumBGPPeeringPolicy, _ *v2.CiliumNode) error {
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
			plist: func() ([]*v2alpha1.CiliumBGPPeeringPolicy, error) {
				return []*v2alpha1.CiliumBGPPeeringPolicy{wantPolicy}, nil
			},
			labels: map[string]string{
				"bgp-policy": "a",
			},
			annotations: map[string]string{},
			configurePeers: func(_ context.Context, p *v2alpha1.CiliumBGPPeeringPolicy, _ *v2.CiliumNode) error {
				return errors.New("")
			},
			err: errors.New(""),
		},
		{
			name: "timer validation error",
			plist: func() ([]*v2alpha1.CiliumBGPPeeringPolicy, error) {
				p := wantPolicy.DeepCopy()
				p.Spec.VirtualRouters = []v2alpha1.CiliumBGPVirtualRouter{
					{
						LocalASN: 65001,
						Neighbors: []v2alpha1.CiliumBGPNeighbor{
							{
								PeerASN:     65000,
								PeerAddress: "172.0.0.1/32",
								// KeepAliveTimeSeconds larger than HoldTimeSeconds = error
								KeepAliveTimeSeconds: ptr.To[int32](10),
								HoldTimeSeconds:      ptr.To[int32](5),
							},
						},
					},
				}
				return []*v2alpha1.CiliumBGPPeeringPolicy{p}, nil
			},
			labels: map[string]string{
				"bgp-policy": "a",
			},
			annotations: map[string]string{},
			configurePeers: func(_ context.Context, p *v2alpha1.CiliumBGPPeeringPolicy, _ *v2.CiliumNode) error {
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
			node := &v2.CiliumNode{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "Test Node",
					Annotations: tt.annotations,
					Labels:      tt.labels,
				},
			}

			c := agent.Controller{
				PolicyLister:       policyLister,
				BGPMgr:             rtmgr,
				LocalCiliumNode:    node,
				BGPNodeConfigStore: store.NewMockBGPCPResourceStore[*v2.CiliumBGPNodeConfig](),
				ConfigMode:         mode.NewConfigMode(),
			}

			err := c.Reconcile(context.Background())
			if (tt.err == nil) != (err == nil) {
				t.Fatalf("want: %v, got: %v", tt.err, err)
			}

			if tt.fullWithdrawalExpected != fullWithdrawalObserved {
				t.Fatal("full withdrawal not observed")
			}
		})
		fullWithdrawalObserved = false
	}
}

// TestDeselection ensures that the deselection of a policy causes a full withdrawal
func TestDeselection(t *testing.T) {
	var policy = &v2alpha1.CiliumBGPPeeringPolicy{
		Spec: v2alpha1.CiliumBGPPeeringPolicySpec{
			NodeSelector: &v1.LabelSelector{
				MatchLabels: map[string]string{
					"bgp-policy": "a",
				},
			},
		},
	}

	withPolicy := func() ([]*v2alpha1.CiliumBGPPeeringPolicy, error) {
		return []*v2alpha1.CiliumBGPPeeringPolicy{policy}, nil
	}

	withoutPolicy := func() ([]*v2alpha1.CiliumBGPPeeringPolicy, error) {
		return []*v2alpha1.CiliumBGPPeeringPolicy{}, nil
	}

	// Start from empty policy list
	policyLister := &agent.MockCiliumBGPPeeringPolicyLister{
		List_: withoutPolicy,
	}

	fullWithdrawalObserved := false
	rtmgr := &mock.MockBGPRouterManager{
		ConfigurePeers_: func(_ context.Context, p *v2alpha1.CiliumBGPPeeringPolicy, n *v2.CiliumNode) error {
			if p == nil && n == nil {
				fullWithdrawalObserved = true
			}
			return nil
		},
	}

	// create test cilium node
	node := &v2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "Test Node",
			Labels: map[string]string{
				"bgp-policy": "a",
			},
		},
	}

	c := agent.Controller{
		PolicyLister:       policyLister,
		BGPMgr:             rtmgr,
		LocalCiliumNode:    node,
		BGPNodeConfigStore: store.NewMockBGPCPResourceStore[*v2.CiliumBGPNodeConfig](),
		ConfigMode:         mode.NewConfigMode(),
	}

	// First, reconcile with the policy selected
	err := c.Reconcile(context.Background())
	require.NoError(t, err)

	// At this point, we shouldn't see any full withdrawal because
	// there is no previous policy.
	require.False(t, fullWithdrawalObserved)

	// Now, reconcile with the policy selected
	policyLister.List_ = withPolicy
	err = c.Reconcile(context.Background())
	require.NoError(t, err)

	// At this point, we shouldn't see any full withdrawal because
	// the policy is still selected.
	require.False(t, fullWithdrawalObserved)

	// Now, reconcile with the policy deselected
	policyLister.List_ = withoutPolicy
	err = c.Reconcile(context.Background())
	require.NoError(t, err)

	// At this point, we should see a full withdrawal because
	// the policy is no longer selected.
	require.True(t, fullWithdrawalObserved)
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
			var policies []*v2alpha1.CiliumBGPPeeringPolicy
			var want *v2alpha1.CiliumBGPPeeringPolicy
			for _, p := range tt.policies {
				policy := &v2alpha1.CiliumBGPPeeringPolicy{
					Spec: v2alpha1.CiliumBGPPeeringPolicySpec{
						NodeSelector: p.selector,
					},
				}
				policies = append(policies, policy)
				if p.want {
					want = policy
				}
			}
			// call function under test
			policy, err := agent.PolicySelection(tt.nodeLabels, policies)
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

func TestBGPModeSelection(t *testing.T) {
	var table = []struct {
		name          string
		initialMode   mode.Mode
		ciliumNode    *v2.CiliumNode
		policy        *v2alpha1.CiliumBGPPeeringPolicy
		bgpNodeConfig *v2.CiliumBGPNodeConfig
		expectedMode  mode.Mode
	}{
		{
			name:        "Disabled to BGPv1",
			initialMode: mode.Disabled,
			ciliumNode: &v2.CiliumNode{
				ObjectMeta: metav1.ObjectMeta{
					Name: "Test Node",
					Labels: map[string]string{
						"bgp-policy": "a",
					},
				},
			},
			policy: &v2alpha1.CiliumBGPPeeringPolicy{
				Spec: v2alpha1.CiliumBGPPeeringPolicySpec{
					NodeSelector: &v1.LabelSelector{
						MatchLabels: map[string]string{
							"bgp-policy": "a",
						},
					},
				},
			},
			bgpNodeConfig: nil,
			expectedMode:  mode.BGPv1,
		},
		{
			name:        "Disabled to BGPv2",
			initialMode: mode.Disabled,
			ciliumNode: &v2.CiliumNode{
				ObjectMeta: metav1.ObjectMeta{
					Name: "Test Node",
					Labels: map[string]string{
						"bgp-policy": "a",
					},
				},
			},
			policy: nil,
			bgpNodeConfig: &v2.CiliumBGPNodeConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name: "Test Node",
				},
			},
			expectedMode: mode.BGPv2,
		},
		{
			name:        "BGPv1 to BGPv2",
			initialMode: mode.BGPv1,
			ciliumNode: &v2.CiliumNode{
				ObjectMeta: metav1.ObjectMeta{
					Name: "Test Node",
					Labels: map[string]string{
						"bgp-policy": "a",
					},
				},
			},
			policy: nil,
			bgpNodeConfig: &v2.CiliumBGPNodeConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name: "Test Node",
				},
			},
			expectedMode: mode.BGPv2,
		},
		{
			name:        "BGPv2 to BGPv1, BGPNodeConfig present",
			initialMode: mode.BGPv2,
			ciliumNode: &v2.CiliumNode{
				ObjectMeta: metav1.ObjectMeta{
					Name: "Test Node",
					Labels: map[string]string{
						"bgp-policy": "a",
					},
				},
			},
			policy: &v2alpha1.CiliumBGPPeeringPolicy{
				Spec: v2alpha1.CiliumBGPPeeringPolicySpec{
					NodeSelector: &v1.LabelSelector{
						MatchLabels: map[string]string{
							"bgp-policy": "a",
						},
					},
				},
			},
			bgpNodeConfig: &v2.CiliumBGPNodeConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name: "Test Node",
				},
			},
			expectedMode: mode.BGPv1,
		},
		{
			name:        "BGPv2 to BGPv1, BGPNodeConfig removed",
			initialMode: mode.BGPv2,
			ciliumNode: &v2.CiliumNode{
				ObjectMeta: metav1.ObjectMeta{
					Name: "Test Node",
					Labels: map[string]string{
						"bgp-policy": "a",
					},
				},
			},
			policy: &v2alpha1.CiliumBGPPeeringPolicy{
				Spec: v2alpha1.CiliumBGPPeeringPolicySpec{
					NodeSelector: &v1.LabelSelector{
						MatchLabels: map[string]string{
							"bgp-policy": "a",
						},
					},
				},
			},
			bgpNodeConfig: nil,
			expectedMode:  mode.BGPv1,
		},
		{
			name:        "BGPv1 to disabled",
			initialMode: mode.BGPv1,
			ciliumNode: &v2.CiliumNode{
				ObjectMeta: metav1.ObjectMeta{
					Name: "Test Node",
					Labels: map[string]string{
						"bgp-policy": "a",
					},
				},
			},
			policy:        nil,
			bgpNodeConfig: nil,
			expectedMode:  mode.Disabled,
		},
		{
			name:        "BGPv2 to disabled",
			initialMode: mode.BGPv2,
			ciliumNode: &v2.CiliumNode{
				ObjectMeta: metav1.ObjectMeta{
					Name: "Test Node",
					Labels: map[string]string{
						"bgp-policy": "a",
					},
				},
			},
			policy:        nil,
			bgpNodeConfig: nil,
			expectedMode:  mode.Disabled,
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			mockStore := store.NewMockBGPCPResourceStore[*v2.CiliumBGPNodeConfig]()
			if tt.bgpNodeConfig != nil {
				mockStore.Upsert(tt.bgpNodeConfig)
			}

			policyLister := func() ([]*v2alpha1.CiliumBGPPeeringPolicy, error) {
				if tt.policy == nil {
					return []*v2alpha1.CiliumBGPPeeringPolicy{}, nil
				}
				return []*v2alpha1.CiliumBGPPeeringPolicy{tt.policy}, nil
			}

			cm := mode.NewConfigMode()
			cm.Set(tt.initialMode)

			c := agent.Controller{
				PolicyLister: &agent.MockCiliumBGPPeeringPolicyLister{
					List_: policyLister,
				},
				BGPMgr: &mock.MockBGPRouterManager{
					ConfigurePeers_: func(_ context.Context, p *v2alpha1.CiliumBGPPeeringPolicy, n *v2.CiliumNode) error {
						return nil
					},
					ReconcileInstances_: func(ctx context.Context, bgpnc *v2.CiliumBGPNodeConfig, ciliumNode *v2.CiliumNode) error {
						return nil
					},
				},
				LocalCiliumNode:    tt.ciliumNode,
				BGPNodeConfigStore: mockStore,
				ConfigMode:         cm,
			}

			err := c.Reconcile(context.Background())
			require.NoError(t, err)

			require.Equal(t, tt.expectedMode, cm.Get())
		})
	}
}
