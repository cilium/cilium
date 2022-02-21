// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package agent_test

import (
	"context"
	"errors"
	"net"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sLabels "k8s.io/apimachinery/pkg/labels"

	"github.com/cilium/cilium/pkg/bgpv1/agent"
	"github.com/cilium/cilium/pkg/bgpv1/mock"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	nodeaddr "github.com/cilium/cilium/pkg/node"
	nodetypes "github.com/cilium/cilium/pkg/node/types"
)

var (
	// the standard node name we'll use throughout our tests.
	nodeName = "node-under-test-01"
	nodeIPv4 = net.ParseIP("192.168.0.1")
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
	var wantNode = &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				"bgp-policy": "a",
			},
		},
	}
	var table = []struct {
		// name of test case
		name string
		// a mock Get method for the controller's NodeLister
		get func(string) (*corev1.Node, error)
		// a mock List method for the controller's PolicyLister
		plist func(k8sLabels.Selector) (ret []*v2alpha1api.CiliumBGPPeeringPolicy, err error)
		// a mock ConfigurePeers method for the controller's BGPRouterManager
		configurePeers func(context.Context, *v2alpha1api.CiliumBGPPeeringPolicy, *agent.ControlPlaneState) error
		// error nil or not
		err error
	}{
		// test the normal control flow of a policy being selected and applied.
		{
			name: "successful reconcile",
			get: func(node string) (*corev1.Node, error) {
				if node != nodeName {
					t.Fatalf("got: %v, want: %v", node, nodeName)
				}
				return wantNode, nil
			},
			plist: func(_ k8sLabels.Selector) (ret []*v2alpha1api.CiliumBGPPeeringPolicy, err error) {
				return []*v2alpha1api.CiliumBGPPeeringPolicy{wantPolicy}, nil
			},
			configurePeers: func(_ context.Context, p *v2alpha1api.CiliumBGPPeeringPolicy, c *agent.ControlPlaneState) error {
				// pointer check, not deep equal
				if p != wantPolicy {
					t.Fatalf("got: %+v, want: %+v", p, wantPolicy)
				}
				if !c.IPv4.Equal(nodeIPv4) {
					t.Fatalf("got: %v, want: %v", c.IPv4, nodeIPv4)
				}
				return nil
			},
			err: nil,
		},
		// follow tests demonstrate proper error handling when dependencies
		// return errors.
		//
		// make use of nil function pointer dereferences to indicate a dependency
		// was called erroneously
		{
			name: "node lister error",
			get: func(node string) (*corev1.Node, error) {
				if node != nodeName {
					t.Fatalf("got: %v, want: %v", node, nodeName)
				}
				return nil, errors.New("")
			},
			err: errors.New(""),
		},
		{
			name: "policy list error",
			get: func(node string) (*corev1.Node, error) {
				if node != nodeName {
					t.Fatalf("got: %v, want: %v", node, nodeName)
				}
				return wantNode, nil
			},
			plist: func(_ k8sLabels.Selector) (ret []*v2alpha1api.CiliumBGPPeeringPolicy, err error) {
				return nil, errors.New("")
			},
			err: errors.New(""),
		}, {
			name: "configure peers error",
			get: func(node string) (*corev1.Node, error) {
				if node != nodeName {
					t.Fatalf("got: %v, want: %v", node, nodeName)
				}
				return wantNode, nil
			},
			plist: func(_ k8sLabels.Selector) (ret []*v2alpha1api.CiliumBGPPeeringPolicy, err error) {
				return []*v2alpha1api.CiliumBGPPeeringPolicy{wantPolicy}, nil
			},
			configurePeers: func(_ context.Context, p *v2alpha1api.CiliumBGPPeeringPolicy, c *agent.ControlPlaneState) error {
				return errors.New("")
			},
			err: errors.New(""),
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			nodeaddr.SetIPv4(nodeIPv4)
			nodetypes.SetName(nodeName)

			nodeLister := &mock.MockNodeLister{
				Get_: tt.get,
			}
			policyLister := &mock.MockCiliumBGPPeeringPolicyLister{
				List_: tt.plist,
			}
			rtmgr := &mock.MockBGPRouterManager{
				ConfigurePeers_: tt.configurePeers,
			}
			c := agent.Controller{
				NodeLister:   nodeLister,
				PolicyLister: policyLister,
				BGPMgr:       rtmgr,
			}
			err := c.Reconcile(context.Background())
			if (tt.err == nil) != (err == nil) {
				t.Fatalf("wanted error: %v", tt.err == nil)
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
			// expand tt.nodeLabel into a corev1.Node
			node := &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Labels: tt.nodeLabels,
				},
			}
			// expand anon policies into CiliumBGPPeeringPolicy, make note of wanted
			var policies []*v2alpha1api.CiliumBGPPeeringPolicy
			var want *v2alpha1api.CiliumBGPPeeringPolicy
			for _, p := range tt.policies {
				policy := &v2alpha1api.CiliumBGPPeeringPolicy{
					Spec: v2alpha1api.CiliumBGPPeeringPolicySpec{
						NodeSelector: p.selector,
					},
				}
				policies = append(policies, policy)
				if p.want == true {
					want = policy
				}
			}
			// call function under test
			policy, err := agent.PolicySelection(context.Background(), node, policies)
			if (tt.err == nil) != (err == nil) {
				t.Fatalf("expected err: %v", (tt.err == nil))
			}
			if want != nil {
				// pointer comparison, not a deep equal.
				if policy != want {
					t.Fatalf("got: %+v, want: %+v", *policy, *want)
				}
			}
		})
	}
}
