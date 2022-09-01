// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package agent_test

import (
	"context"
	"errors"
	"net"
	"testing"

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

// a mock agent.nodeSpecer implementation.
type fakeNodeSpecer struct {
	PodCIDRs_    func() ([]string, error)
	Labels_      func() (map[string]string, error)
	Annotations_ func() (map[string]string, error)
}

func (f *fakeNodeSpecer) PodCIDRs() ([]string, error) {
	return f.PodCIDRs_()
}

func (f *fakeNodeSpecer) Labels() (map[string]string, error) {
	return f.Labels_()
}

func (f *fakeNodeSpecer) Annotations() (map[string]string, error) {
	return f.Annotations_()
}

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
		labels      func() (map[string]string, error)
		annotations func() (map[string]string, error)
		podCIDRs    func() ([]string, error)
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
			labels: func() (map[string]string, error) {
				return map[string]string{
					"bgp-policy": "a",
				}, nil
			},
			annotations: func() (map[string]string, error) {
				return map[string]string{}, nil
			},
			podCIDRs: func() ([]string, error) {
				return []string{}, nil
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
			name: "podcidr listing error",
			plist: func(_ k8sLabels.Selector) (ret []*v2alpha1api.CiliumBGPPeeringPolicy, err error) {
				return []*v2alpha1api.CiliumBGPPeeringPolicy{wantPolicy}, nil
			},
			labels: func() (map[string]string, error) {
				return map[string]string{
					"bgp-policy": "a",
				}, nil
			},
			annotations: func() (map[string]string, error) {
				return map[string]string{}, nil
			},
			podCIDRs: func() ([]string, error) {
				return []string{}, errors.New("")
			},
			err: errors.New(""),
		},
		{
			name: "annotations listing error",
			plist: func(_ k8sLabels.Selector) (ret []*v2alpha1api.CiliumBGPPeeringPolicy, err error) {
				return []*v2alpha1api.CiliumBGPPeeringPolicy{wantPolicy}, nil
			},
			labels: func() (map[string]string, error) {
				return map[string]string{
					"bgp-policy": "a",
				}, nil
			},
			annotations: func() (map[string]string, error) {
				return map[string]string{}, errors.New("")
			},
			podCIDRs: func() ([]string, error) {
				return []string{}, nil
			},
			err: errors.New(""),
		},
		{
			name: "label listening error",
			plist: func(_ k8sLabels.Selector) (ret []*v2alpha1api.CiliumBGPPeeringPolicy, err error) {
				return []*v2alpha1api.CiliumBGPPeeringPolicy{wantPolicy}, nil
			},
			labels: func() (map[string]string, error) {
				return map[string]string{
					"bgp-policy": "a",
				}, errors.New("")
			},
			annotations: func() (map[string]string, error) {
				return map[string]string{}, nil
			},
			podCIDRs: func() ([]string, error) {
				return []string{}, nil
			},
			err: errors.New(""),
		},
		{
			name: "policy list error",
			plist: func(_ k8sLabels.Selector) (ret []*v2alpha1api.CiliumBGPPeeringPolicy, err error) {
				return nil, errors.New("")
			},
			labels: func() (map[string]string, error) {
				return map[string]string{
					"bgp-policy": "a",
				}, nil
			},
			annotations: func() (map[string]string, error) {
				return map[string]string{}, nil
			},
			podCIDRs: func() ([]string, error) {
				return []string{}, nil
			},
			err: errors.New(""),
		}, {
			name: "configure peers error",
			plist: func(_ k8sLabels.Selector) (ret []*v2alpha1api.CiliumBGPPeeringPolicy, err error) {
				return []*v2alpha1api.CiliumBGPPeeringPolicy{wantPolicy}, nil
			},
			labels: func() (map[string]string, error) {
				return map[string]string{
					"bgp-policy": "a",
				}, nil
			},
			annotations: func() (map[string]string, error) {
				return map[string]string{}, nil
			},
			podCIDRs: func() ([]string, error) {
				return []string{}, nil
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
			nodeSpecer := &fakeNodeSpecer{
				Annotations_: tt.annotations,
				Labels_:      tt.labels,
				PodCIDRs_:    tt.podCIDRs,
			}
			policyLister := &mock.MockCiliumBGPPeeringPolicyLister{
				List_: tt.plist,
			}
			rtmgr := &mock.MockBGPRouterManager{
				ConfigurePeers_: tt.configurePeers,
			}
			c := agent.Controller{
				NodeSpec:     nodeSpecer,
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
			policy, err := agent.PolicySelection(context.Background(), tt.nodeLabels, policies)
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
