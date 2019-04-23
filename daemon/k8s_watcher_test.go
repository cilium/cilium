// Copyright 2017-2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package main

import (
	"github.com/cilium/cilium/pkg/checker"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/fake"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"

	. "gopkg.in/check.v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sTypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
)

func (ds *DaemonSuite) Test_addCiliumNetworkPolicyV2(c *C) {
	// ciliumV2Store cache.Store, oldRules api.Rules, cnp *cilium_v2.CiliumNetworkPolicy

	uuid := k8sTypes.UID("13bba160-ddca-13e8-b697-0800273b04ff")
	type args struct {
		ciliumV2Store cache.Store
		cnp           *types.SlimCNP
		repo          *policy.Repository
	}
	type wanted struct {
		err  error
		repo *policy.Repository
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWanted func() wanted
	}{
		{
			name: "simple policy added",
			setupArgs: func() args {
				return args{
					ciliumV2Store: &cache.FakeCustomStore{},
					cnp: &types.SlimCNP{
						CiliumNetworkPolicy: &v2.CiliumNetworkPolicy{
							ObjectMeta: metav1.ObjectMeta{
								Name:      "db",
								Namespace: "production",
								UID:       uuid,
							},
							Spec: &api.Rule{
								EndpointSelector: api.EndpointSelector{
									LabelSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"env": "cluster-1",
										},
									},
								},
							},
						},
					},
					repo: policy.NewPolicyRepository(),
				}
			},
			setupWanted: func() wanted {
				r := policy.NewPolicyRepository()
				r.AddList(api.Rules{
					api.NewRule().
						WithEndpointSelector(api.EndpointSelector{
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"env": "cluster-1",
									labels.LabelSourceK8s + "." + k8sConst.PodNamespaceLabel: "production",
								},
							},
						}).
						WithIngressRules(nil).
						WithEgressRules(nil).
						WithLabels(utils.GetPolicyLabels(
							"production",
							"db",
							uuid,
							utils.ResourceTypeCiliumNetworkPolicy),
						),
				})
				return wanted{
					err:  nil,
					repo: r,
				}
			},
		},
		{
			name: "have a rule with user labels and update it without user labels, all other rules should be deleted",
			setupArgs: func() args {
				r := policy.NewPolicyRepository()
				lbls := utils.GetPolicyLabels("production", "db", uuid, utils.ResourceTypeCiliumNetworkPolicy)
				lbls = append(lbls, labels.ParseLabelArray("foo=bar")...).Sort()
				r.AddList(api.Rules{
					{
						EndpointSelector: api.EndpointSelector{
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"env": "cluster-1",
									labels.LabelSourceK8s + "." + k8sConst.PodNamespaceLabel: "production",
								},
							},
						},
						Ingress:     nil,
						Egress:      nil,
						Labels:      lbls,
						Description: "",
					},
				})
				return args{
					ciliumV2Store: &cache.FakeCustomStore{},
					cnp: &types.SlimCNP{
						CiliumNetworkPolicy: &v2.CiliumNetworkPolicy{
							ObjectMeta: metav1.ObjectMeta{
								Name:      "db",
								Namespace: "production",
								UID:       uuid,
							},
							Spec: &api.Rule{
								EndpointSelector: api.EndpointSelector{
									LabelSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"env": "cluster-1",
										},
									},
								},
							},
						},
					},
					repo: r,
				}
			},
			setupWanted: func() wanted {
				r := policy.NewPolicyRepository()
				r.AddList(api.Rules{
					api.NewRule().
						WithEndpointSelector(api.EndpointSelector{
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"env": "cluster-1",
									labels.LabelSourceK8s + "." + k8sConst.PodNamespaceLabel: "production",
								},
							},
						}).
						WithIngressRules(nil).
						WithEgressRules(nil).
						WithLabels(utils.GetPolicyLabels(
							"production",
							"db",
							uuid,
							utils.ResourceTypeCiliumNetworkPolicy,
						)),
				})
				return wanted{
					err:  nil,
					repo: r,
				}
			},
		},
		{
			name: "have a rule without user labels and update it with user labels, all other rules should be deleted",
			setupArgs: func() args {
				r := policy.NewPolicyRepository()
				r.AddList(api.Rules{
					{
						EndpointSelector: api.EndpointSelector{
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"env": "cluster-1",
									labels.LabelSourceK8s + "." + k8sConst.PodNamespaceLabel: "production",
								},
							},
						},
						Ingress:     nil,
						Egress:      nil,
						Labels:      utils.GetPolicyLabels("production", "db", uuid, utils.ResourceTypeCiliumNetworkPolicy),
						Description: "",
					},
				})
				return args{
					ciliumV2Store: &cache.FakeCustomStore{},
					cnp: &types.SlimCNP{
						CiliumNetworkPolicy: &v2.CiliumNetworkPolicy{
							ObjectMeta: metav1.ObjectMeta{
								Name:      "db",
								Namespace: "production",
								UID:       uuid,
							},
							Spec: &api.Rule{
								EndpointSelector: api.EndpointSelector{
									LabelSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"env": "cluster-1",
										},
									},
								},
								Labels: labels.ParseLabelArray("foo=bar"),
							},
						},
					},
					repo: r,
				}
			},
			setupWanted: func() wanted {
				r := policy.NewPolicyRepository()
				lbls := utils.GetPolicyLabels("production", "db", uuid, utils.ResourceTypeCiliumNetworkPolicy)
				lbls = append(lbls, labels.ParseLabelArray("foo=bar")...).Sort()
				r.AddList(api.Rules{
					api.NewRule().
						WithEndpointSelector(api.EndpointSelector{
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"env": "cluster-1",
									labels.LabelSourceK8s + "." + k8sConst.PodNamespaceLabel: "production",
								},
							},
						}).
						WithIngressRules(nil).
						WithEgressRules(nil).
						WithLabels(lbls),
				})
				return wanted{
					err:  nil,
					repo: r,
				}
			},
		},
		{
			name: "have a rule policy installed with multiple rules and apply an empty spec should delete all rules installed",
			setupArgs: func() args {
				r := policy.NewPolicyRepository()
				r.AddList(api.Rules{
					{
						EndpointSelector: api.EndpointSelector{
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"env": "cluster-1",
									labels.LabelSourceK8s + "." + k8sConst.PodNamespaceLabel: "production",
								},
							},
						},
						Ingress: []api.IngressRule{
							{
								FromEndpoints: []api.EndpointSelector{
									{
										LabelSelector: &metav1.LabelSelector{
											MatchLabels: map[string]string{
												"env": "cluster-1",
												labels.LabelSourceK8s + "." + k8sConst.PodNamespaceLabel: "production",
											},
										},
									},
								},
							},
						},
						Egress:      nil,
						Labels:      utils.GetPolicyLabels("production", "db", uuid, utils.ResourceTypeCiliumNetworkPolicy),
						Description: "",
					},
				})
				return args{
					ciliumV2Store: &cache.FakeCustomStore{},
					cnp: &types.SlimCNP{
						CiliumNetworkPolicy: &v2.CiliumNetworkPolicy{
							ObjectMeta: metav1.ObjectMeta{
								Name:      "db",
								Namespace: "production",
								UID:       uuid,
							},
						},
					},
					repo: r,
				}
			},
			setupWanted: func() wanted {
				r := policy.NewPolicyRepository()
				r.AddList(api.Rules{})
				return wanted{
					err:  nil,
					repo: r,
				}
			},
		},
	}
	for _, tt := range tests {
		args := tt.setupArgs()
		want := tt.setupWanted()
		ds.d.policy = args.repo
		err := ds.d.addCiliumNetworkPolicyV2(&fake.Clientset{}, args.ciliumV2Store, args.cnp)
		c.Assert(err, checker.DeepEquals, want.err, Commentf("Test name: %q", tt.name))
		c.Assert(ds.d.policy.GetRulesList().Policy, checker.DeepEquals, want.repo.GetRulesList().Policy, Commentf("Test name: %q", tt.name))
	}
}
