// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policycell

import (
	"context"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sTypes "k8s.io/apimachinery/pkg/types"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcachetypes "github.com/cilium/cilium/pkg/ipcache/types"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/policy"
	policyapi "github.com/cilium/cilium/pkg/policy/api"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
)

type fakeEPM struct {
	regen   *set.Set[identity.NumericIdentity]
	fromRev uint64
	toRev   uint64
}

func (m *fakeEPM) UpdatePolicy(idsToRegen *set.Set[identity.NumericIdentity], fromRev, toRev uint64) {
	m.regen = idsToRegen
	m.fromRev = fromRev
	m.toRev = toRev

}

type fakeipcache struct {
	waited  bool
	added   set.Set[string]
	removed set.Set[string]
}

func (ipc *fakeipcache) UpsertMetadataBatch(updates ...ipcache.MU) (revision uint64) {
	ipc.added = set.Set[string]{}
	for _, update := range updates {
		ipc.added.Insert(update.Prefix.String())
	}
	return 2
}
func (ipc *fakeipcache) RemoveMetadataBatch(updates ...ipcache.MU) (revision uint64) {
	ipc.removed = set.Set[string]{}
	for _, update := range updates {
		ipc.removed.Insert(update.Prefix.String())
	}
	return 2
}
func (ipc *fakeipcache) WaitForRevision(ctx context.Context, rev uint64) error {
	ipc.waited = true
	return nil
}

func TestAddReplaceRemoveRule(t *testing.T) {
	resource := ipcachetypes.ResourceID("resourceid")
	epm := &fakeEPM{}
	ipc := &fakeipcache{}

	ids := identity.IdentityMap{
		100: labels.LabelArray{
			{
				Source: labels.LabelSourceK8s,
				Key:    "id",
				Value:  "100",
			},
		},
		101: labels.LabelArray{
			{
				Source: labels.LabelSourceK8s,
				Key:    "id",
				Value:  "101",
			},
		},
		102: labels.LabelArray{
			{
				Source: labels.LabelSourceK8s,
				Key:    "id",
				Value:  "102",
			},
		},
	}

	pi := &policyImporter{
		log:  slog.Default(),
		repo: policy.NewPolicyRepository(hivetest.Logger(t), ids, nil, nil, nil, policyapi.NewPolicyMetricsNoop()),
		epm:  epm,
		ipc:  ipc,

		q: make(chan *policytypes.PolicyUpdate, 10),

		prefixesByResource: map[ipcachetypes.ResourceID][]netip.Prefix{},
	}
	pi.repo.GetSelectorCache().SetLocalIdentityNotifier(testidentity.NewDummyIdentityNotifier())

	writeRule := func(r *policyapi.Rule) uint64 {
		t.Helper()

		require.NoError(t, r.Sanitize())

		dc := make(chan uint64, 1)
		pi.processUpdates(context.Background(), []*policytypes.PolicyUpdate{
			{
				Rules:    []*policyapi.Rule{r},
				Resource: resource,
				DoneChan: dc,
			},
		})
		return <-dc
	}

	rev := writeRule(policyapi.NewRule().
		WithEndpointSelector(policyapi.NewESFromK8sLabelSelector("",
			&slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"id": "100",
				},
			}),
		).
		WithEgressRules([]policyapi.EgressRule{{
			EgressCommonRule: policyapi.EgressCommonRule{
				ToCIDR: policyapi.CIDRSlice{"1.0.1.0/24"},
			}}}))

	// Check that prefix was allocated
	require.True(t, ipc.waited)
	require.ElementsMatch(t, ipc.added.AsSlice(), []string{"1.0.1.0/24"})
	require.Empty(t, ipc.removed.AsSlice())

	// Check that the right endpoints were updated
	require.Equal(t, rev, epm.toRev)
	require.ElementsMatch(t, epm.regen.AsSlice(), []identity.NumericIdentity{100})

	// Update to new rule that selects id 102 and has two prefixes
	// we should see 1 new prefix, and 2 regenerated endpoints
	rev = writeRule(policyapi.NewRule().
		WithEndpointSelector(policyapi.NewESFromK8sLabelSelector("",
			&slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"id": "101",
				},
			}),
		).
		WithEgressRules([]policyapi.EgressRule{{
			EgressCommonRule: policyapi.EgressCommonRule{
				ToCIDR: policyapi.CIDRSlice{"1.0.1.0/24", "1.0.2.0/24"},
			}}}))

	require.True(t, ipc.waited)
	// We only allocate 1 new cidr
	require.ElementsMatch(t, ipc.added.AsSlice(), []string{"1.0.2.0/24"})
	require.Empty(t, ipc.removed.AsSlice())

	require.ElementsMatch(t, pi.prefixesByResource[resource], []netip.Prefix{
		netip.MustParsePrefix("1.0.1.0/24"),
		netip.MustParsePrefix("1.0.2.0/24"),
	})

	// Check that the right endpoints were updated
	require.Equal(t, rev, epm.toRev)
	require.ElementsMatch(t, epm.regen.AsSlice(), []identity.NumericIdentity{100, 101})

	// Swap endpoints and prefixes
	rev = writeRule(policyapi.NewRule().
		WithEndpointSelector(policyapi.NewESFromK8sLabelSelector("",
			&slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"id": "102",
				},
			}),
		).
		WithEgressRules([]policyapi.EgressRule{{
			EgressCommonRule: policyapi.EgressCommonRule{
				ToCIDR: policyapi.CIDRSlice{"2.0.0.0/24"},
			}}}))

	require.True(t, ipc.waited)
	// We only allocate 1 new cidr
	require.ElementsMatch(t, ipc.removed.AsSlice(), []string{"1.0.1.0/24", "1.0.2.0/24"})
	require.ElementsMatch(t, ipc.added.AsSlice(), []string{"2.0.0.0/24"})

	// Check that the right endpoints were updated
	require.Equal(t, rev, epm.toRev)
	require.ElementsMatch(t, epm.regen.AsSlice(), []identity.NumericIdentity{101, 102})

}

// This test is ported over from the daemon test suite. Apologies if it seems a bit awkward.
// It tests the local-api-only label replacement.
func TestAddCiliumNetworkPolicyByLabels(t *testing.T) {
	uuid := k8sTypes.UID("13bba160-ddca-13e8-b697-0800273b04ff")
	type args struct {
		cnp  *types.SlimCNP
		repo policy.PolicyRepository
	}
	type wanted struct {
		err  error
		repo policy.PolicyRepository
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
					cnp: &types.SlimCNP{
						CiliumNetworkPolicy: &v2.CiliumNetworkPolicy{
							ObjectMeta: metav1.ObjectMeta{
								Name:      "db",
								Namespace: "production",
								UID:       uuid,
							},
							Spec: &policyapi.Rule{
								EndpointSelector: policyapi.EndpointSelector{
									LabelSelector: &slim_metav1.LabelSelector{
										MatchLabels: map[string]string{
											"env": "cluster-1",
										},
									},
								},
								Ingress: []policyapi.IngressRule{{}},
								Egress:  nil,
							},
						},
					},
					repo: policy.NewPolicyRepository(hivetest.Logger(t), nil, nil, nil, nil, policyapi.NewPolicyMetricsNoop()),
				}
			},
			setupWanted: func() wanted {
				r := policy.NewPolicyRepository(hivetest.Logger(t), nil, nil, nil, nil, policyapi.NewPolicyMetricsNoop())
				r.MustAddList(policyapi.Rules{
					policyapi.NewRule().
						WithEndpointSelector(policyapi.EndpointSelector{
							LabelSelector: &slim_metav1.LabelSelector{
								MatchLabels: map[string]string{
									"env": "cluster-1",
									labels.LabelSourceK8s + "." + k8sConst.PodNamespaceLabel: "production",
								},
							},
						}).
						WithIngressRules([]policyapi.IngressRule{{}}).
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
				r := policy.NewPolicyRepository(hivetest.Logger(t), nil, nil, nil, nil, policyapi.NewPolicyMetricsNoop())
				lbls := utils.GetPolicyLabels("production", "db", uuid, utils.ResourceTypeCiliumNetworkPolicy)
				lbls = append(lbls, labels.ParseLabelArray("foo=bar")...).Sort()
				r.MustAddList(policyapi.Rules{
					{
						EndpointSelector: policyapi.EndpointSelector{
							LabelSelector: &slim_metav1.LabelSelector{
								MatchLabels: map[string]string{
									"env": "cluster-1",
									labels.LabelSourceK8s + "." + k8sConst.PodNamespaceLabel: "production",
								},
							},
						},
						Ingress:     []policyapi.IngressRule{{}},
						Egress:      []policyapi.EgressRule{{}},
						Labels:      lbls,
						Description: "",
					},
				})
				return args{
					cnp: &types.SlimCNP{
						CiliumNetworkPolicy: &v2.CiliumNetworkPolicy{
							ObjectMeta: metav1.ObjectMeta{
								Name:      "db",
								Namespace: "production",
								UID:       uuid,
							},
							Spec: &policyapi.Rule{
								EndpointSelector: policyapi.EndpointSelector{
									LabelSelector: &slim_metav1.LabelSelector{
										MatchLabels: map[string]string{
											"env": "cluster-1",
										},
									},
								},
								Ingress: []policyapi.IngressRule{{}},
								Egress:  nil,
							},
						},
					},
					repo: r,
				}
			},
			setupWanted: func() wanted {
				r := policy.NewPolicyRepository(hivetest.Logger(t), nil, nil, nil, nil, policyapi.NewPolicyMetricsNoop())
				r.MustAddList(policyapi.Rules{
					policyapi.NewRule().
						WithEndpointSelector(policyapi.EndpointSelector{
							LabelSelector: &slim_metav1.LabelSelector{
								MatchLabels: map[string]string{
									"env": "cluster-1",
									labels.LabelSourceK8s + "." + k8sConst.PodNamespaceLabel: "production",
								},
							},
						}).
						WithIngressRules([]policyapi.IngressRule{{}}).
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
				r := policy.NewPolicyRepository(hivetest.Logger(t), nil, nil, nil, nil, policyapi.NewPolicyMetricsNoop())
				r.MustAddList(policyapi.Rules{
					{
						EndpointSelector: policyapi.EndpointSelector{
							LabelSelector: &slim_metav1.LabelSelector{
								MatchLabels: map[string]string{
									"env": "cluster-1",
									labels.LabelSourceK8s + "." + k8sConst.PodNamespaceLabel: "production",
								},
							},
						},
						Ingress:     []policyapi.IngressRule{{}},
						Egress:      []policyapi.EgressRule{{}},
						Labels:      utils.GetPolicyLabels("production", "db", uuid, utils.ResourceTypeCiliumNetworkPolicy),
						Description: "",
					},
				})
				return args{
					cnp: &types.SlimCNP{
						CiliumNetworkPolicy: &v2.CiliumNetworkPolicy{
							ObjectMeta: metav1.ObjectMeta{
								Name:      "db",
								Namespace: "production",
								UID:       uuid,
							},
							Spec: &policyapi.Rule{
								EndpointSelector: policyapi.EndpointSelector{
									LabelSelector: &slim_metav1.LabelSelector{
										MatchLabels: map[string]string{
											"env": "cluster-1",
										},
									},
								},
								Labels:  labels.ParseLabelArray("foo=bar"),
								Ingress: []policyapi.IngressRule{{}},
							},
						},
					},
					repo: r,
				}
			},
			setupWanted: func() wanted {
				r := policy.NewPolicyRepository(hivetest.Logger(t), nil, nil, nil, nil, policyapi.NewPolicyMetricsNoop())
				lbls := utils.GetPolicyLabels("production", "db", uuid, utils.ResourceTypeCiliumNetworkPolicy)
				lbls = append(lbls, labels.ParseLabelArray("foo=bar")...).Sort()
				r.MustAddList(policyapi.Rules{
					policyapi.NewRule().
						WithEndpointSelector(policyapi.EndpointSelector{
							LabelSelector: &slim_metav1.LabelSelector{
								MatchLabels: map[string]string{
									"env": "cluster-1",
									labels.LabelSourceK8s + "." + k8sConst.PodNamespaceLabel: "production",
								},
							},
						}).
						WithIngressRules([]policyapi.IngressRule{{}}).
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
				r := policy.NewPolicyRepository(hivetest.Logger(t), nil, nil, nil, nil, policyapi.NewPolicyMetricsNoop())
				r.MustAddList(policyapi.Rules{
					{
						EndpointSelector: policyapi.EndpointSelector{
							LabelSelector: &slim_metav1.LabelSelector{
								MatchLabels: map[string]string{
									"env": "cluster-1",
									labels.LabelSourceK8s + "." + k8sConst.PodNamespaceLabel: "production",
								},
							},
						},
						Ingress: []policyapi.IngressRule{
							{
								IngressCommonRule: policyapi.IngressCommonRule{
									FromEndpoints: []policyapi.EndpointSelector{
										{
											LabelSelector: &slim_metav1.LabelSelector{
												MatchLabels: map[string]string{
													"env": "cluster-1",
													labels.LabelSourceK8s + "." + k8sConst.PodNamespaceLabel: "production",
												},
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
				r := policy.NewPolicyRepository(hivetest.Logger(t), nil, nil, nil, nil, policyapi.NewPolicyMetricsNoop())
				r.MustAddList(policyapi.Rules{
					{
						EndpointSelector: policyapi.EndpointSelector{
							LabelSelector: &slim_metav1.LabelSelector{
								MatchLabels: map[string]string{
									"env": "cluster-1",
									labels.LabelSourceK8s + "." + k8sConst.PodNamespaceLabel: "production",
								},
							},
						},
						Ingress: []policyapi.IngressRule{
							{
								IngressCommonRule: policyapi.IngressCommonRule{
									FromEndpoints: []policyapi.EndpointSelector{
										{
											LabelSelector: &slim_metav1.LabelSelector{
												MatchLabels: map[string]string{
													"env": "cluster-1",
													labels.LabelSourceK8s + "." + k8sConst.PodNamespaceLabel: "production",
												},
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
				return wanted{
					err:  v2.ErrEmptyCNP,
					repo: r,
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := tt.setupArgs()
			want := tt.setupWanted()

			args.repo.GetSelectorCache().SetLocalIdentityNotifier(testidentity.NewDummyIdentityNotifier())
			want.repo.GetSelectorCache().SetLocalIdentityNotifier(testidentity.NewDummyIdentityNotifier())

			rules, policyImportErr := args.cnp.Parse(hivetest.Logger(t), cmtypes.PolicyAnyCluster)
			require.Equal(t, want.err, policyImportErr)

			// Only add policies if we have successfully parsed them. Otherwise, if
			// parsing fails, `rules` is nil, which would wipe out the repo.
			if want.err != nil {
				return
			}

			pi := &policyImporter{
				log:  slog.Default(),
				repo: args.repo,
			}

			pi.processUpdates(context.Background(), []*policytypes.PolicyUpdate{{
				Rules:             rules,
				ReplaceWithLabels: args.cnp.GetIdentityLabels(),
				Source:            metrics.LabelEventSourceK8s,
			}})

			require.Equalf(t, want.repo.GetRulesList().Policy, args.repo.GetRulesList().Policy, "Test name: %q", tt.name)
		})
	}
}
