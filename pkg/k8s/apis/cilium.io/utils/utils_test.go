// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utils

import (
	"fmt"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"

	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
)

func Test_namespacesAreValid(t *testing.T) {
	require.True(t, namespacesAreValid("default", []string{}))
	require.True(t, namespacesAreValid("default", []string{"default"}))
	require.False(t, namespacesAreValid("default", []string{"foo"}))
	require.False(t, namespacesAreValid("default", []string{"default", "foo"}))
}

func Test_ParseToCiliumRule(t *testing.T) {
	role := fmt.Sprintf("%s.role", labels.LabelSourceAny)
	namespace := fmt.Sprintf("%s.%s", labels.LabelSourceK8s, k8sConst.PodNamespaceLabel)
	uuid := types.UID("11bba160-ddca-11e8-b697-0800273b04ff")
	type args struct {
		namespace      string
		clusterName    string
		rule           *api.Rule
		uid            types.UID
		overrideConfig func()
	}
	tests := []struct {
		name string
		args args
		want *api.Rule
	}{
		{
			// When the rule has no namespace match, the namespace
			// is inherited from the namespace where the rule is
			// added.
			name: "parse-in-namespace",
			args: args{
				namespace: slim_metav1.NamespaceDefault,
				uid:       uuid,
				rule: &api.Rule{
					EndpointSelector: api.NewESFromMatchRequirements(
						map[string]string{
							role: "backend",
						},
						nil,
					),
				},
			},
			want: api.NewRule().WithEndpointSelector(
				api.NewESFromMatchRequirements(
					map[string]string{
						role:      "backend",
						namespace: "default",
					},
					nil,
				),
			).WithLabels(
				labels.LabelArray{
					{
						Key:    "io.cilium.k8s.policy.derived-from",
						Value:  "CiliumNetworkPolicy",
						Source: labels.LabelSourceK8s,
					},
					{
						Key:    "io.cilium.k8s.policy.name",
						Value:  "parse-in-namespace",
						Source: labels.LabelSourceK8s,
					},
					{
						Key:    "io.cilium.k8s.policy.namespace",
						Value:  "default",
						Source: labels.LabelSourceK8s,
					},
					{
						Key:    "io.cilium.k8s.policy.uid",
						Value:  string(uuid),
						Source: labels.LabelSourceK8s,
					},
				},
			),
		},
		{
			// When the rule specifies a namespace, it is overridden
			// by the namespace where the rule was inserted.
			name: "parse-in-namespace-with-ns-selector",
			args: args{
				namespace: slim_metav1.NamespaceDefault,
				uid:       uuid,
				rule: &api.Rule{
					EndpointSelector: api.NewESFromMatchRequirements(
						map[string]string{
							role:      "backend",
							namespace: "foo",
						},
						nil,
					),
				},
			},
			want: api.NewRule().WithEndpointSelector(
				api.NewESFromMatchRequirements(
					map[string]string{
						role:      "backend",
						namespace: "default",
					},
					nil,
				),
			).WithLabels(
				labels.LabelArray{
					{
						Key:    "io.cilium.k8s.policy.derived-from",
						Value:  "CiliumNetworkPolicy",
						Source: labels.LabelSourceK8s,
					},
					{
						Key:    "io.cilium.k8s.policy.name",
						Value:  "parse-in-namespace-with-ns-selector",
						Source: labels.LabelSourceK8s,
					},
					{
						Key:    "io.cilium.k8s.policy.namespace",
						Value:  "default",
						Source: labels.LabelSourceK8s,
					},
					{
						Key:    "io.cilium.k8s.policy.uid",
						Value:  string(uuid),
						Source: labels.LabelSourceK8s,
					},
				},
			),
		},
		{
			// Don't insert a namespace selection when the rule
			// is for init policies.
			name: "parse-init-policy",
			args: args{
				uid: uuid,
				rule: &api.Rule{
					EndpointSelector: api.NewESFromMatchRequirements(
						map[string]string{
							role:       "backend",
							podInitLbl: "",
						},
						nil,
					),
				},
			},
			want: api.NewRule().WithEndpointSelector(
				api.NewESFromMatchRequirements(
					map[string]string{
						role:       "backend",
						podInitLbl: "",
						// No namespace because it's init.
						// namespace: "default",
					},
					nil,
				),
			).WithLabels(
				labels.LabelArray{
					{
						Key:    "io.cilium.k8s.policy.derived-from",
						Value:  "CiliumClusterwideNetworkPolicy",
						Source: labels.LabelSourceK8s,
					},
					{
						Key:    "io.cilium.k8s.policy.name",
						Value:  "parse-init-policy",
						Source: labels.LabelSourceK8s,
					},
					{
						Key:    "io.cilium.k8s.policy.uid",
						Value:  string(uuid),
						Source: labels.LabelSourceK8s,
					},
				},
			),
		},
		{
			// CNP with endpoint selectors should always select the
			// current namespace
			name: "parse-init-policy-namespaced",
			args: args{
				namespace: slim_metav1.NamespaceDefault,
				uid:       uuid,
				rule: &api.Rule{
					EndpointSelector: api.NewESFromMatchRequirements(
						nil,
						[]slim_metav1.LabelSelectorRequirement{
							{
								Key:      "reserved.init",
								Operator: slim_metav1.LabelSelectorOpDoesNotExist,
							},
						},
					),
					Ingress: []api.IngressRule{
						{
							IngressCommonRule: api.IngressCommonRule{
								FromEndpoints: []api.EndpointSelector{
									{
										LabelSelector: &slim_metav1.LabelSelector{},
									},
								},
							},
						},
					},
				},
			},
			want: api.NewRule().WithEndpointSelector(
				api.NewESFromMatchRequirements(
					map[string]string{
						namespace: "default",
					},
					[]slim_metav1.LabelSelectorRequirement{
						{
							Key:      "reserved.init",
							Operator: slim_metav1.LabelSelectorOpDoesNotExist,
						},
					},
				),
			).WithIngressRules(
				[]api.IngressRule{
					{
						IngressCommonRule: api.IngressCommonRule{
							FromEndpoints: []api.EndpointSelector{
								api.NewESFromK8sLabelSelector(
									labels.LabelSourceK8sKeyPrefix,
									&slim_metav1.LabelSelector{
										MatchLabels: map[string]string{
											k8sConst.PodNamespaceLabel: "default",
										},
									}),
							},
						},
					},
				},
			).WithLabels(
				labels.LabelArray{
					{
						Key:    "io.cilium.k8s.policy.derived-from",
						Value:  "CiliumNetworkPolicy",
						Source: labels.LabelSourceK8s,
					},
					{
						Key:    "io.cilium.k8s.policy.name",
						Value:  "parse-init-policy-namespaced",
						Source: labels.LabelSourceK8s,
					},
					{
						Key:    "io.cilium.k8s.policy.namespace",
						Value:  "default",
						Source: labels.LabelSourceK8s,
					},
					{
						Key:    "io.cilium.k8s.policy.uid",
						Value:  string(uuid),
						Source: labels.LabelSourceK8s,
					},
				},
			),
		},
		{
			name: "set-any-source-for-namespace",
			args: args{
				namespace: slim_metav1.NamespaceDefault,
				uid:       uuid,
				rule: &api.Rule{
					EndpointSelector: api.NewESFromMatchRequirements(
						map[string]string{
							role: "backend",
						},
						nil,
					),
					Ingress: []api.IngressRule{
						{
							IngressCommonRule: api.IngressCommonRule{
								FromEndpoints: []api.EndpointSelector{
									{
										LabelSelector: &slim_metav1.LabelSelector{
											MatchLabels: map[string]string{
												podAnyPrefixLbl: "ns-2",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: api.NewRule().WithEndpointSelector(
				api.NewESFromMatchRequirements(
					map[string]string{
						role:      "backend",
						namespace: "default",
					},
					nil,
				),
			).WithIngressRules(
				[]api.IngressRule{
					{
						IngressCommonRule: api.IngressCommonRule{
							FromEndpoints: []api.EndpointSelector{
								api.NewESFromK8sLabelSelector(
									labels.LabelSourceAnyKeyPrefix,
									&slim_metav1.LabelSelector{
										MatchLabels: map[string]string{
											k8sConst.PodNamespaceLabel: "ns-2",
										},
									}),
							},
						},
					},
				},
			).WithLabels(
				labels.LabelArray{
					{
						Key:    "io.cilium.k8s.policy.derived-from",
						Value:  "CiliumNetworkPolicy",
						Source: labels.LabelSourceK8s,
					},
					{
						Key:    "io.cilium.k8s.policy.name",
						Value:  "set-any-source-for-namespace",
						Source: labels.LabelSourceK8s,
					},
					{
						Key:    "io.cilium.k8s.policy.namespace",
						Value:  "default",
						Source: labels.LabelSourceK8s,
					},
					{
						Key:    "io.cilium.k8s.policy.uid",
						Value:  string(uuid),
						Source: labels.LabelSourceK8s,
					},
				},
			),
		},
		{
			name: "set-cluster-by-default",
			args: args{
				clusterName: "cluster1",
				namespace:   slim_metav1.NamespaceDefault,
				uid:         uuid,
				rule: &api.Rule{
					EndpointSelector: api.NewESFromMatchRequirements(
						map[string]string{
							role: "backend",
						},
						nil,
					),
					Ingress: []api.IngressRule{
						{
							IngressCommonRule: api.IngressCommonRule{
								FromEndpoints: []api.EndpointSelector{
									{
										LabelSelector: &slim_metav1.LabelSelector{
											MatchLabels: map[string]string{},
										},
									},
									{
										LabelSelector: &slim_metav1.LabelSelector{
											MatchLabels: map[string]string{
												clusterPrefixLbl: "cluster2",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: api.NewRule().WithEndpointSelector(
				api.NewESFromMatchRequirements(
					map[string]string{
						role:      "backend",
						namespace: "default",
					},
					nil,
				),
			).WithIngressRules(
				[]api.IngressRule{
					{
						IngressCommonRule: api.IngressCommonRule{
							FromEndpoints: []api.EndpointSelector{
								api.NewESFromK8sLabelSelector(
									labels.LabelSourceK8sKeyPrefix,
									&slim_metav1.LabelSelector{
										MatchLabels: map[string]string{
											k8sConst.PodNamespaceLabel:  "default",
											k8sConst.PolicyLabelCluster: "cluster1",
										},
									}),
								api.NewESFromK8sLabelSelector(
									labels.LabelSourceK8sKeyPrefix,
									&slim_metav1.LabelSelector{
										MatchLabels: map[string]string{
											k8sConst.PodNamespaceLabel:  "default",
											k8sConst.PolicyLabelCluster: "cluster2",
										},
									}),
							},
						},
					},
				},
			).WithLabels(
				labels.LabelArray{
					{
						Key:    "io.cilium.k8s.policy.derived-from",
						Value:  "CiliumNetworkPolicy",
						Source: labels.LabelSourceK8s,
					},
					{
						Key:    "io.cilium.k8s.policy.name",
						Value:  "set-cluster-by-default",
						Source: labels.LabelSourceK8s,
					},
					{
						Key:    "io.cilium.k8s.policy.namespace",
						Value:  "default",
						Source: labels.LabelSourceK8s,
					},
					{
						Key:    "io.cilium.k8s.policy.uid",
						Value:  string(uuid),
						Source: labels.LabelSourceK8s,
					},
				},
			),
		},
		{
			// When the rule specifies namespace labels, namespace label is not added
			// by the namespace where the rule was inserted.
			name: "parse-in-namespace-with-ns-labels-selector",
			args: args{
				namespace: slim_metav1.NamespaceDefault,
				uid:       uuid,
				rule: &api.Rule{
					EndpointSelector: api.NewESFromMatchRequirements(
						map[string]string{
							role: "backend",
						},
						nil,
					),
					Ingress: []api.IngressRule{
						{
							IngressCommonRule: api.IngressCommonRule{
								FromEndpoints: []api.EndpointSelector{
									{
										LabelSelector: &slim_metav1.LabelSelector{
											MatchLabels: map[string]string{
												podAnyNamespaceLabelsPrefix + "team": "team-a",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: api.NewRule().WithEndpointSelector(
				api.NewESFromMatchRequirements(
					map[string]string{
						role:      "backend",
						namespace: "default",
					},
					nil,
				),
			).WithIngressRules(
				[]api.IngressRule{
					{
						IngressCommonRule: api.IngressCommonRule{
							FromEndpoints: []api.EndpointSelector{
								api.NewESFromK8sLabelSelector(
									labels.LabelSourceAnyKeyPrefix,
									&slim_metav1.LabelSelector{
										MatchLabels: map[string]string{
											k8sConst.PodNamespaceMetaLabelsPrefix + "team": "team-a",
										},
									}),
							},
						},
					},
				},
			).WithLabels(
				labels.LabelArray{
					{
						Key:    "io.cilium.k8s.policy.derived-from",
						Value:  "CiliumNetworkPolicy",
						Source: labels.LabelSourceK8s,
					},
					{
						Key:    "io.cilium.k8s.policy.name",
						Value:  "parse-in-namespace-with-ns-labels-selector",
						Source: labels.LabelSourceK8s,
					},
					{
						Key:    "io.cilium.k8s.policy.namespace",
						Value:  "default",
						Source: labels.LabelSourceK8s,
					},
					{
						Key:    "io.cilium.k8s.policy.uid",
						Value:  string(uuid),
						Source: labels.LabelSourceK8s,
					},
				},
			),
		},
		{
			// For a clusterwide policy the namespace is empty but when a to/fromEndpoint
			// rule is added that represents a wildcard we add a match expression
			// to account only for endpoints managed by cilium.
			name: "wildcard-to-from-endpoints-with-ccnp",
			args: args{
				// Empty namespace for Clusterwide policy
				namespace: "",
				uid:       uuid,
				rule: &api.Rule{
					EndpointSelector: api.NewESFromMatchRequirements(
						map[string]string{
							role: "backend",
						},
						nil,
					),
					Ingress: []api.IngressRule{
						{
							IngressCommonRule: api.IngressCommonRule{
								FromEndpoints: []api.EndpointSelector{
									{
										LabelSelector: &slim_metav1.LabelSelector{},
									},
								},
							},
						},
					},
				},
			},
			want: api.NewRule().WithEndpointSelector(
				api.NewESFromMatchRequirements(
					map[string]string{
						role: "backend",
					},
					nil,
				),
			).WithIngressRules(
				[]api.IngressRule{
					{
						IngressCommonRule: api.IngressCommonRule{
							FromEndpoints: []api.EndpointSelector{
								api.NewESFromK8sLabelSelector(
									labels.LabelSourceK8sKeyPrefix,
									&slim_metav1.LabelSelector{
										MatchExpressions: []slim_metav1.LabelSelectorRequirement{
											{
												Key:      k8sConst.PodNamespaceLabel,
												Operator: slim_metav1.LabelSelectorOpExists,
												Values:   []string{},
											},
										},
									}),
							},
						},
					},
				},
			).WithLabels(
				labels.LabelArray{
					{
						Key:    "io.cilium.k8s.policy.derived-from",
						Value:  "CiliumClusterwideNetworkPolicy",
						Source: labels.LabelSourceK8s,
					},
					{
						Key:    "io.cilium.k8s.policy.name",
						Value:  "wildcard-to-from-endpoints-with-ccnp",
						Source: labels.LabelSourceK8s,
					},
					{
						Key:    "io.cilium.k8s.policy.uid",
						Value:  string(uuid),
						Source: labels.LabelSourceK8s,
					},
				},
			),
		},
		{
			// CNP with fromNodes selector should add a match expression
			// for reserved:remote-node to allow only nodes and not endpoints
			name: "parse-from-to-nodes-rule",
			args: args{
				overrideConfig: func() {
					option.Config.EnableNodeSelectorLabels = true
				},
				namespace: slim_metav1.NamespaceDefault,
				uid:       uuid,
				rule: &api.Rule{
					EndpointSelector: api.NewESFromMatchRequirements(
						map[string]string{
							role: "backend",
						},
						nil,
					),
					Ingress: []api.IngressRule{
						{
							IngressCommonRule: api.IngressCommonRule{
								FromNodes: []api.EndpointSelector{
									{
										LabelSelector: &slim_metav1.LabelSelector{},
									},
								},
							},
						},
					},
				},
			},
			want: api.NewRule().WithEndpointSelector(
				api.NewESFromMatchRequirements(
					map[string]string{
						role:      "backend",
						namespace: "default",
					},
					nil,
				),
			).WithIngressRules(
				[]api.IngressRule{
					{
						IngressCommonRule: api.IngressCommonRule{
							FromNodes: []api.EndpointSelector{
								api.NewESFromK8sLabelSelector(
									"",
									&slim_metav1.LabelSelector{
										MatchExpressions: []slim_metav1.LabelSelectorRequirement{
											{
												Key:      labels.LabelSourceReservedKeyPrefix + labels.IDNameRemoteNode,
												Operator: slim_metav1.LabelSelectorOpExists,
												Values:   []string{},
											},
										},
									}),
							},
						},
					},
				},
			).WithLabels(
				labels.LabelArray{
					{
						Key:    "io.cilium.k8s.policy.derived-from",
						Value:  "CiliumNetworkPolicy",
						Source: labels.LabelSourceK8s,
					},
					{
						Key:    "io.cilium.k8s.policy.name",
						Value:  "parse-from-to-nodes-rule",
						Source: labels.LabelSourceK8s,
					},
					{
						Key:    "io.cilium.k8s.policy.namespace",
						Value:  "default",
						Source: labels.LabelSourceK8s,
					},
					{
						Key:    "io.cilium.k8s.policy.uid",
						Value:  string(uuid),
						Source: labels.LabelSourceK8s,
					},
				},
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.args.rule.Sanitize()
			if tt.args.overrideConfig != nil {
				tt.args.overrideConfig()
			} else {
				option.Config.EnableNodeSelectorLabels = false
			}
			got := ParseToCiliumRule(hivetest.Logger(t), tt.args.clusterName, tt.args.namespace, tt.name, tt.args.uid, tt.args.rule)

			// Sanitize to set AggregatedSelectors field.
			tt.want.Sanitize()
			require.Equal(t, tt.want, got, "Test Name: %s", tt.name)
		})
	}
}

func TestParseToCiliumLabels(t *testing.T) {

	uuid := types.UID("11bba160-ddca-11e8-b697-0800273b04ff")
	type args struct {
		namespace string
		name      string
		uid       types.UID
		ruleLbs   labels.LabelArray
	}
	tests := []struct {
		name string
		args args
		want labels.LabelArray
	}{
		{
			name: "parse labels",
			args: args{
				name:      "foo",
				namespace: "bar",
				uid:       uuid,
				ruleLbs: labels.LabelArray{
					{
						Key:    "hello",
						Value:  "world",
						Source: labels.LabelSourceK8s,
					},
				},
			},
			want: labels.LabelArray{
				{
					Key:    "hello",
					Value:  "world",
					Source: labels.LabelSourceK8s,
				},
				{
					Key:    "io.cilium.k8s.policy.derived-from",
					Value:  "CiliumNetworkPolicy",
					Source: labels.LabelSourceK8s,
				},
				{
					Key:    "io.cilium.k8s.policy.name",
					Value:  "foo",
					Source: labels.LabelSourceK8s,
				},
				{
					Key:    "io.cilium.k8s.policy.namespace",
					Value:  "bar",
					Source: labels.LabelSourceK8s,
				},
				{
					Key:    "io.cilium.k8s.policy.uid",
					Value:  string(uuid),
					Source: labels.LabelSourceK8s,
				},
			},
		},
	}
	for _, tt := range tests {
		got := ParseToCiliumLabels(tt.args.namespace, tt.args.name, tt.args.uid, tt.args.ruleLbs)
		require.Equalf(t, tt.want, got, "Test Name: %s", tt.name)
	}
}
