// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"log/slog"
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	policyv1alpha2 "sigs.k8s.io/network-policy-api/apis/v1alpha2"

	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/types"

	"github.com/stretchr/testify/require"
)

const (
	namespaceLabelPrefix = "io.cilium.k8s.namespace.labels."
)

func TestParseClusterNetworkPolicy(t *testing.T) {
	logger := slog.Default()
	clusterName := "testCluster"

	tests := []struct {
		name                     string
		cnp                      *policyv1alpha2.ClusterNetworkPolicy
		enableNodeSelectorLabels bool
		enableL7Proxy            bool
		want                     types.PolicyEntries
		wantErr                  bool
	}{
		{
			name:    "nil CNP",
			cnp:     nil,
			wantErr: true,
		},
		{
			name: "ingress rule with namespace selector",
			cnp: &policyv1alpha2.ClusterNetworkPolicy{
				Spec: policyv1alpha2.ClusterNetworkPolicySpec{
					Subject: policyv1alpha2.ClusterNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{
							MatchLabels: map[string]string{"app": "subject"},
						},
					},
					Ingress: []policyv1alpha2.ClusterNetworkPolicyIngressRule{
						{
							From: []policyv1alpha2.ClusterNetworkPolicyIngressPeer{
								{
									Namespaces: &metav1.LabelSelector{
										MatchLabels: map[string]string{"env": "prod"},
									},
								},
							},
						},
					},
				},
			},
			want: types.PolicyEntries{
				{
					Ingress: true,
					Subject: api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{namespaceLabelPrefix + "app": "subject"},
					}),
					L3: types.PeerSelectorSlice{
						api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, &slim_metav1.LabelSelector{
							MatchLabels: map[string]string{namespaceLabelPrefix + "env": "prod"},
						}),
					},
					Labels: labels.LabelArray{
						labels.NewLabel("io.cilium.k8s.policy.derived-from", "ClusterNetworkPolicy", labels.LabelSourceK8s),
						labels.NewLabel("io.cilium.k8s.policy.name", "", labels.LabelSourceK8s),
						labels.NewLabel("io.cilium.k8s.policy.uid", "", labels.LabelSourceK8s),
					},
				},
			}},
		{
			name: "ingress rule with pod selector",
			cnp: &policyv1alpha2.ClusterNetworkPolicy{
				Spec: policyv1alpha2.ClusterNetworkPolicySpec{
					Subject: policyv1alpha2.ClusterNetworkPolicySubject{
						Pods: &policyv1alpha2.NamespacedPod{
							NamespaceSelector: metav1.LabelSelector{
								MatchLabels: map[string]string{"ns": "subject-ns"},
							},
							PodSelector: metav1.LabelSelector{
								MatchLabels: map[string]string{"app": "subject-pod"},
							},
						},
					},
					Ingress: []policyv1alpha2.ClusterNetworkPolicyIngressRule{
						{
							From: []policyv1alpha2.ClusterNetworkPolicyIngressPeer{
								{
									Pods: &policyv1alpha2.NamespacedPod{
										NamespaceSelector: metav1.LabelSelector{
											MatchLabels: map[string]string{"ns": "from-ns"},
										},
										PodSelector: metav1.LabelSelector{
											MatchLabels: map[string]string{"app": "from-pod"},
										},
									},
								},
							},
						},
					},
				},
			},
			want: types.PolicyEntries{
				{
					Ingress: true,
					Subject: api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{namespaceLabelPrefix + "ns": "subject-ns"},
					}, &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "subject-pod"},
					}),
					L3: types.PeerSelectorSlice{
						api.NewESFromK8sLabelSelector("", &slim_metav1.LabelSelector{
							MatchLabels: map[string]string{
								"k8s." + namespaceLabelPrefix + "ns": "from-ns",
								"k8s.app":                            "from-pod",
								"io.cilium.k8s.policy.cluster":       clusterName,
							},
						}),
					},
					Labels: labels.LabelArray{
						labels.NewLabel("io.cilium.k8s.policy.derived-from", "ClusterNetworkPolicy", labels.LabelSourceK8s),
						labels.NewLabel("io.cilium.k8s.policy.name", "", labels.LabelSourceK8s),
						labels.NewLabel("io.cilium.k8s.policy.uid", "", labels.LabelSourceK8s),
					},
				},
			},
		},
		{
			name: "ingress rule with port number",
			cnp: &policyv1alpha2.ClusterNetworkPolicy{
				Spec: policyv1alpha2.ClusterNetworkPolicySpec{
					Subject: policyv1alpha2.ClusterNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "test"}},
					},
					Ingress: []policyv1alpha2.ClusterNetworkPolicyIngressRule{
						{
							From: []policyv1alpha2.ClusterNetworkPolicyIngressPeer{
								{Namespaces: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "dev"}}},
							},
							Ports: &[]policyv1alpha2.ClusterNetworkPolicyPort{
								{
									PortNumber: &policyv1alpha2.Port{Port: 80, Protocol: v1.ProtocolTCP},
								},
							},
						},
					},
				},
			},
			want: types.PolicyEntries{
				{
					Ingress: true,
					Subject: api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{namespaceLabelPrefix + "app": "test"},
					}),
					L3: types.PeerSelectorSlice{
						api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, &slim_metav1.LabelSelector{
							MatchLabels: map[string]string{namespaceLabelPrefix + "env": "dev"},
						}),
					},
					L4: []api.PortRule{
						{Ports: []api.PortProtocol{{Port: "80", Protocol: api.ProtoTCP}}},
					},
					Labels: labels.LabelArray{
						labels.NewLabel("io.cilium.k8s.policy.derived-from", "ClusterNetworkPolicy", labels.LabelSourceK8s),
						labels.NewLabel("io.cilium.k8s.policy.name", "", labels.LabelSourceK8s),
						labels.NewLabel("io.cilium.k8s.policy.uid", "", labels.LabelSourceK8s),
					},
				},
			},
		},
		{
			name: "ingress rule with port range",
			cnp: &policyv1alpha2.ClusterNetworkPolicy{
				Spec: policyv1alpha2.ClusterNetworkPolicySpec{
					Subject: policyv1alpha2.ClusterNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "test"}},
					},
					Ingress: []policyv1alpha2.ClusterNetworkPolicyIngressRule{
						{
							From: []policyv1alpha2.ClusterNetworkPolicyIngressPeer{
								{Namespaces: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "dev"}}},
							},
							Ports: &[]policyv1alpha2.ClusterNetworkPolicyPort{
								{
									PortRange: &policyv1alpha2.PortRange{Start: 8080, End: 8090, Protocol: v1.ProtocolUDP},
								},
							},
						},
					},
				},
			},
			want: types.PolicyEntries{
				{
					Ingress: true,
					Subject: api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{namespaceLabelPrefix + "app": "test"},
					}),
					L3: types.PeerSelectorSlice{
						api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, &slim_metav1.LabelSelector{
							MatchLabels: map[string]string{namespaceLabelPrefix + "env": "dev"},
						}),
					},
					L4: []api.PortRule{
						{Ports: []api.PortProtocol{{Port: "8080", EndPort: 8090, Protocol: api.ProtoUDP}}},
					},
					Labels: labels.LabelArray{
						labels.NewLabel("io.cilium.k8s.policy.derived-from", "ClusterNetworkPolicy", labels.LabelSourceK8s),
						labels.NewLabel("io.cilium.k8s.policy.name", "", labels.LabelSourceK8s),
						labels.NewLabel("io.cilium.k8s.policy.uid", "", labels.LabelSourceK8s),
					},
				},
			},
		},
		{
			name: "ingress rule with named port",
			cnp: &policyv1alpha2.ClusterNetworkPolicy{
				Spec: policyv1alpha2.ClusterNetworkPolicySpec{
					Subject: policyv1alpha2.ClusterNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "test"}},
					},
					Ingress: []policyv1alpha2.ClusterNetworkPolicyIngressRule{
						{
							From: []policyv1alpha2.ClusterNetworkPolicyIngressPeer{
								{Namespaces: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "dev"}}},
							},
							Ports: &[]policyv1alpha2.ClusterNetworkPolicyPort{
								{
									NamedPort: func() *string { s := "http"; return &s }(),
								},
							},
						},
					},
				},
			},
			want: types.PolicyEntries{
				{
					Ingress: true,
					Subject: api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{namespaceLabelPrefix + "app": "test"},
					}),
					L3: types.PeerSelectorSlice{
						api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, &slim_metav1.LabelSelector{
							MatchLabels: map[string]string{namespaceLabelPrefix + "env": "dev"},
						}),
					},
					L4: []api.PortRule{
						{Ports: []api.PortProtocol{{Port: "http", Protocol: api.ProtoTCP}}},
					},
					Labels: labels.LabelArray{
						labels.NewLabel("io.cilium.k8s.policy.derived-from", "ClusterNetworkPolicy", labels.LabelSourceK8s),
						labels.NewLabel("io.cilium.k8s.policy.name", "", labels.LabelSourceK8s),
						labels.NewLabel("io.cilium.k8s.policy.uid", "", labels.LabelSourceK8s),
					},
				},
			},
		},
		{
			name: "ingress rule with deny action",
			cnp: &policyv1alpha2.ClusterNetworkPolicy{
				Spec: policyv1alpha2.ClusterNetworkPolicySpec{
					Subject: policyv1alpha2.ClusterNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "test"}},
					},
					Ingress: []policyv1alpha2.ClusterNetworkPolicyIngressRule{
						{
							Action: policyv1alpha2.ClusterNetworkPolicyRuleActionDeny,
							From: []policyv1alpha2.ClusterNetworkPolicyIngressPeer{
								{Namespaces: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "dev"}}},
							},
						},
					},
				},
			},
			want: types.PolicyEntries{
				{
					Ingress: true,
					Deny:    true,
					Subject: api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{namespaceLabelPrefix + "app": "test"},
					}),
					L3: types.PeerSelectorSlice{
						api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, &slim_metav1.LabelSelector{
							MatchLabels: map[string]string{namespaceLabelPrefix + "env": "dev"},
						}),
					},
					Labels: labels.LabelArray{
						labels.NewLabel("io.cilium.k8s.policy.derived-from", "ClusterNetworkPolicy", labels.LabelSourceK8s),
						labels.NewLabel("io.cilium.k8s.policy.name", "", labels.LabelSourceK8s),
						labels.NewLabel("io.cilium.k8s.policy.uid", "", labels.LabelSourceK8s),
					},
				},
			},
		},
		{
			name: "egress rule with namespace selector",
			cnp: &policyv1alpha2.ClusterNetworkPolicy{
				Spec: policyv1alpha2.ClusterNetworkPolicySpec{
					Subject: policyv1alpha2.ClusterNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "subject"}},
					},
					Egress: []policyv1alpha2.ClusterNetworkPolicyEgressRule{
						{
							To: []policyv1alpha2.ClusterNetworkPolicyEgressPeer{
								{
									Namespaces: &metav1.LabelSelector{
										MatchLabels: map[string]string{"env": "prod"},
									},
								},
							},
						},
					},
				},
			},
			want: types.PolicyEntries{
				{
					Ingress: false,
					Subject: api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{namespaceLabelPrefix + "app": "subject"},
					}),
					L3: types.PeerSelectorSlice{
						api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, &slim_metav1.LabelSelector{
							MatchLabels: map[string]string{namespaceLabelPrefix + "env": "prod"},
						}),
					},
					Labels: labels.LabelArray{
						labels.NewLabel("io.cilium.k8s.policy.derived-from", "ClusterNetworkPolicy", labels.LabelSourceK8s),
						labels.NewLabel("io.cilium.k8s.policy.name", "", labels.LabelSourceK8s),
						labels.NewLabel("io.cilium.k8s.policy.uid", "", labels.LabelSourceK8s),
					},
				},
			},
		},
		{
			name: "egress rule with node selector",
			cnp: &policyv1alpha2.ClusterNetworkPolicy{
				Spec: policyv1alpha2.ClusterNetworkPolicySpec{
					Subject: policyv1alpha2.ClusterNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "subject"}},
					},
					Egress: []policyv1alpha2.ClusterNetworkPolicyEgressRule{
						{
							To: []policyv1alpha2.ClusterNetworkPolicyEgressPeer{
								{
									Nodes: &metav1.LabelSelector{
										MatchLabels: map[string]string{"kubernetes.io/hostname": "node1"},
									},
								},
							},
						},
					},
				},
			},
			enableNodeSelectorLabels: true,
			want: types.PolicyEntries{
				{
					Ingress: false,
					Subject: api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{namespaceLabelPrefix + "app": "subject"},
					}),
					L3: types.PeerSelectorSlice{
						api.NewESFromK8sLabelSelector("", &slim_metav1.LabelSelector{
							MatchLabels: map[string]string{
								"node.kubernetes.io/hostname":  "node1",
								"io.cilium.k8s.policy.cluster": clusterName,
							},
							MatchExpressions: []slim_metav1.LabelSelectorRequirement{{
								Key:      "reserved.remote-node",
								Operator: "Exists",
								Values:   []string{},
							}},
						}),
					},
					Labels: labels.LabelArray{
						labels.NewLabel("io.cilium.k8s.policy.derived-from", "ClusterNetworkPolicy", labels.LabelSourceK8s),
						labels.NewLabel("io.cilium.k8s.policy.name", "", labels.LabelSourceK8s),
						labels.NewLabel("io.cilium.k8s.policy.uid", "", labels.LabelSourceK8s),
					},
				},
			},
		},
		{
			name: "egress rule with node selector and node selector labels disabled",
			cnp: &policyv1alpha2.ClusterNetworkPolicy{
				Spec: policyv1alpha2.ClusterNetworkPolicySpec{
					Subject: policyv1alpha2.ClusterNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "subject"}},
					},
					Egress: []policyv1alpha2.ClusterNetworkPolicyEgressRule{
						{
							To: []policyv1alpha2.ClusterNetworkPolicyEgressPeer{
								{
									Nodes: &metav1.LabelSelector{
										MatchLabels: map[string]string{"kubernetes.io/hostname": "node1"},
									},
								},
							},
						},
					},
				},
			},
			enableNodeSelectorLabels: false,
			wantErr:                  true,
		},
		{
			name: "egress rule with networks (CIDR)",
			cnp: &policyv1alpha2.ClusterNetworkPolicy{
				Spec: policyv1alpha2.ClusterNetworkPolicySpec{
					Subject: policyv1alpha2.ClusterNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "subject"}},
					},
					Egress: []policyv1alpha2.ClusterNetworkPolicyEgressRule{
						{
							To: []policyv1alpha2.ClusterNetworkPolicyEgressPeer{
								{
									Networks: []policyv1alpha2.CIDR{"192.168.1.0/24", "10.0.0.0/8"},
								},
							},
						},
					},
				},
			},
			want: types.PolicyEntries{
				{
					Ingress: false,
					Subject: api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{namespaceLabelPrefix + "app": "subject"},
					}),
					L3: types.PeerSelectorSlice{
						api.CIDR("192.168.1.0/24"),
						api.CIDR("10.0.0.0/8"),
					},
					Labels: labels.LabelArray{
						labels.NewLabel("io.cilium.k8s.policy.derived-from", "ClusterNetworkPolicy", labels.LabelSourceK8s),
						labels.NewLabel("io.cilium.k8s.policy.name", "", labels.LabelSourceK8s),
						labels.NewLabel("io.cilium.k8s.policy.uid", "", labels.LabelSourceK8s),
					},
				},
			},
		},
		{
			name: "egress rule with domain names (FQDN)",
			cnp: &policyv1alpha2.ClusterNetworkPolicy{
				Spec: policyv1alpha2.ClusterNetworkPolicySpec{
					Subject: policyv1alpha2.ClusterNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "subject"}},
					},
					Egress: []policyv1alpha2.ClusterNetworkPolicyEgressRule{
						{
							Action: policyv1alpha2.ClusterNetworkPolicyRuleActionAccept,
							To: []policyv1alpha2.ClusterNetworkPolicyEgressPeer{
								{
									DomainNames: []policyv1alpha2.DomainName{"example.com", "*.another.org"},
								},
							},
						},
					},
				},
			},
			enableL7Proxy: true,
			want: types.PolicyEntries{
				{
					Ingress: false,
					Subject: api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{namespaceLabelPrefix + "app": "subject"},
					}),
					L3: types.PeerSelectorSlice{api.WildcardEndpointSelector},
					L4: api.PortRules{{
						Ports: []api.PortProtocol{
							{Port: "53", Protocol: api.ProtoUDP},
							{Port: "53", Protocol: api.ProtoTCP},
						},
						Rules: &api.L7Rules{
							DNS: api.PortRulesDNS{
								api.PortRuleDNS{MatchName: "example.com"},
								api.PortRuleDNS{MatchPattern: "*.another.org"},
							},
						},
					}},
					Labels: labels.LabelArray{
						labels.NewLabel("io.cilium.k8s.policy.derived-from", "ClusterNetworkPolicy", labels.LabelSourceK8s),
						labels.NewLabel("io.cilium.k8s.policy.name", "", labels.LabelSourceK8s),
						labels.NewLabel("io.cilium.k8s.policy.uid", "", labels.LabelSourceK8s),
					},
				},
				{
					Ingress: false,
					Subject: api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{namespaceLabelPrefix + "app": "subject"},
					}),
					L3: types.PeerSelectorSlice{
						api.FQDNSelector{MatchName: "example.com"},
						api.FQDNSelector{MatchPattern: "*.another.org"},
					},
					Labels: labels.LabelArray{
						labels.NewLabel("io.cilium.k8s.policy.derived-from", "ClusterNetworkPolicy", labels.LabelSourceK8s),
						labels.NewLabel("io.cilium.k8s.policy.name", "", labels.LabelSourceK8s),
						labels.NewLabel("io.cilium.k8s.policy.uid", "", labels.LabelSourceK8s),
					},
				},
			},
		},
		{
			name: "egress rule with domain names (FQDN) with L7 proxy disabled",
			cnp: &policyv1alpha2.ClusterNetworkPolicy{
				Spec: policyv1alpha2.ClusterNetworkPolicySpec{
					Subject: policyv1alpha2.ClusterNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "subject"}},
					},
					Egress: []policyv1alpha2.ClusterNetworkPolicyEgressRule{
						{
							Action: policyv1alpha2.ClusterNetworkPolicyRuleActionAccept,
							To: []policyv1alpha2.ClusterNetworkPolicyEgressPeer{
								{
									DomainNames: []policyv1alpha2.DomainName{"example.com", "*.another.org"},
								},
							},
						},
					},
				},
			},
			enableL7Proxy: false,
			wantErr:       true,
		},
		{
			name: "egress rule with ports and deny action",
			cnp: &policyv1alpha2.ClusterNetworkPolicy{
				Spec: policyv1alpha2.ClusterNetworkPolicySpec{
					Subject: policyv1alpha2.ClusterNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "subject"}},
					},
					Egress: []policyv1alpha2.ClusterNetworkPolicyEgressRule{
						{
							Action: policyv1alpha2.ClusterNetworkPolicyRuleActionDeny,
							To: []policyv1alpha2.ClusterNetworkPolicyEgressPeer{
								{
									Namespaces: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
								},
							},
							Ports: &[]policyv1alpha2.ClusterNetworkPolicyPort{
								{PortNumber: &policyv1alpha2.Port{Port: 443, Protocol: v1.ProtocolTCP}},
							},
						},
					},
				},
			},
			want: types.PolicyEntries{
				{
					Ingress: false,
					Deny:    true,
					Subject: api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{namespaceLabelPrefix + "app": "subject"},
					}),
					L3: types.PeerSelectorSlice{
						api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, &slim_metav1.LabelSelector{
							MatchLabels: map[string]string{namespaceLabelPrefix + "env": "prod"},
						}),
					},
					L4: []api.PortRule{
						{Ports: []api.PortProtocol{{Port: "443", Protocol: api.ProtoTCP}}},
					},
					Labels: labels.LabelArray{
						labels.NewLabel("io.cilium.k8s.policy.derived-from", "ClusterNetworkPolicy", labels.LabelSourceK8s),
						labels.NewLabel("io.cilium.k8s.policy.name", "", labels.LabelSourceK8s),
						labels.NewLabel("io.cilium.k8s.policy.uid", "", labels.LabelSourceK8s),
					},
				},
			},
		},
		{
			name: "combined ingress and egress rules",
			cnp: &policyv1alpha2.ClusterNetworkPolicy{
				Spec: policyv1alpha2.ClusterNetworkPolicySpec{
					Subject: policyv1alpha2.ClusterNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "main"}},
					},
					Ingress: []policyv1alpha2.ClusterNetworkPolicyIngressRule{
						{
							From: []policyv1alpha2.ClusterNetworkPolicyIngressPeer{
								{Namespaces: &metav1.LabelSelector{MatchLabels: map[string]string{"role": "ingress-source"}}},
							},
							Ports: &[]policyv1alpha2.ClusterNetworkPolicyPort{
								{PortNumber: &policyv1alpha2.Port{Port: 80, Protocol: v1.ProtocolTCP}},
							},
						},
					},
					Egress: []policyv1alpha2.ClusterNetworkPolicyEgressRule{
						{
							To: []policyv1alpha2.ClusterNetworkPolicyEgressPeer{
								{Namespaces: &metav1.LabelSelector{MatchLabels: map[string]string{"role": "egress-dest"}}},
							},
							Ports: &[]policyv1alpha2.ClusterNetworkPolicyPort{
								{PortNumber: &policyv1alpha2.Port{Port: 53, Protocol: v1.ProtocolUDP}},
							},
						},
					},
				},
			},
			want: types.PolicyEntries{
				{
					Ingress: true,
					Subject: api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{namespaceLabelPrefix + "app": "main"},
					}),
					L3: types.PeerSelectorSlice{
						api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, &slim_metav1.LabelSelector{
							MatchLabels: map[string]string{namespaceLabelPrefix + "role": "ingress-source"},
						}),
					},
					L4: []api.PortRule{
						{Ports: []api.PortProtocol{{Port: "80", Protocol: api.ProtoTCP}}},
					},
					Labels: labels.LabelArray{
						labels.NewLabel("io.cilium.k8s.policy.derived-from", "ClusterNetworkPolicy", labels.LabelSourceK8s),
						labels.NewLabel("io.cilium.k8s.policy.name", "", labels.LabelSourceK8s),
						labels.NewLabel("io.cilium.k8s.policy.uid", "", labels.LabelSourceK8s),
					},
				},
				{
					Ingress: false,
					Subject: api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{namespaceLabelPrefix + "app": "main"},
					}),
					L3: types.PeerSelectorSlice{
						api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, &slim_metav1.LabelSelector{
							MatchLabels: map[string]string{namespaceLabelPrefix + "role": "egress-dest"},
						}),
					},
					L4: []api.PortRule{
						{Ports: []api.PortProtocol{{Port: "53", Protocol: api.ProtoUDP}}},
					},
					Labels: labels.LabelArray{
						labels.NewLabel("io.cilium.k8s.policy.derived-from", "ClusterNetworkPolicy", labels.LabelSourceK8s),
						labels.NewLabel("io.cilium.k8s.policy.name", "", labels.LabelSourceK8s),
						labels.NewLabel("io.cilium.k8s.policy.uid", "", labels.LabelSourceK8s),
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			option.Config.EnableNodeSelectorLabels = tt.enableNodeSelectorLabels
			option.Config.EnableL7Proxy = tt.enableL7Proxy
			got, err := ParseClusterNetworkPolicy(logger, clusterName, tt.cnp)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
