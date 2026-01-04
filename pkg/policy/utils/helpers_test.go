// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utils

import (
	"fmt"
	"testing"

	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
)

func TestNamespacesAreValid(t *testing.T) {
	require.True(t, namespacesAreValid("default", []string{}))
	require.True(t, namespacesAreValid("default", []string{"default"}))
	require.False(t, namespacesAreValid("default", []string{"foo"}))
	require.False(t, namespacesAreValid("default", []string{"default", "foo"}))
}

func TestAddClusterFilterByDefault(t *testing.T) {
	dummyLabel := labels.ParseSelectLabel("app=test")

	k8sClusterLabel := labels.ParseSelectLabel(fmt.Sprintf("%s=test", clusterPrefixLbl))
	anyClusterLabel := labels.ParseSelectLabel(fmt.Sprintf("%s=test", clusterAnyPrefixLbl))

	k8sClusterLabel2 := labels.ParseSelectLabel(fmt.Sprintf("%s=cluster-2", clusterPrefixLbl))
	anyClusterLabel2 := labels.ParseSelectLabel(fmt.Sprintf("%s=cluster-2", clusterAnyPrefixLbl))

	tests := []struct {
		name    string
		cluster string
		arg     api.EndpointSelector
		want    api.EndpointSelector
	}{
		{
			name:    "Add cluster label when not present",
			cluster: "test",
			arg:     api.NewESFromLabels(dummyLabel),
			want:    api.NewESFromLabels(dummyLabel, k8sClusterLabel),
		},
		{
			name:    "Do not add cluster label for emtpy cluster",
			cluster: cmtypes.PolicyAnyCluster,
			arg:     api.NewESFromLabels(dummyLabel),
			want:    api.NewESFromLabels(dummyLabel),
		},
		{
			name:    "Do not add cluster label when already present with k8s prefix(same cluster)",
			cluster: "test",
			arg:     api.NewESFromLabels(dummyLabel, k8sClusterLabel),
			want:    api.NewESFromLabels(dummyLabel, k8sClusterLabel),
		},
		{
			name:    "Do not add cluster label when already present with k8s prefix(different cluster)",
			cluster: "test",
			arg:     api.NewESFromLabels(dummyLabel, k8sClusterLabel2),
			want:    api.NewESFromLabels(dummyLabel, k8sClusterLabel2),
		},
		{
			name:    "Do not add cluster label when already present with any prefix(same cluster)",
			cluster: "test",
			arg:     api.NewESFromLabels(dummyLabel, anyClusterLabel),
			want:    api.NewESFromLabels(dummyLabel, anyClusterLabel),
		},
		{
			name:    "Do not add cluster label when already present with any prefix(different cluster)",
			cluster: "test",
			arg:     api.NewESFromLabels(dummyLabel, anyClusterLabel2),
			want:    api.NewESFromLabels(dummyLabel, anyClusterLabel2),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addClusterFilterByDefault(&tt.arg, tt.cluster)
			require.Equal(t, tt.want, tt.arg)
		})
	}
}

func TestGetEndpointSelector(t *testing.T) {
	tests := []struct {
		name        string
		namespace   string
		cluster     string
		matchesInit bool

		arg  *slim_metav1.LabelSelector
		want *slim_metav1.LabelSelector
	}{
		{
			name:        "Don't add additional labels when reserved label is present(add any source prefix)",
			cluster:     "test",
			namespace:   "default",
			matchesInit: false,

			arg: &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"reserved:host": "",
					"app":           "test",
				},
			},
			want: &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"reserved:host": "",
					"any:app":       "test",
				},
			},
		},
		{
			name:        "Don't add additional labels when reserved label is present(keep source prefix)",
			cluster:     "test",
			namespace:   "default",
			matchesInit: false,

			arg: &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"reserved:host": "",
					"source:app":    "test",
				},
			},
			want: &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"reserved:host": "",
					"source:app":    "test",
				},
			},
		},
		{
			name:        "Add namespace when provided",
			cluster:     "test-cluster",
			namespace:   "test-ns",
			matchesInit: false,
			arg: &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{"k8s:app": "test"},
			},
			want: &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s:app":        "test",
					podPrefixLbl:     "test-ns",
					clusterPrefixLbl: "test-cluster",
				},
			},
		},
		{
			name:        "Add namespace label exists match expression for Clusterwide policy",
			cluster:     "test-cluster",
			namespace:   "",
			matchesInit: false,
			arg: &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{"k8s:app": "test"},
			},
			want: &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s:app":        "test",
					clusterPrefixLbl: "test-cluster",
				},
				MatchExpressions: []slim_metav1.LabelSelectorRequirement{
					{podPrefixLbl, slim_metav1.LabelSelectorOpExists, []string{}},
				},
			},
		},
		{
			name:        "Don't add namespace label for Clusterwide policy when matches init is true",
			cluster:     "test-cluster",
			namespace:   "",
			matchesInit: true,
			arg: &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{"k8s:app": "test"},
			},
			want: &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s:app":        "test",
					clusterPrefixLbl: "test-cluster",
				},
			},
		},
		{
			name:      "Don't add namespace when already present with k8s prefix",
			cluster:   "test-cluster",
			namespace: "test-ns",
			arg: &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s:app":    "test",
					podPrefixLbl: "test-ns",
				},
			},
			want: &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s:app":        "test",
					podPrefixLbl:     "test-ns",
					clusterPrefixLbl: "test-cluster",
				},
			},
		},
		{
			name:      "Don't add namespace when already present with any prefix",
			cluster:   "test-cluster",
			namespace: "test-ns",
			arg: &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app":           "test",
					podAnyPrefixLbl: "test-ns",
				},
			},
			want: &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"any:app":        "test",
					podAnyPrefixLbl:  "test-ns",
					clusterPrefixLbl: "test-cluster",
				},
			},
		},
		{
			name:      "Don't add namespace when namespace label prefix is already present",
			cluster:   "test-cluster",
			namespace: "default",
			arg: &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"io.cilium.k8s.namespace.labels.team": "team-a",
				},
			},
			want: &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"any:io.cilium.k8s.namespace.labels.team": "team-a",
					clusterPrefixLbl: "test-cluster",
				},
			},
		},
		{
			name:      "Don't add namespace when k8s namespace label prefix is already present",
			cluster:   "",
			namespace: "default",
			arg: &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s:io.cilium.k8s.namespace.labels.team": "team-a",
				},
			},
			want: &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s:io.cilium.k8s.namespace.labels.team": "team-a",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			es := getEndpointSelector(tt.cluster, tt.namespace, tt.arg, tt.matchesInit)
			require.Equal(t, tt.want, es.LabelSelector)
		})
	}
}

func TestGetNodeSelector(t *testing.T) {
	tests := []struct {
		name    string
		cluster string
		arg     *slim_metav1.LabelSelector
		want    *slim_metav1.LabelSelector
	}{
		{
			name:    "Add remote node expression and cluster filter",
			cluster: "test-cluster",
			arg: &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{"node": "test"},
			},
			want: &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"any:node":       "test",
					clusterPrefixLbl: "test-cluster",
				},
				MatchExpressions: []slim_metav1.LabelSelectorRequirement{
					{labels.LabelSourceReservedKeyPrefix + labels.IDNameRemoteNode, slim_metav1.LabelSelectorOpExists, []string{}},
				},
			},
		},
		{
			name:    "Add remote node expression and cluster filter",
			cluster: "",
			arg: &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{"k8s:node": "test"},
			},
			want: &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s:node": "test",
				},
				MatchExpressions: []slim_metav1.LabelSelectorRequirement{
					{labels.LabelSourceReservedKeyPrefix + labels.IDNameRemoteNode, slim_metav1.LabelSelectorOpExists, []string{}},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			es := getNodeSelector(tt.cluster, tt.arg)
			require.Equal(t, tt.want, es.LabelSelector)
		})
	}
}

func TestMatchesPodInit(t *testing.T) {
	tests := []struct {
		name     string
		selector api.EndpointSelector
		want     bool
	}{
		{
			name:     "matches pod init",
			selector: api.NewESFromLabels(labels.ParseSelectLabel("reserved:init")),
			want:     true,
		},
		{
			name:     "does not match pod init",
			selector: api.NewESFromLabels(labels.ParseSelectLabel("app=test")),
			want:     false,
		},
		{
			name:     "nil label selector returns false",
			selector: api.EndpointSelector{LabelSelector: nil},
			want:     false,
		},
		{
			name: "matches pod init with other labels",
			selector: api.NewESFromLabels(
				labels.ParseSelectLabel("reserved:init"),
				labels.ParseSelectLabel("app=test"),
			),
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, matchesPodInit(tt.selector))
		})
	}
}

func TestEvaluateDefaultDenyForRule(t *testing.T) {
	// Save original config
	originalConfig := option.Config.EnableNonDefaultDenyPolicies
	defer func() {
		option.Config.EnableNonDefaultDenyPolicies = originalConfig
	}()

	var (
		boolTrue  bool = true
		boolFalse      = false
	)

	tests := []struct {
		name  string
		setup func()
		arg   *api.Rule

		wantIngressDeny bool
		wantEgressDeny  bool
	}{
		{
			name: "EnableNonDefaultDenyPolicies disabled - always returns true",
			setup: func() {
				option.Config.EnableNonDefaultDenyPolicies = false
			},
			arg:             &api.Rule{},
			wantIngressDeny: true,
			wantEgressDeny:  true,
		},
		{
			name: "EnableNonDefaultDenyPolicies enabled - no rules, explicit false",
			setup: func() {
				option.Config.EnableNonDefaultDenyPolicies = true
			},
			arg: &api.Rule{
				EnableDefaultDeny: api.DefaultDenyConfig{
					Ingress: &boolFalse,
					Egress:  &boolFalse,
				},
			},
			wantIngressDeny: false,
			wantEgressDeny:  false,
		},
		{
			name: "EnableNonDefaultDenyPolicies enabled - ingress rules present, implicit true",
			setup: func() {
				option.Config.EnableNonDefaultDenyPolicies = true
			},
			arg: &api.Rule{
				Ingress: []api.IngressRule{{}},
			},
			wantIngressDeny: true,
			wantEgressDeny:  false,
		},
		{
			name: "EnableNonDefaultDenyPolicies enabled - egress rules present, implicit true",
			setup: func() {
				option.Config.EnableNonDefaultDenyPolicies = true
			},
			arg: &api.Rule{
				Egress: []api.EgressRule{{}},
			},
			wantIngressDeny: false,
			wantEgressDeny:  true,
		},
		{
			name: "EnableNonDefaultDenyPolicies enabled - ingress deny rules present",
			setup: func() {
				option.Config.EnableNonDefaultDenyPolicies = true
			},
			arg: &api.Rule{
				IngressDeny: []api.IngressDenyRule{{}},
			},
			wantIngressDeny: true,
			wantEgressDeny:  false,
		},
		{
			name: "EnableNonDefaultDenyPolicies enabled - egress deny rules present",
			setup: func() {
				option.Config.EnableNonDefaultDenyPolicies = true
			},
			arg: &api.Rule{
				EgressDeny: []api.EgressDenyRule{{}},
			},
			wantIngressDeny: false,
			wantEgressDeny:  true,
		},
		{
			name: "EnableNonDefaultDenyPolicies enabled - explicit true overrides",
			setup: func() {
				option.Config.EnableNonDefaultDenyPolicies = true
			},
			arg: &api.Rule{
				EnableDefaultDeny: api.DefaultDenyConfig{
					Ingress: &boolTrue,
					Egress:  &boolTrue,
				},
			},
			wantIngressDeny: true,
			wantEgressDeny:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()
			ingressDeny, egressDeny := evaluateDefaultDenyForRule(tt.arg)
			require.Equal(t, tt.wantIngressDeny, ingressDeny)
			require.Equal(t, tt.wantEgressDeny, egressDeny)
		})
	}
}
