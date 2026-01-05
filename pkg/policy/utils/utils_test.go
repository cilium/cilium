// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utils

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/labels"
)

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
		{
			name: "parse labels with empty source",
			args: args{
				name:      "test-policy",
				namespace: "default",
				uid:       uuid,
				ruleLbs: labels.LabelArray{
					{
						Key:    "policy-comment",
						Value:  "allow all traffic inside namespace",
						Source: "",
					},
					{
						Key:    "team",
						Value:  "platform",
						Source: labels.LabelSourceUnspec,
					},
					{
						Key:    "explicit-source",
						Value:  "test",
						Source: "custom",
					},
				},
			},
			want: labels.LabelArray{
				{
					Key:    "explicit-source",
					Value:  "test",
					Source: "custom",
				},
				{
					Key:    "io.cilium.k8s.policy.derived-from",
					Value:  "CiliumNetworkPolicy",
					Source: labels.LabelSourceK8s,
				},
				{
					Key:    "io.cilium.k8s.policy.name",
					Value:  "test-policy",
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
				{
					Key:    "policy-comment",
					Value:  "allow all traffic inside namespace",
					Source: labels.LabelSourceUnspec,
				},
				{
					Key:    "team",
					Value:  "platform",
					Source: labels.LabelSourceUnspec,
				},
			},
		},
	}
	for _, tt := range tests {
		got := ParseToCiliumLabels(tt.args.namespace, tt.args.name, tt.args.uid, tt.args.ruleLbs)
		require.Equalf(t, tt.want, got, "Test Name: %s", tt.name)
	}
}

func TestGetPolicyFromLabels(t *testing.T) {
	type args struct {
		policyLabels []string
		revision     uint64
	}
	uuid := types.UID("11bba160-ddca-11e8-b697-0800273b04ff")
	tests := []struct {
		name string
		args args
		want *flow.Policy
	}{
		{
			name: "parse policy from labels",
			args: args{
				policyLabels: []string{
					"k8s:io.cilium.k8s.policy.derived-from=CiliumNetworkPolicy",
					"k8s:io.cilium.k8s.policy.name=foo",
					"k8s:io.cilium.k8s.policy.namespace=bar",
					"k8s:io.cilium.k8s.policy.uid=" + string(uuid),
				},
				revision: 1,
			},
			want: &flow.Policy{
				Revision:  1,
				Name:      "foo",
				Namespace: "bar",
				Kind:      "CiliumNetworkPolicy",
				Labels: []string{
					"k8s:io.cilium.k8s.policy.derived-from=CiliumNetworkPolicy",
					"k8s:io.cilium.k8s.policy.name=foo",
					"k8s:io.cilium.k8s.policy.namespace=bar",
					"k8s:io.cilium.k8s.policy.uid=" + string(uuid),
				},
			},
		},
		{
			name: "parse policy from labels with clusterwide policy",
			args: args{
				policyLabels: []string{
					"k8s:io.cilium.k8s.policy.derived-from=CiliumClusterwideNetworkPolicy",
					"k8s:io.cilium.k8s.policy.name=foo",
					"k8s:io.cilium.k8s.policy.uid=" + string(uuid),
				},
				revision: 1,
			},
			want: &flow.Policy{
				Revision:  1,
				Kind:      "CiliumClusterwideNetworkPolicy",
				Name:      "foo",
				Namespace: "",
				Labels: []string{
					"k8s:io.cilium.k8s.policy.derived-from=CiliumClusterwideNetworkPolicy",
					"k8s:io.cilium.k8s.policy.name=foo",
					"k8s:io.cilium.k8s.policy.uid=" + string(uuid),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := GetPolicyFromLabels(tt.args.policyLabels, tt.args.revision)
			require.Equal(t, tt.want, actual)
		})
	}
}
