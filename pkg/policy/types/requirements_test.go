// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"testing"

	"github.com/stretchr/testify/require"

	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/selection"
)

func TestLabelSelectorToRequirements(t *testing.T) {
	labelSelector := &slim_metav1.LabelSelector{
		MatchLabels: map[string]string{
			"any.foo": "bar",
			"k8s.baz": "alice",
		},
		MatchExpressions: []slim_metav1.LabelSelectorRequirement{
			{
				Key:      "any.foo",
				Operator: "NotIn",
				Values:   []string{"default"},
			},
		},
	}

	expRequirements := Requirements{}
	req := NewRequirement("any.foo", selection.Equals, []string{"bar"})
	expRequirements = append(expRequirements, req)
	req = NewRequirement("any.foo", selection.NotIn, []string{"default"})
	expRequirements = append(expRequirements, req)
	req = NewRequirement("k8s.baz", selection.Equals, []string{"alice"})
	expRequirements = append(expRequirements, req)

	require.Equal(t, expRequirements, LabelSelectorToRequirements(labelSelector))
}
