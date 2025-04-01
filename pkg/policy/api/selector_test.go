// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	k8sLbls "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/selection"
	"github.com/cilium/cilium/pkg/labels"
)

func TestSelectsAllEndpoints(t *testing.T) {
	setUpSuite(t)

	// Empty endpoint selector slice does NOT equate to a wildcard.
	selectorSlice := EndpointSelectorSlice{}
	require.False(t, selectorSlice.SelectsAllEndpoints())

	selectorSlice = EndpointSelectorSlice{WildcardEndpointSelector}
	require.True(t, selectorSlice.SelectsAllEndpoints())

	// Entity "reserved:all" maps to WildcardEndpointSelector
	selectorSlice = EntitySlice{EntityAll}.GetAsEndpointSelectors()
	require.True(t, selectorSlice.SelectsAllEndpoints())

	// Slice that contains wildcard and other selectors still selects all endpoints.
	selectorSlice = EndpointSelectorSlice{WildcardEndpointSelector, NewESFromLabels(labels.ParseSelectLabel("bar"))}
	require.True(t, selectorSlice.SelectsAllEndpoints())

	selectorSlice = EndpointSelectorSlice{NewESFromLabels(labels.ParseSelectLabel("bar")), NewESFromLabels(labels.ParseSelectLabel("foo"))}
	require.False(t, selectorSlice.SelectsAllEndpoints())
}

func TestLabelSelectorToRequirements(t *testing.T) {
	setUpSuite(t)

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

	expRequirements := k8sLbls.Requirements{}
	req, err := k8sLbls.NewRequirement("any.foo", selection.Equals, []string{"bar"})
	require.NoError(t, err)
	expRequirements = append(expRequirements, *req)
	req, err = k8sLbls.NewRequirement("any.foo", selection.NotIn, []string{"default"})
	require.NoError(t, err)
	expRequirements = append(expRequirements, *req)
	req, err = k8sLbls.NewRequirement("k8s.baz", selection.Equals, []string{"alice"})
	require.NoError(t, err)
	expRequirements = append(expRequirements, *req)

	require.Equal(t, &expRequirements, labelSelectorToRequirements(labelSelector))
}

func benchmarkMatchesSetup(match string, count int) (EndpointSelector, labels.LabelArray) {
	stringLabels := []string{}
	for i := range count {
		stringLabels = append(stringLabels, fmt.Sprintf("%d", i))
	}
	lbls := labels.NewLabelsFromModel(stringLabels)
	return NewESFromLabels(lbls.ToSlice()...), labels.ParseLabelArray(match)
}

func BenchmarkMatchesValid1000(b *testing.B) {
	es, match := benchmarkMatchesSetup("42", 1000)

	for b.Loop() {
		es.Matches(match)
	}
}

func BenchmarkMatchesInvalid1000(b *testing.B) {
	es, match := benchmarkMatchesSetup("foo", 1000)

	for b.Loop() {
		es.Matches(match)
	}
}

func BenchmarkMatchesValid1000Parallel(b *testing.B) {
	es, match := benchmarkMatchesSetup("42", 1000)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			es.Matches(match)
		}
	})
}

func BenchmarkMatchesInvalid1000Parallel(b *testing.B) {
	es, match := benchmarkMatchesSetup("foo", 1000)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			es.Matches(match)
		}
	})
}
