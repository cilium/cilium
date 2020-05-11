// Copyright 2018-2020 Authors of Cilium
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

package api

import (
	"fmt"
	"testing"

	"github.com/cilium/cilium/pkg/checker"
	k8sLbls "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/selection"
	"github.com/cilium/cilium/pkg/labels"

	. "gopkg.in/check.v1"
)

var _ = Suite(&PolicyAPITestSuite{})

func (s *PolicyAPITestSuite) TestSelectsAllEndpoints(c *C) {

	// Empty endpoint selector slice does NOT equate to a wildcard.
	selectorSlice := EndpointSelectorSlice{}
	c.Assert(selectorSlice.SelectsAllEndpoints(), Equals, false)

	selectorSlice = EndpointSelectorSlice{WildcardEndpointSelector}
	c.Assert(selectorSlice.SelectsAllEndpoints(), Equals, true)

	// Entity "reserved:all" maps to WildcardEndpointSelector
	selectorSlice = EntitySlice{EntityAll}.GetAsEndpointSelectors()
	c.Assert(selectorSlice.SelectsAllEndpoints(), Equals, true)

	// Slice that contains wildcard and other selectors still selects all endpoints.
	selectorSlice = EndpointSelectorSlice{WildcardEndpointSelector, NewESFromLabels(labels.ParseSelectLabel("bar"))}
	c.Assert(selectorSlice.SelectsAllEndpoints(), Equals, true)

	selectorSlice = EndpointSelectorSlice{NewESFromLabels(labels.ParseSelectLabel("bar")), NewESFromLabels(labels.ParseSelectLabel("foo"))}
	c.Assert(selectorSlice.SelectsAllEndpoints(), Equals, false)
}

func (s *PolicyAPITestSuite) TestLabelSelectorToRequirements(c *C) {
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
	c.Assert(err, IsNil)
	expRequirements = append(expRequirements, *req)
	req, err = k8sLbls.NewRequirement("any.foo", selection.NotIn, []string{"default"})
	c.Assert(err, IsNil)
	expRequirements = append(expRequirements, *req)
	req, err = k8sLbls.NewRequirement("k8s.baz", selection.Equals, []string{"alice"})
	c.Assert(err, IsNil)
	expRequirements = append(expRequirements, *req)

	c.Assert(labelSelectorToRequirements(labelSelector), checker.DeepEquals, &expRequirements)
}

func benchmarkMatchesSetup(match string, count int) (EndpointSelector, labels.LabelArray) {
	stringLabels := []string{}
	for i := 0; i < count; i++ {
		stringLabels = append(stringLabels, fmt.Sprintf("%d", i))
	}
	lbls := labels.NewLabelsFromModel(stringLabels)
	return NewESFromLabels(lbls.ToSlice()...), labels.ParseLabelArray(match)
}

func BenchmarkMatchesValid1000(b *testing.B) {
	es, match := benchmarkMatchesSetup("42", 1000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		es.Matches(match)
	}
}

func BenchmarkMatchesInvalid1000(b *testing.B) {
	es, match := benchmarkMatchesSetup("foo", 1000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
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
