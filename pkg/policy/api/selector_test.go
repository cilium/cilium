// Copyright 2018 Authors of Cilium
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

package api

import (
	"testing"

	"github.com/cilium/cilium/pkg/comparator"
	"github.com/cilium/cilium/pkg/labels"

	. "gopkg.in/check.v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Suite(&PolicyAPITestSuite{})

func (s *PolicyAPITestSuite) TestSelectsAllEndpoints(c *C) {

	// Empty endpoint selector slice equates to a wildcard.
	selectorSlice := EndpointSelectorSlice{}
	c.Assert(selectorSlice.SelectsAllEndpoints(), Equals, true)

	selectorSlice = EndpointSelectorSlice{WildcardEndpointSelector}
	c.Assert(selectorSlice.SelectsAllEndpoints(), Equals, true)

	// Slice that contains wildcard and other selectors still selects all endpoints.
	selectorSlice = EndpointSelectorSlice{WildcardEndpointSelector, NewESFromLabels(labels.ParseSelectLabel("bar"))}
	c.Assert(selectorSlice.SelectsAllEndpoints(), Equals, true)

	selectorSlice = EndpointSelectorSlice{NewESFromLabels(labels.ParseSelectLabel("bar")), NewESFromLabels(labels.ParseSelectLabel("foo"))}
	c.Assert(selectorSlice.SelectsAllEndpoints(), Equals, false)
}

func Test_AddMatch(t *testing.T) {
	type match struct {
		key   string
		value string
	}
	type args struct {
		endpointSelector EndpointSelector
		add              match
	}
	tests := []struct {
		name string
		args args
		want EndpointSelector
	}{
		{
			name: "add-match-to-empty-selector",
			args: args{
				endpointSelector: NewESFromMatchRequirements(nil, nil),
				add: match{
					key: "role",
					value: "foo",
				},
			},
			want: EndpointSelector(
				NewESFromMatchRequirements(
					map[string]string{
						"role": "foo",
					},
					nil,
				),
			),
		},
		{
			name: "replace-match-in-selector",
			args: args{
				endpointSelector: NewESFromMatchRequirements(
					map[string]string{
						"role": "foo",
					},
					nil,
				),
				add: match{
					key: "role",
					value: "bar",
				},
			},
			want: EndpointSelector(
				NewESFromMatchRequirements(
					map[string]string{
						"role": "bar",
					},
					nil,
				),
			),
		},
		{
			name: "remove-requirement-during-add",
			args: args{
				endpointSelector: NewESFromMatchRequirements(
					map[string]string{
						"role": "foo",
					},
					[]metav1.LabelSelectorRequirement{
						{
							Key: "role",
							Operator: "Equals",
							Values: []string{
								"baz",
							},
						},
					},
				),
				add: match{
					key: "role",
					value: "bar",
				},
			},
			want: EndpointSelector(
				NewESFromMatchRequirements(
					map[string]string{
						"role": "bar",
					},
					nil,
				),
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			es := tt.args.endpointSelector
			es.AddMatch(tt.args.add.key, tt.args.add.value)
			args := []interface{}{es, tt.want}
			names := []string{"obtained", "expected"}
			if equal, err := comparator.DeepEquals.Check(args, names); !equal {
				t.Errorf("Failed to EndpointSelector.AddMatch():\n%s", err)
			}
		})
	}
}
