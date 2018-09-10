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

package utils

import (
	"fmt"
	"testing"

	"github.com/cilium/cilium/pkg/checker"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"

	. "gopkg.in/check.v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type CiliumUtilsSuite struct{}

var _ = Suite(&CiliumUtilsSuite{})

func (s *CiliumUtilsSuite) Test_namespacesAreValid(c *C) {
	c.Assert(namespacesAreValid("default", []string{}), Equals, true)
	c.Assert(namespacesAreValid("default", []string{"default"}), Equals, true)
	c.Assert(namespacesAreValid("default", []string{"foo"}), Equals, false)
	c.Assert(namespacesAreValid("default", []string{"default", "foo"}), Equals, false)
}

func Test_ParseToCiliumRule(t *testing.T) {
	role := fmt.Sprintf("%s.role", labels.LabelSourceAny)
	namespace := fmt.Sprintf("%s.%s", labels.LabelSourceK8s, k8sConst.PodNamespaceLabel)
	type args struct {
		namespace string
		rule      *api.Rule
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
				namespace: metav1.NamespaceDefault,
				rule: &api.Rule{
					EndpointSelector: api.NewESFromMatchRequirements(
						map[string]string{
							role: "backend",
						},
						nil,
					),
				},
			},
			want: &api.Rule{
				EndpointSelector: api.NewESFromMatchRequirements(
					map[string]string{
						role:      "backend",
						namespace: "default",
					},
					nil,
				),
				Labels: labels.LabelArray{
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
				},
			},
		},
		{
			// When the rule specifies a namespace, it is overridden
			// by the namespace where the rule was inserted.
			name: "parse-in-namespace-with-ns-selector",
			args: args{
				namespace: metav1.NamespaceDefault,
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
			want: &api.Rule{
				EndpointSelector: api.NewESFromMatchRequirements(
					map[string]string{
						role:      "backend",
						namespace: "default",
					},
					nil,
				),
				Labels: labels.LabelArray{
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
				},
			},
		},
		{
			// Don't insert a namespace selection when the rule
			// is for init policies.
			name: "parse-init-policy",
			args: args{
				namespace: metav1.NamespaceDefault,
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
			want: &api.Rule{
				EndpointSelector: api.NewESFromMatchRequirements(
					map[string]string{
						role:       "backend",
						podInitLbl: "",
						// No namespace because it's init.
						// namespace: "default",
					},
					nil,
				),
				Labels: labels.LabelArray{
					{
						Key:    "io.cilium.k8s.policy.name",
						Value:  "parse-init-policy",
						Source: labels.LabelSourceK8s,
					},
					{
						Key:    "io.cilium.k8s.policy.namespace",
						Value:  "default",
						Source: labels.LabelSourceK8s,
					},
				},
			},
		},
		{
			name: "set-any-source-for-namespace",
			args: args{
				namespace: metav1.NamespaceDefault,
				rule: &api.Rule{
					EndpointSelector: api.NewESFromMatchRequirements(
						map[string]string{
							role: "backend",
						},
						nil,
					),
					Ingress: []api.IngressRule{
						{
							FromEndpoints: []api.EndpointSelector{
								{
									LabelSelector: &metav1.LabelSelector{
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
			want: &api.Rule{
				EndpointSelector: api.NewESFromMatchRequirements(
					map[string]string{
						role:      "backend",
						namespace: "default",
					},
					nil,
				),
				Ingress: []api.IngressRule{
					{
						FromEndpoints: []api.EndpointSelector{
							api.NewESFromK8sLabelSelector(
								labels.LabelSourceAnyKeyPrefix,
								&metav1.LabelSelector{
									MatchLabels: map[string]string{
										k8sConst.PodNamespaceLabel: "ns-2",
									},
								}),
						},
					},
				},
				Labels: labels.LabelArray{
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
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseToCiliumRule(tt.args.namespace, tt.name, tt.args.rule)
			args := []interface{}{got, tt.want}
			names := []string{"obtained", "expected"}
			if equal, err := checker.DeepEquals.Check(args, names); !equal {
				t.Errorf("Failed to ParseToCiliumRule():\n%s", err)
			}
		})
	}
}
