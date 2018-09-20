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

package k8s

import (
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"

	. "gopkg.in/check.v1"
	"k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (s *K8sSuite) Test_missingK8sNetworkPolicyV1(c *C) {
	type args struct {
		o1 *v1.NetworkPolicy
		o2 *v1.NetworkPolicy
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "KNP with the same name",
			args: args{
				o1: &v1.NetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name: "rule1",
					},
				},
				o2: &v1.NetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name: "rule1",
					},
				},
			},
			want: true,
		},
		{
			name: "KNP with the different spec",
			args: args{
				o1: &v1.NetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name: "rule1",
					},
					Spec: v1.NetworkPolicySpec{
						PodSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{
								"foo": "bar",
							},
						},
					},
				},
				o2: &v1.NetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name: "rule1",
					},
				},
			},
			want: false,
		},
		{
			name: "KNP with the same spec",
			args: args{
				o1: &v1.NetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name: "rule1",
					},
					Spec: v1.NetworkPolicySpec{},
				},
				o2: &v1.NetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name: "rule1",
					},
					Spec: v1.NetworkPolicySpec{},
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		got := equalV1NetworkPolicy(tt.args.o1, tt.args.o2)
		c.Assert(got, Equals, tt.want, Commentf("Test Name: %s", tt.name))
	}
}

func (s *K8sSuite) Test_equalV2CNP(c *C) {
	type args struct {
		o1 *v2.CiliumNetworkPolicy
		o2 *v2.CiliumNetworkPolicy
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "CNP with the same name",
			args: args{
				o1: &v2.CiliumNetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name: "rule1",
					},
				},
				o2: &v2.CiliumNetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name: "rule1",
					},
				},
			},
			want: true,
		},
		{
			name: "CNP with the different spec",
			args: args{
				o1: &v2.CiliumNetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name: "rule1",
					},
					Spec: &api.Rule{
						EndpointSelector: api.NewESFromLabels(labels.NewLabel("foo", "bar", "k8s")),
					},
				},
				o2: &v2.CiliumNetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name: "rule1",
					},
					Spec: nil,
				},
			},
			want: false,
		},
		{
			name: "CNP with the same spec",
			args: args{
				o1: &v2.CiliumNetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name: "rule1",
					},
					Spec: &api.Rule{},
				},
				o2: &v2.CiliumNetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name: "rule1",
					},
					Spec: &api.Rule{},
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		got := equalV2CNP(tt.args.o1, tt.args.o2)
		c.Assert(got, Equals, tt.want, Commentf("Test Name: %s", tt.name))
	}
}
