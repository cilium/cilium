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
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"

	. "gopkg.in/check.v1"
	core_v1 "k8s.io/api/core/v1"
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

func (s *K8sSuite) Test_equalV1Endpoints(c *C) {
	type args struct {
		o1 *core_v1.Endpoints
		o2 *core_v1.Endpoints
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "EPs with the same name",
			args: args{
				o1: &core_v1.Endpoints{
					ObjectMeta: metav1.ObjectMeta{
						Name: "rule1",
					},
				},
				o2: &core_v1.Endpoints{
					ObjectMeta: metav1.ObjectMeta{
						Name: "rule1",
					},
				},
			},
			want: true,
		},
		{
			name: "EPs with the different spec",
			args: args{
				o1: &core_v1.Endpoints{
					ObjectMeta: metav1.ObjectMeta{
						Name: "rule1",
					},
					Subsets: []core_v1.EndpointSubset{
						{
							Addresses: []core_v1.EndpointAddress{
								{
									IP: "172.0.0.1",
								},
							},
						},
					},
				},
				o2: &core_v1.Endpoints{
					ObjectMeta: metav1.ObjectMeta{
						Name: "rule1",
					},
				},
			},
			want: false,
		},
		{
			name: "EPs with the same spec",
			args: args{
				o1: &core_v1.Endpoints{
					ObjectMeta: metav1.ObjectMeta{
						Name: "rule1",
					},
					Subsets: []core_v1.EndpointSubset{
						{
							Addresses: []core_v1.EndpointAddress{
								{
									IP: "172.0.0.1",
								},
							},
						},
					},
				},
				o2: &core_v1.Endpoints{
					ObjectMeta: metav1.ObjectMeta{
						Name: "rule1",
					},
					Subsets: []core_v1.EndpointSubset{
						{
							Addresses: []core_v1.EndpointAddress{
								{
									IP: "172.0.0.1",
								},
							},
						},
					},
				},
			},
			want: true,
		},
		{
			name: "EPs with the same spec (multiple IPs)",
			args: args{
				o1: &core_v1.Endpoints{
					ObjectMeta: metav1.ObjectMeta{
						Name: "rule1",
					},
					Subsets: []core_v1.EndpointSubset{
						{
							Addresses: []core_v1.EndpointAddress{
								{
									IP: "172.0.0.1",
								},
								{
									IP: "172.0.0.2",
								},
							},
						},
					},
				},
				o2: &core_v1.Endpoints{
					ObjectMeta: metav1.ObjectMeta{
						Name: "rule1",
					},
					Subsets: []core_v1.EndpointSubset{
						{
							Addresses: []core_v1.EndpointAddress{
								{
									IP: "172.0.0.1",
								},
								{
									IP: "172.0.0.2",
								},
							},
						},
					},
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		got := equalV1Endpoints(tt.args.o1, tt.args.o2)
		c.Assert(got, Equals, tt.want, Commentf("Test Name: %s", tt.name))
	}
}

func (s *K8sSuite) Test_equalV1Pod(c *C) {
	type args struct {
		o1 interface{}
		o2 interface{}
	}
	tests := []struct {
		name string
		args args
		want bool
	}{

		{
			name: "Pods with the same name",
			args: args{
				o1: &core_v1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name: "pod1",
					},
				},
				o2: &core_v1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name: "pod1",
					},
				},
			},
			want: true,
		},
		{
			name: "Pods with the different spec",
			args: args{
				o1: &core_v1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name: "pod1",
					},
					Status: core_v1.PodStatus{
						HostIP: "127.0.0.1",
						PodIP:  "127.0.0.2",
					},
				},
				o2: &core_v1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name: "pod1",
					},
					Status: core_v1.PodStatus{
						HostIP: "127.0.0.1",
						PodIP:  "127.0.0.1",
					},
				},
			},
			want: false,
		},
		{
			name: "Pods with the same spec",
			args: args{
				o1: &core_v1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name: "pod1",
					},
					Status: core_v1.PodStatus{
						HostIP: "127.0.0.1",
						PodIP:  "127.0.0.2",
					},
				},
				o2: &core_v1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name: "pod1",
					},
					Status: core_v1.PodStatus{
						HostIP: "127.0.0.1",
						PodIP:  "127.0.0.2",
					},
				},
			},
			want: true,
		},
		{
			name: "Pods with the same spec but different labels",
			args: args{
				o1: &core_v1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name: "pod1",
						Labels: map[string]string{
							"foo": "bar",
						},
					},
					Status: core_v1.PodStatus{
						HostIP: "127.0.0.1",
						PodIP:  "127.0.0.2",
					},
				},
				o2: &core_v1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name: "pod1",
					},
					Status: core_v1.PodStatus{
						HostIP: "127.0.0.1",
						PodIP:  "127.0.0.2",
					},
				},
			},
			want: false,
		},
		{
			name: "Pods with the same spec and same labels",
			args: args{
				o1: &core_v1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name: "pod1",
						Labels: map[string]string{
							"foo": "bar",
						},
					},
					Status: core_v1.PodStatus{
						HostIP: "127.0.0.1",
						PodIP:  "127.0.0.2",
					},
				},
				o2: &core_v1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name: "pod1",
						Labels: map[string]string{
							"foo": "bar",
						},
					},
					Status: core_v1.PodStatus{
						HostIP: "127.0.0.1",
						PodIP:  "127.0.0.2",
					},
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		got := equalV1Pod(tt.args.o1, tt.args.o2)
		c.Assert(got, Equals, tt.want, Commentf("Test Name: %s", tt.name))
	}
}

func (s *K8sSuite) Test_equalV1Node(c *C) {
	type args struct {
		o1 interface{}
		o2 interface{}
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Nodes with the same name",
			args: args{
				o1: &core_v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: "Node1",
					},
				},
				o2: &core_v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: "Node1",
					},
				},
			},
			want: true,
		},
		{
			name: "Nodes with the different names",
			args: args{
				o1: &core_v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: "Node1",
					},
				},
				o2: &core_v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: "Node2",
					},
				},
			},
			want: false,
		},
		{
			name: "Nodes with the different spec should return true as we don't care about the spec",
			args: args{
				o1: &core_v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: "Node1",
					},
					Spec: core_v1.NodeSpec{
						PodCIDR: "192.168.0.0/10",
					},
				},
				o2: &core_v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: "Node1",
					},
					Spec: core_v1.NodeSpec{
						PodCIDR: "127.0.0.1/10",
					},
				},
			},
			want: true,
		},
		{
			name: "Nodes with the same annotations",
			args: args{
				o1: &core_v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: "Node1",
						Annotations: map[string]string{
							annotation.CiliumHostIP: "127.0.0.1",
						},
					},
				},
				o2: &core_v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: "Node1",
						Annotations: map[string]string{
							annotation.CiliumHostIP: "127.0.0.1",
						},
					},
				},
			},
			want: true,
		},
		{
			name: "Nodes with the different annotations",
			args: args{
				o1: &core_v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: "Node1",
						Annotations: map[string]string{
							annotation.CiliumHostIP: "127.0.0.1",
						},
					},
				},
				o2: &core_v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: "Node1",
						Annotations: map[string]string{
							annotation.CiliumHostIP: "127.0.0.2",
						},
					},
				},
			},
			want: false,
		},
		{
			name: "Nodes with the same annotations and different specs should return true because he don't care about the spec",
			args: args{
				o1: &core_v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: "Node1",
						Annotations: map[string]string{
							annotation.CiliumHostIP: "127.0.0.1",
						},
					},
					Spec: core_v1.NodeSpec{
						PodCIDR: "192.168.0.0/10",
					},
				},
				o2: &core_v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: "Node1",
						Annotations: map[string]string{
							annotation.CiliumHostIP: "127.0.0.1",
						},
					},
					Spec: core_v1.NodeSpec{
						PodCIDR: "127.0.0.1/10",
					},
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		got := equalV1Node(tt.args.o1, tt.args.o2)
		c.Assert(got, Equals, tt.want, Commentf("Test Name: %s", tt.name))
	}
}

func (s *K8sSuite) Test_equalV1Namespace(c *C) {
	type args struct {
		o1 interface{}
		o2 interface{}
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Namespaces with the same name",
			args: args{
				o1: &core_v1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "Namespace1",
					},
				},
				o2: &core_v1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "Namespace1",
					},
				},
			},
			want: true,
		},
		{
			name: "Namespaces with the different names",
			args: args{
				o1: &core_v1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "Namespace1",
					},
				},
				o2: &core_v1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "Namespace2",
					},
				},
			},
			want: false,
		},
		{
			name: "Namespaces with the different spec should return true as we don't care about the spec",
			args: args{
				o1: &core_v1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "Namespace1",
					},
					Spec: core_v1.NamespaceSpec{
						Finalizers: []core_v1.FinalizerName{
							core_v1.FinalizerName("foo"),
						},
					},
				},
				o2: &core_v1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "Namespace1",
					},
				},
			},
			want: true,
		},
		{
			name: "Namespaces with the same labels",
			args: args{
				o1: &core_v1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "Namespace1",
						Labels: map[string]string{
							"prod": "true",
						},
					},
				},
				o2: &core_v1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "Namespace1",
						Labels: map[string]string{
							"prod": "true",
						},
					},
				},
			},
			want: true,
		},
		{
			name: "Namespaces with the different labels",
			args: args{
				o1: &core_v1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "Namespace1",
						Labels: map[string]string{
							"prod": "true",
						},
					},
				},
				o2: &core_v1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "Namespace1",
						Labels: map[string]string{
							"prod": "false",
						},
					},
				},
			},
			want: false,
		},
		{
			name: "Namespaces with the same annotations and different specs should return true because he don't care about the spec",
			args: args{
				o1: &core_v1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "Namespace1",
						Labels: map[string]string{
							"prod": "false",
						},
					},
					Spec: core_v1.NamespaceSpec{
						Finalizers: []core_v1.FinalizerName{
							core_v1.FinalizerName("foo"),
						},
					},
				},
				o2: &core_v1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "Namespace1",
						Labels: map[string]string{
							"prod": "false",
						},
					},
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		got := equalV1Namespace(tt.args.o1, tt.args.o2)
		c.Assert(got, Equals, tt.want, Commentf("Test Name: %s", tt.name))
	}
}
