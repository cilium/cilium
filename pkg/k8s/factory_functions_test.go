// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"time"

	. "github.com/cilium/checkmate"
	core_v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/checker"
	fakeDatapath "github.com/cilium/cilium/pkg/datapath/fake"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
)

func (s *K8sSuite) Test_EqualV2CNP(c *C) {
	type args struct {
		o1 *types.SlimCNP
		o2 *types.SlimCNP
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "CNP with the same name",
			args: args{
				o1: &types.SlimCNP{
					CiliumNetworkPolicy: &v2.CiliumNetworkPolicy{
						ObjectMeta: metav1.ObjectMeta{
							Name: "rule1",
						},
					},
				},
				o2: &types.SlimCNP{
					CiliumNetworkPolicy: &v2.CiliumNetworkPolicy{
						ObjectMeta: metav1.ObjectMeta{
							Name: "rule1",
						},
					},
				},
			},
			want: true,
		},
		{
			name: "CNP with the different spec",
			args: args{
				o1: &types.SlimCNP{
					CiliumNetworkPolicy: &v2.CiliumNetworkPolicy{
						ObjectMeta: metav1.ObjectMeta{
							Name: "rule1",
						},
						Spec: &api.Rule{
							EndpointSelector: api.NewESFromLabels(labels.NewLabel("foo", "bar", "k8s")),
						},
					},
				},
				o2: &types.SlimCNP{
					CiliumNetworkPolicy: &v2.CiliumNetworkPolicy{
						ObjectMeta: metav1.ObjectMeta{
							Name: "rule1",
						},
						Spec: nil,
					},
				},
			},
			want: false,
		},
		{
			name: "CNP with the same spec",
			args: args{
				o1: &types.SlimCNP{
					CiliumNetworkPolicy: &v2.CiliumNetworkPolicy{
						ObjectMeta: metav1.ObjectMeta{
							Name: "rule1",
						},
						Spec: &api.Rule{},
					},
				},
				o2: &types.SlimCNP{
					CiliumNetworkPolicy: &v2.CiliumNetworkPolicy{
						ObjectMeta: metav1.ObjectMeta{
							Name: "rule1",
						},
						Spec: &api.Rule{},
					},
				},
			},
			want: true,
		},
		{
			name: "CNP with different last applied annotations. The are ignored so they should be equal",
			args: args{
				o1: &types.SlimCNP{
					CiliumNetworkPolicy: &v2.CiliumNetworkPolicy{
						ObjectMeta: metav1.ObjectMeta{
							Name: "rule1",
							Annotations: map[string]string{
								core_v1.LastAppliedConfigAnnotation: "foo",
							},
						},
						Spec: &api.Rule{},
					},
				},
				o2: &types.SlimCNP{
					CiliumNetworkPolicy: &v2.CiliumNetworkPolicy{
						ObjectMeta: metav1.ObjectMeta{
							Name: "rule1",
							Annotations: map[string]string{
								core_v1.LastAppliedConfigAnnotation: "bar",
							},
						},
						Spec: &api.Rule{},
					},
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		got := tt.args.o1.DeepEqual(tt.args.o2)
		c.Assert(got, Equals, tt.want, Commentf("Test Name: %s", tt.name))
	}
}

func (s *K8sSuite) Test_EqualV1Endpoints(c *C) {
	type args struct {
		o1 *slim_corev1.Endpoints
		o2 *slim_corev1.Endpoints
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "EPs with the same name",
			args: args{
				o1: &slim_corev1.Endpoints{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "rule1",
					},
				},
				o2: &slim_corev1.Endpoints{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "rule1",
					},
				},
			},
			want: true,
		},
		{
			name: "EPs with the different spec",
			args: args{
				o1: &slim_corev1.Endpoints{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "rule1",
					},
					Subsets: []slim_corev1.EndpointSubset{
						{
							Addresses: []slim_corev1.EndpointAddress{
								{
									IP: "172.0.0.1",
								},
							},
						},
					},
				},
				o2: &slim_corev1.Endpoints{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "rule1",
					},
				},
			},
			want: false,
		},
		{
			name: "EPs with the same spec",
			args: args{
				o1: &slim_corev1.Endpoints{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "rule1",
					},
					Subsets: []slim_corev1.EndpointSubset{
						{
							Addresses: []slim_corev1.EndpointAddress{
								{
									IP: "172.0.0.1",
								},
							},
						},
					},
				},
				o2: &slim_corev1.Endpoints{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "rule1",
					},
					Subsets: []slim_corev1.EndpointSubset{
						{
							Addresses: []slim_corev1.EndpointAddress{
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
				o1: &slim_corev1.Endpoints{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "rule1",
					},
					Subsets: []slim_corev1.EndpointSubset{
						{
							Addresses: []slim_corev1.EndpointAddress{
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
				o2: &slim_corev1.Endpoints{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "rule1",
					},
					Subsets: []slim_corev1.EndpointSubset{
						{
							Addresses: []slim_corev1.EndpointAddress{
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
		got := tt.args.o1.DeepEqual(tt.args.o2)
		c.Assert(got, Equals, tt.want, Commentf("Test Name: %s", tt.name))
	}
}

func (s *K8sSuite) Test_EqualV1Pod(c *C) {
	type args struct {
		o1 *slim_corev1.Pod
		o2 *slim_corev1.Pod
	}
	tests := []struct {
		name string
		args args
		want bool
	}{

		{
			name: "Pods with the same name",
			args: args{
				o1: &slim_corev1.Pod{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "pod1",
					},
				},
				o2: &slim_corev1.Pod{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "pod1",
					},
				},
			},
			want: true,
		},
		{
			name: "Pods with the different spec",
			args: args{
				o1: &slim_corev1.Pod{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "pod1",
					},
					Status: slim_corev1.PodStatus{
						HostIP: "127.0.0.1",
						PodIPs: []slim_corev1.PodIP{
							{
								IP: "127.0.0.2",
							},
						},
					},
				},
				o2: &slim_corev1.Pod{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "pod1",
					},
					Status: slim_corev1.PodStatus{
						HostIP: "127.0.0.1",
						PodIPs: []slim_corev1.PodIP{
							{
								IP: "127.0.0.1",
							},
						},
					},
				},
			},
			want: false,
		},
		{
			name: "Pods with the same spec",
			args: args{
				o1: &slim_corev1.Pod{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "pod1",
					},
					Status: slim_corev1.PodStatus{
						HostIP: "127.0.0.1",
						PodIPs: []slim_corev1.PodIP{
							{
								IP: "127.0.0.2",
							},
						},
					},
				},
				o2: &slim_corev1.Pod{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "pod1",
					},
					Status: slim_corev1.PodStatus{
						HostIP: "127.0.0.1",
						PodIPs: []slim_corev1.PodIP{
							{
								IP: "127.0.0.2",
							},
						},
					},
				},
			},
			want: true,
		},
		{
			name: "Pods with the same spec but different labels",
			args: args{
				o1: &slim_corev1.Pod{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "pod1",
						Labels: map[string]string{
							"foo": "bar",
						},
					},
					Status: slim_corev1.PodStatus{
						HostIP: "127.0.0.1",
						PodIPs: []slim_corev1.PodIP{
							{
								IP: "127.0.0.2",
							},
						},
					},
				},
				o2: &slim_corev1.Pod{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "pod1",
					},
					Status: slim_corev1.PodStatus{
						HostIP: "127.0.0.1",
						PodIPs: []slim_corev1.PodIP{
							{
								IP: "127.0.0.2",
							},
						},
					},
				},
			},
			want: false,
		},
		{
			name: "Pods with the same spec and same labels",
			args: args{
				o1: &slim_corev1.Pod{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "pod1",
						Labels: map[string]string{
							"foo": "bar",
						},
					},
					Status: slim_corev1.PodStatus{
						HostIP: "127.0.0.1",
						PodIPs: []slim_corev1.PodIP{
							{
								IP: "127.0.0.2",
							},
						},
					},
				},
				o2: &slim_corev1.Pod{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "pod1",
						Labels: map[string]string{
							"foo": "bar",
						},
					},
					Status: slim_corev1.PodStatus{
						HostIP: "127.0.0.1",
						PodIPs: []slim_corev1.PodIP{
							{
								IP: "127.0.0.2",
							},
						},
					},
				},
			},
			want: true,
		},
		{
			name: "Pods with differing proxy-visibility annotations",
			args: args{
				o1: &slim_corev1.Pod{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "pod1",
						Labels: map[string]string{
							"foo": "bar",
						},
					},
					Status: slim_corev1.PodStatus{
						HostIP: "127.0.0.1",
						PodIPs: []slim_corev1.PodIP{
							{
								IP: "127.0.0.2",
							},
						},
					},
				},
				o2: &slim_corev1.Pod{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "pod1",
						Labels: map[string]string{
							"foo": "bar",
						},
						Annotations: map[string]string{
							annotation.ProxyVisibility: "80/HTTP",
						},
					},
					Status: slim_corev1.PodStatus{
						HostIP: "127.0.0.1",
						PodIPs: []slim_corev1.PodIP{
							{
								IP: "127.0.0.2",
							},
						},
					},
				},
			},
			want: false,
		},
		{
			name: "Pods with irrelevant annotations",
			args: args{
				o1: &slim_corev1.Pod{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "pod1",
						Labels: map[string]string{
							"foo": "bar",
						},
					},
					Status: slim_corev1.PodStatus{
						HostIP: "127.0.0.1",
						PodIPs: []slim_corev1.PodIP{
							{
								IP: "127.0.0.2",
							},
						},
					},
				},
				o2: &slim_corev1.Pod{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "pod1",
						Labels: map[string]string{
							"foo": "bar",
						},
						Annotations: map[string]string{
							"useless": "80/HTTP",
						},
					},
					Status: slim_corev1.PodStatus{
						HostIP: "127.0.0.1",
						PodIPs: []slim_corev1.PodIP{
							{
								IP: "127.0.0.2",
							},
						},
					},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		got := tt.args.o1.DeepEqual(tt.args.o2)
		c.Assert(got, Equals, tt.want, Commentf("Test Name: %s", tt.name))
	}
}

func (s *K8sSuite) Test_EqualV1Node(c *C) {
	type args struct {
		o1 *slim_corev1.Node
		o2 *slim_corev1.Node
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Nodes with the same name",
			args: args{
				o1: &slim_corev1.Node{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "Node1",
					},
				},
				o2: &slim_corev1.Node{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "Node1",
					},
				},
			},
			want: true,
		},
		{
			name: "Nodes with the different names",
			args: args{
				o1: &slim_corev1.Node{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "Node1",
					},
				},
				o2: &slim_corev1.Node{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "Node2",
					},
				},
			},
			want: false,
		},
		{
			name: "Nodes with the different spec should return false",
			args: args{
				o1: &slim_corev1.Node{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "Node1",
					},
					Spec: slim_corev1.NodeSpec{
						PodCIDR: "192.168.0.0/10",
					},
				},
				o2: &slim_corev1.Node{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "Node1",
					},
					Spec: slim_corev1.NodeSpec{
						PodCIDR: "127.0.0.1/10",
					},
				},
			},
			want: false,
		},
		{
			name: "Nodes with the same annotations",
			args: args{
				o1: &slim_corev1.Node{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "Node1",
						Annotations: map[string]string{
							annotation.CiliumHostIP: "127.0.0.1",
						},
					},
				},
				o2: &slim_corev1.Node{
					ObjectMeta: slim_metav1.ObjectMeta{
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
				o1: &slim_corev1.Node{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "Node1",
						Annotations: map[string]string{
							annotation.CiliumHostIP: "127.0.0.1",
						},
					},
				},
				o2: &slim_corev1.Node{
					ObjectMeta: slim_metav1.ObjectMeta{
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
			name: "Nodes with the same annotations and different specs should return false",
			args: args{
				o1: &slim_corev1.Node{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "Node1",
						Annotations: map[string]string{
							annotation.CiliumHostIP: "127.0.0.1",
						},
					},
					Spec: slim_corev1.NodeSpec{
						PodCIDR: "192.168.0.0/10",
					},
				},
				o2: &slim_corev1.Node{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "Node1",
						Annotations: map[string]string{
							annotation.CiliumHostIP: "127.0.0.1",
						},
					},
					Spec: slim_corev1.NodeSpec{
						PodCIDR: "127.0.0.1/10",
					},
				},
			},
			want: false,
		},
		{
			name: "Nodes with the same taints and different specs should return false",
			args: args{
				o1: &slim_corev1.Node{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "Node1",
					},
					Spec: slim_corev1.NodeSpec{
						PodCIDR: "192.168.0.0/10",
						Taints: []slim_corev1.Taint{
							{
								Key:    "key",
								Value:  "value",
								Effect: "no-effect",
							},
						},
					},
				},
				o2: &slim_corev1.Node{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "Node1",
					},
					Spec: slim_corev1.NodeSpec{
						PodCIDR: "127.0.0.1/10",
						Taints: []slim_corev1.Taint{
							{
								Key:    "key",
								Value:  "value",
								Effect: "no-effect",
							},
						},
					},
				},
			},
			want: false,
		},
		{
			name: "Nodes with the same taints and different specs should false",
			args: args{
				o1: &slim_corev1.Node{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "Node1",
					},
					Spec: slim_corev1.NodeSpec{
						PodCIDR: "192.168.0.0/10",
						Taints: []slim_corev1.Taint{
							{
								Key:       "key",
								Value:     "value",
								Effect:    "no-effect",
								TimeAdded: func() *slim_metav1.Time { return &slim_metav1.Time{Time: time.Unix(1, 1)} }(),
							},
						},
					},
				},
				o2: &slim_corev1.Node{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "Node1",
					},
					Spec: slim_corev1.NodeSpec{
						PodCIDR: "127.0.0.1/10",
						Taints: []slim_corev1.Taint{
							{
								Key:       "key",
								Value:     "value",
								Effect:    "no-effect",
								TimeAdded: func() *slim_metav1.Time { return &slim_metav1.Time{Time: time.Unix(1, 1)} }(),
							},
						},
					},
				},
			},
			want: false,
		},
		{
			name: "Nodes with the different taints and different specs should return false",
			args: args{
				o1: &slim_corev1.Node{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "Node1",
					},
					Spec: slim_corev1.NodeSpec{
						PodCIDR: "192.168.0.0/10",
						Taints: []slim_corev1.Taint{
							{
								Key:    "key",
								Value:  "value",
								Effect: "no-effect",
							},
						},
					},
				},
				o2: &slim_corev1.Node{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "Node1",
					}, Spec: slim_corev1.NodeSpec{
						PodCIDR: "127.0.0.1/10",
						Taints: []slim_corev1.Taint{
							{
								Key:       "key",
								Value:     "value",
								Effect:    "no-effect",
								TimeAdded: func() *slim_metav1.Time { return &slim_metav1.Time{Time: time.Unix(1, 1)} }(),
							},
						},
					},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		got := tt.args.o1.DeepEqual(tt.args.o2)
		c.Assert(got, Equals, tt.want, Commentf("Test Name: %s", tt.name))
	}
}

func (s *K8sSuite) Test_EqualV1Namespace(c *C) {
	type args struct {
		o1 *slim_corev1.Namespace
		o2 *slim_corev1.Namespace
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Namespaces with the same name",
			args: args{
				o1: &slim_corev1.Namespace{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "Namespace1",
					},
				},
				o2: &slim_corev1.Namespace{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "Namespace1",
					},
				},
			},
			want: true,
		},
		{
			name: "Namespaces with the different names",
			args: args{
				o1: &slim_corev1.Namespace{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "Namespace1",
					},
				},
				o2: &slim_corev1.Namespace{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "Namespace2",
					},
				},
			},
			want: false,
		},
		{
			name: "Namespaces with the same labels",
			args: args{
				o1: &slim_corev1.Namespace{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "Namespace1",
						Labels: map[string]string{
							"prod": "true",
						},
					},
				},
				o2: &slim_corev1.Namespace{
					ObjectMeta: slim_metav1.ObjectMeta{
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
				o1: &slim_corev1.Namespace{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "Namespace1",
						Labels: map[string]string{
							"prod": "true",
						},
					},
				},
				o2: &slim_corev1.Namespace{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "Namespace1",
						Labels: map[string]string{
							"prod": "false",
						},
					},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		got := tt.args.o1.DeepEqual(tt.args.o2)
		c.Assert(got, Equals, tt.want, Commentf("Test Name: %s", tt.name))
	}
}

func (s *K8sSuite) Test_EqualV1Service(c *C) {
	type args struct {
		o1 *slim_corev1.Service
		o2 *slim_corev1.Service
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Service with different annotations",
			args: args{
				o1: &slim_corev1.Service{
					ObjectMeta: slim_metav1.ObjectMeta{
						Annotations: map[string]string{},
					},
				},
				o2: &slim_corev1.Service{
					ObjectMeta: slim_metav1.ObjectMeta{
						Annotations: map[string]string{
							"service.cilium.io/shared": "true",
						},
					},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		got := EqualV1Services(tt.args.o1, tt.args.o2, fakeDatapath.NewNodeAddressing())
		c.Assert(got, Equals, tt.want, Commentf("Test Name: %s", tt.name))
	}
}

func (s *K8sSuite) Test_ConvertToK8sService(c *C) {
	type args struct {
		obj interface{}
	}
	tests := []struct {
		name string
		args args
		want interface{}
	}{
		{
			name: "normal conversion",
			args: args{
				obj: &core_v1.Service{},
			},
			want: &slim_corev1.Service{},
		},
		{
			name: "delete final state unknown conversion",
			args: args{
				obj: cache.DeletedFinalStateUnknown{
					Key: "foo",
					Obj: &core_v1.Service{},
				},
			},
			want: cache.DeletedFinalStateUnknown{
				Key: "foo",
				Obj: &slim_corev1.Service{},
			},
		},
		{
			name: "unknown object type in delete final state unknown conversion",
			args: args{
				obj: cache.DeletedFinalStateUnknown{
					Key: "foo",
					Obj: 100,
				},
			},
			want: cache.DeletedFinalStateUnknown{
				Key: "foo",
				Obj: 100,
			},
		},
		{
			name: "unknown object type in conversion",
			args: args{
				obj: 100,
			},
			want: 100,
		},
	}
	for _, tt := range tests {
		got := ConvertToK8sService(tt.args.obj)
		c.Assert(got, checker.DeepEquals, tt.want, Commentf("Test Name: %s", tt.name))
	}
}

func (s *K8sSuite) Test_ConvertToK8sV1ServicePorts(c *C) {
	type args struct {
		ports []slim_corev1.ServicePort
	}
	tests := []struct {
		name string
		args args
		want []core_v1.ServicePort
	}{
		{
			name: "empty",
			args: args{
				ports: []slim_corev1.ServicePort{},
			},
			want: []core_v1.ServicePort{},
		},
		{
			name: "non-empty",
			args: args{
				ports: []slim_corev1.ServicePort{
					{
						Name: "foo",
						Port: int32(1),
					},
				},
			},
			want: []core_v1.ServicePort{
				{
					Name: "foo",
					Port: int32(1),
				},
			},
		},
	}
	for _, tt := range tests {
		got := ConvertToK8sV1ServicePorts(tt.args.ports)
		c.Assert(got, checker.DeepEquals, tt.want, Commentf("Test Name: %s", tt.name))
	}
}

func (s *K8sSuite) Test_ConvertToK8sV1SessionAffinityConfig(c *C) {
	ts := int32(1)
	type args struct {
		cfg *slim_corev1.SessionAffinityConfig
	}
	tests := []struct {
		name string
		args args
		want *core_v1.SessionAffinityConfig
	}{
		{
			name: "empty",
			args: args{
				cfg: &slim_corev1.SessionAffinityConfig{},
			},
			want: &core_v1.SessionAffinityConfig{},
		},
		{
			name: "non-empty",
			args: args{
				cfg: &slim_corev1.SessionAffinityConfig{
					ClientIP: &slim_corev1.ClientIPConfig{
						TimeoutSeconds: &ts,
					},
				},
			},
			want: &core_v1.SessionAffinityConfig{
				ClientIP: &core_v1.ClientIPConfig{
					TimeoutSeconds: &ts,
				},
			},
		},
	}
	for _, tt := range tests {
		got := ConvertToK8sV1ServiceAffinityConfig(tt.args.cfg)
		c.Assert(got, checker.DeepEquals, tt.want, Commentf("Test Name: %s", tt.name))
	}
}

func (s *K8sSuite) Test_ConvertToK8sV1LoadBalancerIngress(c *C) {
	type args struct {
		ings []slim_corev1.LoadBalancerIngress
	}
	tests := []struct {
		name string
		args args
		want []core_v1.LoadBalancerIngress
	}{
		{
			name: "empty",
			args: args{
				ings: []slim_corev1.LoadBalancerIngress{},
			},
			want: []core_v1.LoadBalancerIngress{},
		},
		{
			name: "non-empty",
			args: args{
				ings: []slim_corev1.LoadBalancerIngress{
					{
						IP: "1.1.1.1",
					},
				},
			},
			want: []core_v1.LoadBalancerIngress{
				{
					IP:    "1.1.1.1",
					Ports: nil,
				},
			},
		},
	}
	for _, tt := range tests {
		got := ConvertToK8sV1LoadBalancerIngress(tt.args.ings)
		c.Assert(got, checker.DeepEquals, tt.want, Commentf("Test Name: %s", tt.name))
	}
}

func (s *K8sSuite) Test_ConvertToNetworkV1IngressLoadBalancerIngress(c *C) {
	type args struct {
		ings []slim_corev1.LoadBalancerIngress
	}
	tests := []struct {
		name string
		args args
		want []networkingv1.IngressLoadBalancerIngress
	}{
		{
			name: "empty",
			args: args{
				ings: []slim_corev1.LoadBalancerIngress{},
			},
			want: []networkingv1.IngressLoadBalancerIngress{},
		},
		{
			name: "non-empty",
			args: args{
				ings: []slim_corev1.LoadBalancerIngress{
					{
						IP: "1.1.1.1",
					},
				},
			},
			want: []networkingv1.IngressLoadBalancerIngress{
				{
					IP:    "1.1.1.1",
					Ports: []networkingv1.IngressPortStatus{},
				},
			},
		},
	}
	for _, tt := range tests {
		got := ConvertToNetworkV1IngressLoadBalancerIngress(tt.args.ings)
		c.Assert(got, checker.DeepEquals, tt.want, Commentf("Test Name: %s", tt.name))
	}
}

func (s *K8sSuite) Test_ConvertToSlimIngressLoadBalancerStatus(c *C) {
	type args struct {
		lbs *slim_corev1.LoadBalancerStatus
	}
	tests := []struct {
		name string
		args args
		want *slim_networkingv1.IngressLoadBalancerStatus
	}{
		{
			name: "empty",
			args: args{
				lbs: &slim_corev1.LoadBalancerStatus{},
			},
			want: &slim_networkingv1.IngressLoadBalancerStatus{
				Ingress: []slim_networkingv1.IngressLoadBalancerIngress{},
			},
		},
		{
			name: "non-empty",
			args: args{
				lbs: &slim_corev1.LoadBalancerStatus{
					Ingress: []slim_corev1.LoadBalancerIngress{
						{
							IP:    "1.1.1.1",
							Ports: []slim_corev1.PortStatus{},
						},
					},
				},
			},
			want: &slim_networkingv1.IngressLoadBalancerStatus{
				Ingress: []slim_networkingv1.IngressLoadBalancerIngress{
					{
						IP:    "1.1.1.1",
						Ports: []slim_networkingv1.IngressPortStatus{},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		got := ConvertToSlimIngressLoadBalancerStatus(tt.args.lbs)
		c.Assert(got, checker.DeepEquals, tt.want, Commentf("Test Name: %s", tt.name))
	}
}

func (s *K8sSuite) Test_ConvertToCNP(c *C) {
	type args struct {
		obj interface{}
	}
	tests := []struct {
		name string
		args args
		want interface{}
	}{
		{
			name: "normal conversion",
			args: args{
				obj: &v2.CiliumNetworkPolicy{},
			},
			want: &types.SlimCNP{
				CiliumNetworkPolicy: &v2.CiliumNetworkPolicy{},
			},
		},
		{
			name: "delete final state unknown conversion",
			args: args{
				obj: cache.DeletedFinalStateUnknown{
					Key: "foo",
					Obj: &v2.CiliumNetworkPolicy{},
				},
			},
			want: cache.DeletedFinalStateUnknown{
				Key: "foo",
				Obj: &types.SlimCNP{
					CiliumNetworkPolicy: &v2.CiliumNetworkPolicy{},
				},
			},
		},
		{
			name: "unknown object type in delete final state unknown conversion",
			args: args{
				obj: cache.DeletedFinalStateUnknown{
					Key: "foo",
					Obj: 100,
				},
			},
			want: cache.DeletedFinalStateUnknown{
				Key: "foo",
				Obj: 100,
			},
		},
		{
			name: "unknown object type in conversion",
			args: args{
				obj: 100,
			},
			want: 100,
		},
	}
	for _, tt := range tests {
		got := ConvertToCNP(tt.args.obj)
		c.Assert(got, checker.DeepEquals, tt.want, Commentf("Test Name: %s", tt.name))
	}
}

func (s *K8sSuite) Test_ConvertToCCNP(c *C) {
	type args struct {
		obj interface{}
	}
	tests := []struct {
		name string
		args args
		want interface{}
	}{
		{
			name: "normal conversion",
			args: args{
				obj: &v2.CiliumClusterwideNetworkPolicy{},
			},
			want: &types.SlimCNP{
				CiliumNetworkPolicy: &v2.CiliumNetworkPolicy{},
			},
		},
		{
			name: "A CCNP where it doesn't contain neither a spec nor specs",
			args: args{
				obj: &v2.CiliumClusterwideNetworkPolicy{},
			},
			want: &types.SlimCNP{
				CiliumNetworkPolicy: &v2.CiliumNetworkPolicy{},
			},
		},
		{
			name: "delete final state unknown conversion",
			args: args{
				obj: cache.DeletedFinalStateUnknown{
					Key: "foo",
					Obj: &v2.CiliumClusterwideNetworkPolicy{},
				},
			},
			want: cache.DeletedFinalStateUnknown{
				Key: "foo",
				Obj: &types.SlimCNP{
					CiliumNetworkPolicy: &v2.CiliumNetworkPolicy{},
				},
			},
		},
		{
			name: "unknown object type in delete final state unknown conversion",
			args: args{
				obj: cache.DeletedFinalStateUnknown{
					Key: "foo",
					Obj: 100,
				},
			},
			want: cache.DeletedFinalStateUnknown{
				Key: "foo",
				Obj: 100,
			},
		},
		{
			name: "unknown object type in conversion",
			args: args{
				obj: 100,
			},
			want: 100,
		},
	}
	for _, tt := range tests {
		got := ConvertToCCNP(tt.args.obj)
		c.Assert(got, checker.DeepEquals, tt.want, Commentf("Test Name: %s", tt.name))
	}
}

func (s *K8sSuite) Test_ConvertToNode(c *C) {
	type args struct {
		obj interface{}
	}
	tests := []struct {
		name string
		args args
		want interface{}
	}{
		{
			name: "normal conversion",
			args: args{
				obj: &core_v1.Node{},
			},
			want: &slim_corev1.Node{},
		},
		{
			name: "delete final state unknown conversion",
			args: args{
				obj: cache.DeletedFinalStateUnknown{
					Key: "foo",
					Obj: &core_v1.Node{},
				},
			},
			want: cache.DeletedFinalStateUnknown{
				Key: "foo",
				Obj: &slim_corev1.Node{},
			},
		},
		{
			name: "unknown object type in delete final state unknown conversion",
			args: args{
				obj: cache.DeletedFinalStateUnknown{
					Key: "foo",
					Obj: 100,
				},
			},
			want: cache.DeletedFinalStateUnknown{
				Key: "foo",
				Obj: 100,
			},
		},
		{
			name: "unknown object type in conversion",
			args: args{
				obj: 100,
			},
			want: 100,
		},
	}
	for _, tt := range tests {
		got := ConvertToNode(tt.args.obj)
		c.Assert(got, checker.DeepEquals, tt.want, Commentf("Test Name: %s", tt.name))
	}
}

func (s *K8sSuite) Test_ConvertToCiliumNode(c *C) {
	type args struct {
		obj interface{}
	}
	tests := []struct {
		name string
		args args
		want interface{}
	}{
		{
			name: "normal conversion",
			args: args{
				obj: &v2.CiliumNode{},
			},
			want: &v2.CiliumNode{},
		},
		{
			name: "delete final state unknown conversion",
			args: args{
				obj: cache.DeletedFinalStateUnknown{
					Key: "foo",
					Obj: &v2.CiliumNode{},
				},
			},
			want: cache.DeletedFinalStateUnknown{
				Key: "foo",
				Obj: &v2.CiliumNode{},
			},
		},
		{
			name: "unknown object type in delete final state unknown conversion",
			args: args{
				obj: cache.DeletedFinalStateUnknown{
					Key: "foo",
					Obj: 100,
				},
			},
			want: cache.DeletedFinalStateUnknown{
				Key: "foo",
				Obj: 100,
			},
		},
		{
			name: "unknown object type in conversion",
			args: args{
				obj: 100,
			},
			want: 100,
		},
	}
	for _, tt := range tests {
		got := ConvertToCiliumNode(tt.args.obj)
		c.Assert(got, checker.DeepEquals, tt.want, Commentf("Test Name: %s", tt.name))
	}
}

func (s *K8sSuite) Test_ConvertToCiliumEndpoint(c *C) {
	type args struct {
		obj interface{}
	}
	tests := []struct {
		name string
		args args
		want interface{}
	}{
		{
			name: "normal conversion",
			args: args{
				obj: &v2.CiliumEndpoint{},
			},
			want: &types.CiliumEndpoint{
				Encryption: &v2.EncryptionSpec{},
			},
		},
		{
			name: "delete final state unknown conversion",
			args: args{
				obj: cache.DeletedFinalStateUnknown{
					Key: "foo",
					Obj: &v2.CiliumEndpoint{
						TypeMeta: metav1.TypeMeta{
							Kind:       "CiliumEndpoint",
							APIVersion: "v2",
						},
						ObjectMeta: metav1.ObjectMeta{
							Name:            "foo",
							GenerateName:    "generated-Foo",
							Namespace:       "bar",
							UID:             "fdadada-dada",
							ResourceVersion: "5454",
							Generation:      5,
							CreationTimestamp: metav1.Time{
								Time: time.Date(2018, 01, 01, 01, 01, 01, 01, time.UTC),
							},
							Labels: map[string]string{
								"foo": "bar",
							},
							Annotations: map[string]string{
								"foo": "bar",
							},
							OwnerReferences: []metav1.OwnerReference{
								{
									Kind:       "Pod",
									APIVersion: "v1",
									Name:       "foo",
									UID:        "65dasd54d45",
									Controller: nil,
								},
							},
						},
						Status: v2.EndpointStatus{
							ID:          0,
							Controllers: nil,
							ExternalIdentifiers: &models.EndpointIdentifiers{
								ContainerID:   "3290f4bc32129cb3e2f81074557ad9690240ea8fcce84bcc51a9921034875878",
								ContainerName: "foo",
								K8sNamespace:  "foo",
								K8sPodName:    "bar",
								PodName:       "foo/bar",
							},
							Health: &models.EndpointHealth{
								Bpf:           "good",
								Connected:     false,
								OverallHealth: "excellent",
								Policy:        "excellent",
							},
							Identity: &v2.EndpointIdentity{
								ID: 9654,
								Labels: []string{
									"k8s:io.cilium.namespace=bar",
								},
							},
							Networking: &v2.EndpointNetworking{
								Addressing: []*v2.AddressPair{
									{
										IPV4: "10.0.0.1",
										IPV6: "fd00::1",
									},
								},
								NodeIP: "192.168.0.1",
							},
							Encryption: v2.EncryptionSpec{
								Key: 250,
							},
							Policy: &v2.EndpointPolicy{
								Ingress: &v2.EndpointPolicyDirection{
									Enforcing: true,
								},
								Egress: &v2.EndpointPolicyDirection{
									Enforcing: true,
								},
							},
							State: "",
							NamedPorts: []*models.Port{
								{
									Name:     "foo-port",
									Port:     8181,
									Protocol: "TCP",
								},
							},
						},
					},
				},
			},
			want: cache.DeletedFinalStateUnknown{
				Key: "foo",
				Obj: &types.CiliumEndpoint{
					TypeMeta: slim_metav1.TypeMeta{
						Kind:       "CiliumEndpoint",
						APIVersion: "v2",
					},
					ObjectMeta: slim_metav1.ObjectMeta{
						Name:            "foo",
						Namespace:       "bar",
						UID:             "fdadada-dada",
						ResourceVersion: "5454",
						// We don't need to store labels nor annotations because
						// they are not used by the CEP handlers.
						Labels:      nil,
						Annotations: nil,
					},
					Identity: &v2.EndpointIdentity{
						ID: 9654,
						Labels: []string{
							"k8s:io.cilium.namespace=bar",
						},
					},
					Networking: &v2.EndpointNetworking{
						Addressing: []*v2.AddressPair{
							{
								IPV4: "10.0.0.1",
								IPV6: "fd00::1",
							},
						},
						NodeIP: "192.168.0.1",
					},
					Encryption: &v2.EncryptionSpec{
						Key: 250,
					},
					NamedPorts: []*models.Port{
						{
							Name:     "foo-port",
							Port:     8181,
							Protocol: "TCP",
						},
					},
				},
			},
		},
		{
			name: "unknown object type in delete final state unknown conversion",
			args: args{
				obj: cache.DeletedFinalStateUnknown{
					Key: "foo",
					Obj: 100,
				},
			},
			want: cache.DeletedFinalStateUnknown{
				Key: "foo",
				Obj: 100,
			},
		},
		{
			name: "unknown object type in conversion",
			args: args{
				obj: 100,
			},
			want: 100,
		},
	}
	for _, tt := range tests {
		got := ConvertToCiliumEndpoint(tt.args.obj)
		c.Assert(got, checker.DeepEquals, tt.want, Commentf("Test Name: %s", tt.name))
	}
}

func (s *K8sSuite) Test_AnnotationsEqual(c *C) {
	irrelevantAnnoKey := "foo"
	irrelevantAnnoVal := "bar"

	relevantAnnoKey := annotation.ProxyVisibility
	relevantAnnoVal1 := "<Ingress/80/TCP/HTTP>"
	relevantAnnoVal2 := "<Ingress/80/TCP/HTTP>,<Egress/80/TCP/HTTP>"

	// Empty returns true.
	c.Assert(AnnotationsEqual(nil, map[string]string{}, map[string]string{}), Equals, true)

	c.Assert(AnnotationsEqual(nil,
		map[string]string{
			irrelevantAnnoKey: irrelevantAnnoVal,
			relevantAnnoKey:   relevantAnnoVal1,
		}, map[string]string{
			irrelevantAnnoKey: irrelevantAnnoVal,
			relevantAnnoKey:   relevantAnnoVal2,
		}), Equals, true)

	// If the relevant annotation isn't in either map, return true.
	c.Assert(AnnotationsEqual([]string{relevantAnnoKey},
		map[string]string{
			irrelevantAnnoKey: irrelevantAnnoVal,
		}, map[string]string{
			irrelevantAnnoKey: irrelevantAnnoVal,
		}), Equals, true)

	c.Assert(AnnotationsEqual([]string{relevantAnnoKey},
		map[string]string{
			relevantAnnoKey: relevantAnnoVal1,
		}, map[string]string{
			relevantAnnoKey: relevantAnnoVal2,
		}), Equals, false)

}
