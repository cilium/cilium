// Copyright 2018-2019 Authors of Cilium
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

package k8s

import (
	"net"
	"reflect"
	"testing"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/cidr"
	fakeDatapath "github.com/cilium/cilium/pkg/datapath/fake"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/loadbalancer"
	serviceStore "github.com/cilium/cilium/pkg/service/store"

	"gopkg.in/check.v1"
)

func (s *K8sSuite) TestGetAnnotationIncludeExternal(c *check.C) {
	svc := &slim_corev1.Service{ObjectMeta: slim_metav1.ObjectMeta{
		Name: "foo",
	}}
	c.Assert(getAnnotationIncludeExternal(svc), check.Equals, false)

	svc = &slim_corev1.Service{ObjectMeta: slim_metav1.ObjectMeta{
		Annotations: map[string]string{"io.cilium/global-service": "True"},
	}}
	c.Assert(getAnnotationIncludeExternal(svc), check.Equals, true)

	svc = &slim_corev1.Service{ObjectMeta: slim_metav1.ObjectMeta{
		Annotations: map[string]string{"io.cilium/global-service": "false"},
	}}
	c.Assert(getAnnotationIncludeExternal(svc), check.Equals, false)

	svc = &slim_corev1.Service{ObjectMeta: slim_metav1.ObjectMeta{
		Annotations: map[string]string{"io.cilium/global-service": ""},
	}}
	c.Assert(getAnnotationIncludeExternal(svc), check.Equals, false)
}

func (s *K8sSuite) TestGetAnnotationShared(c *check.C) {
	svc := &slim_corev1.Service{ObjectMeta: slim_metav1.ObjectMeta{
		Name: "foo",
	}}
	c.Assert(getAnnotationShared(svc), check.Equals, false)
	svc = &slim_corev1.Service{ObjectMeta: slim_metav1.ObjectMeta{
		Annotations: map[string]string{"io.cilium/global-service": "true"},
	}}
	c.Assert(getAnnotationShared(svc), check.Equals, true)

	svc = &slim_corev1.Service{ObjectMeta: slim_metav1.ObjectMeta{
		Annotations: map[string]string{"io.cilium/shared-service": "True"},
	}}
	c.Assert(getAnnotationShared(svc), check.Equals, true)

	svc = &slim_corev1.Service{ObjectMeta: slim_metav1.ObjectMeta{
		Annotations: map[string]string{"io.cilium/global-service": "true", "io.cilium/shared-service": "false"},
	}}
	c.Assert(getAnnotationShared(svc), check.Equals, false)
}

func (s *K8sSuite) TestParseServiceID(c *check.C) {
	svc := &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
		},
	}

	c.Assert(ParseServiceID(svc), checker.DeepEquals, ServiceID{Namespace: "bar", Name: "foo"})
}

func (s *K8sSuite) TestParseService(c *check.C) {
	k8sSvc := &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
			Labels: map[string]string{
				"foo": "bar",
			},
		},
		Spec: slim_corev1.ServiceSpec{
			ClusterIP: "127.0.0.1",
			Selector: map[string]string{
				"foo": "bar",
			},
			Type: slim_corev1.ServiceTypeClusterIP,
		},
	}

	id, svc := ParseService(k8sSvc, fakeDatapath.NewNodeAddressing())
	c.Assert(id, checker.DeepEquals, ServiceID{Namespace: "bar", Name: "foo"})
	c.Assert(svc, checker.DeepEquals, &Service{
		TrafficPolicy:            loadbalancer.SVCTrafficPolicyCluster,
		FrontendIP:               net.ParseIP("127.0.0.1"),
		Selector:                 map[string]string{"foo": "bar"},
		Labels:                   map[string]string{"foo": "bar"},
		Ports:                    map[loadbalancer.FEPortName]*loadbalancer.L4Addr{},
		NodePorts:                map[loadbalancer.FEPortName]map[string]*loadbalancer.L3n4AddrID{},
		LoadBalancerSourceRanges: map[string]*cidr.CIDR{},
		Type:                     loadbalancer.SVCTypeClusterIP,
	})

	k8sSvc = &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
			Labels: map[string]string{
				"foo": "bar",
			},
		},
		Spec: slim_corev1.ServiceSpec{
			ClusterIP: "none",
			Type:      slim_corev1.ServiceTypeClusterIP,
		},
	}

	id, svc = ParseService(k8sSvc, fakeDatapath.NewNodeAddressing())
	c.Assert(id, checker.DeepEquals, ServiceID{Namespace: "bar", Name: "foo"})
	c.Assert(svc, checker.DeepEquals, &Service{
		IsHeadless:               true,
		TrafficPolicy:            loadbalancer.SVCTrafficPolicyCluster,
		Labels:                   map[string]string{"foo": "bar"},
		Ports:                    map[loadbalancer.FEPortName]*loadbalancer.L4Addr{},
		NodePorts:                map[loadbalancer.FEPortName]map[string]*loadbalancer.L3n4AddrID{},
		LoadBalancerSourceRanges: map[string]*cidr.CIDR{},
		Type:                     loadbalancer.SVCTypeClusterIP,
	})

	k8sSvc = &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
			Labels: map[string]string{
				"foo": "bar",
			},
		},
		Spec: slim_corev1.ServiceSpec{
			ClusterIP:             "127.0.0.1",
			Type:                  slim_corev1.ServiceTypeNodePort,
			ExternalTrafficPolicy: slim_corev1.ServiceExternalTrafficPolicyTypeLocal,
		},
	}

	id, svc = ParseService(k8sSvc, fakeDatapath.NewNodeAddressing())
	c.Assert(id, checker.DeepEquals, ServiceID{Namespace: "bar", Name: "foo"})
	c.Assert(svc, checker.DeepEquals, &Service{
		FrontendIP:               net.ParseIP("127.0.0.1"),
		TrafficPolicy:            loadbalancer.SVCTrafficPolicyLocal,
		Labels:                   map[string]string{"foo": "bar"},
		Ports:                    map[loadbalancer.FEPortName]*loadbalancer.L4Addr{},
		NodePorts:                map[loadbalancer.FEPortName]map[string]*loadbalancer.L3n4AddrID{},
		LoadBalancerSourceRanges: map[string]*cidr.CIDR{},
		Type:                     loadbalancer.SVCTypeNodePort,
	})
}

func (s *K8sSuite) TestIsK8ServiceExternal(c *check.C) {
	si := Service{}

	c.Assert(si.IsExternal(), check.Equals, true)

	si.Selector = map[string]string{"l": "v"}
	c.Assert(si.IsExternal(), check.Equals, false)
}

func (s *K8sSuite) TestServiceUniquePorts(c *check.C) {
	type testMatrix struct {
		input    Service
		expected map[uint16]bool
	}

	matrix := []testMatrix{
		{
			input:    Service{},
			expected: map[uint16]bool{},
		},
		{
			input: Service{
				Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
					loadbalancer.FEPortName("foo"): {
						Protocol: loadbalancer.NONE,
						Port:     1,
					},
					loadbalancer.FEPortName("bar"): {
						Protocol: loadbalancer.NONE,
						Port:     2,
					},
				},
			},
			expected: map[uint16]bool{
				1: true,
				2: true,
			}},
	}

	for _, m := range matrix {
		c.Assert(m.input.UniquePorts(), checker.DeepEquals, m.expected)
	}
}

func TestService_Equals(t *testing.T) {
	type args struct {
		o *Service
	}
	tests := []struct {
		name   string
		fields *Service
		args   args
		want   bool
	}{
		{
			name: "both equal",
			fields: &Service{
				FrontendIP: net.ParseIP("1.1.1.1"),
				IsHeadless: true,
				Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
					loadbalancer.FEPortName("foo"): {
						Protocol: loadbalancer.NONE,
						Port:     1,
					},
				},
				NodePorts: map[loadbalancer.FEPortName]map[string]*loadbalancer.L3n4AddrID{
					loadbalancer.FEPortName("foo"): {
						"0.0.0.0:31000": {
							L3n4Addr: loadbalancer.L3n4Addr{
								L4Addr: loadbalancer.L4Addr{
									Protocol: loadbalancer.NONE,
									Port:     31000,
								},
								IP: net.IPv4(0, 0, 0, 0),
							},
							ID: 1,
						},
					},
				},

				Labels: map[string]string{
					"foo": "bar",
				},
				Selector: map[string]string{
					"baz": "foz",
				},
			},
			args: args{
				o: &Service{
					FrontendIP: net.ParseIP("1.1.1.1"),
					IsHeadless: true,
					Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
						loadbalancer.FEPortName("foo"): {
							Protocol: loadbalancer.NONE,
							Port:     1,
						},
					},
					NodePorts: map[loadbalancer.FEPortName]map[string]*loadbalancer.L3n4AddrID{
						loadbalancer.FEPortName("foo"): {
							"0.0.0.0:31000": {
								L3n4Addr: loadbalancer.L3n4Addr{
									L4Addr: loadbalancer.L4Addr{
										Protocol: loadbalancer.NONE,
										Port:     31000,
									},
									IP: net.IPv4(0, 0, 0, 0),
								},
								ID: 1,
							},
						},
					},

					Labels: map[string]string{
						"foo": "bar",
					},
					Selector: map[string]string{
						"baz": "foz",
					},
				},
			},
			want: true,
		},
		{
			name: "different labels",
			fields: &Service{
				FrontendIP: net.ParseIP("1.1.1.1"),
				IsHeadless: true,
				Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
					loadbalancer.FEPortName("foo"): {
						Protocol: loadbalancer.NONE,
						Port:     1,
					},
				},
				Labels: map[string]string{},
				Selector: map[string]string{
					"baz": "foz",
				},
			},
			args: args{
				o: &Service{
					FrontendIP: net.ParseIP("1.1.1.1"),
					IsHeadless: true,
					Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
						loadbalancer.FEPortName("foo"): {
							Protocol: loadbalancer.NONE,
							Port:     1,
						},
					},
					Labels: map[string]string{
						"foo": "bar",
					},
					Selector: map[string]string{
						"baz": "foz",
					},
				},
			},
			want: false,
		},
		{
			name: "different selector",
			fields: &Service{
				FrontendIP: net.ParseIP("1.1.1.1"),
				IsHeadless: true,
				Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
					loadbalancer.FEPortName("foo"): {
						Protocol: loadbalancer.NONE,
						Port:     1,
					},
				},
				Labels:   map[string]string{},
				Selector: map[string]string{},
			},
			args: args{
				o: &Service{
					FrontendIP: net.ParseIP("1.1.1.1"),
					IsHeadless: true,
					Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
						loadbalancer.FEPortName("foo"): {
							Protocol: loadbalancer.NONE,
							Port:     1,
						},
					},
					Labels: map[string]string{},
					Selector: map[string]string{
						"baz": "foz",
					},
				},
			},
			want: false,
		},
		{
			name: "ports different name",
			fields: &Service{
				FrontendIP: net.ParseIP("1.1.1.1"),
				IsHeadless: true,
				Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
					loadbalancer.FEPortName("foz"): {
						Protocol: loadbalancer.NONE,
						Port:     1,
					},
				},
				Labels:   map[string]string{},
				Selector: map[string]string{},
			},
			args: args{
				o: &Service{
					FrontendIP: net.ParseIP("1.1.1.1"),
					IsHeadless: true,
					Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
						loadbalancer.FEPortName("foo"): {
							Protocol: loadbalancer.NONE,
							Port:     1,
						},
					},
					Labels:   map[string]string{},
					Selector: map[string]string{},
				},
			},
			want: false,
		},
		{
			name: "ports different content",
			fields: &Service{
				FrontendIP: net.ParseIP("1.1.1.1"),
				IsHeadless: true,
				Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
					loadbalancer.FEPortName("foo"): {
						Protocol: loadbalancer.NONE,
						Port:     1,
					},
				},
				Labels:   map[string]string{},
				Selector: map[string]string{},
			},
			args: args{
				o: &Service{
					FrontendIP: net.ParseIP("1.1.1.1"),
					IsHeadless: true,
					Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
						loadbalancer.FEPortName("foo"): {
							Protocol: loadbalancer.NONE,
							Port:     2,
						},
					},
					Labels:   map[string]string{},
					Selector: map[string]string{},
				},
			},
			want: false,
		},
		{
			name: "ports different one is bigger",
			fields: &Service{
				FrontendIP: net.ParseIP("1.1.1.1"),
				IsHeadless: true,
				Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
					loadbalancer.FEPortName("foo"): {
						Protocol: loadbalancer.NONE,
						Port:     1,
					},
				},
				Labels:   map[string]string{},
				Selector: map[string]string{},
			},
			args: args{
				o: &Service{
					FrontendIP: net.ParseIP("1.1.1.1"),
					IsHeadless: true,
					Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
						loadbalancer.FEPortName("foo"): {
							Protocol: loadbalancer.NONE,
							Port:     1,
						},
						loadbalancer.FEPortName("baz"): {
							Protocol: loadbalancer.NONE,
							Port:     2,
						},
					},
					Labels:   map[string]string{},
					Selector: map[string]string{},
				},
			},
			want: false,
		},
		{
			name: "ports different one is nil",
			fields: &Service{
				FrontendIP: net.ParseIP("1.1.1.1"),
				IsHeadless: true,
				Labels:     map[string]string{},
				Selector:   map[string]string{},
			},
			args: args{
				o: &Service{
					FrontendIP: net.ParseIP("1.1.1.1"),
					IsHeadless: true,
					Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
						loadbalancer.FEPortName("foo"): {
							Protocol: loadbalancer.NONE,
							Port:     1,
						},
					},
					Labels:   map[string]string{},
					Selector: map[string]string{},
				},
			},
			want: false,
		},
		{
			name: "nodeports different",
			fields: &Service{
				FrontendIP: net.ParseIP("1.1.1.1"),
				IsHeadless: true,
				Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
					loadbalancer.FEPortName("foo"): {
						Protocol: loadbalancer.NONE,
						Port:     1,
					},
				},
				NodePorts: map[loadbalancer.FEPortName]map[string]*loadbalancer.L3n4AddrID{
					loadbalancer.FEPortName("foo"): {
						"1.1.1.1:31000": {
							L3n4Addr: loadbalancer.L3n4Addr{
								L4Addr: loadbalancer.L4Addr{
									Protocol: loadbalancer.NONE,
									Port:     31000,
								},
								IP: net.IPv4(1, 1, 1, 1),
							},
							ID: 1,
						},
					},
				},

				Labels: map[string]string{
					"foo": "bar",
				},
				Selector: map[string]string{
					"baz": "foz",
				},
			},
			args: args{
				o: &Service{
					FrontendIP: net.ParseIP("1.1.1.1"),
					IsHeadless: true,
					Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
						loadbalancer.FEPortName("foo"): {
							Protocol: loadbalancer.NONE,
							Port:     1,
						},
					},
					NodePorts: map[loadbalancer.FEPortName]map[string]*loadbalancer.L3n4AddrID{
						loadbalancer.FEPortName("foo"): {
							"0.0.0.0:31000": {
								L3n4Addr: loadbalancer.L3n4Addr{
									L4Addr: loadbalancer.L4Addr{
										Protocol: loadbalancer.NONE,
										Port:     31000,
									},
									IP: net.IPv4(0, 0, 0, 0),
								},
								ID: 1,
							},
						},
					},

					Labels: map[string]string{
						"foo": "bar",
					},
					Selector: map[string]string{
						"baz": "foz",
					},
				},
			},
			want: false,
		},
		{
			name: "external-ip was added",
			fields: &Service{
				FrontendIP: net.ParseIP("1.1.1.1"),
				IsHeadless: false,
				Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
					loadbalancer.FEPortName("foo"): {
						Protocol: loadbalancer.NONE,
						Port:     1,
					},
				},
				K8sExternalIPs: nil,
				Labels: map[string]string{
					"foo": "bar",
				},
				Selector: map[string]string{
					"baz": "foz",
				},
			},
			args: args{
				o: &Service{
					FrontendIP: net.ParseIP("1.1.1.1"),
					IsHeadless: false,
					Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
						loadbalancer.FEPortName("foo"): {
							Protocol: loadbalancer.NONE,
							Port:     1,
						},
					},
					K8sExternalIPs: map[string]net.IP{
						"2.2.2.2": net.ParseIP("2.2.2.2"),
					},
					Labels: map[string]string{
						"foo": "bar",
					},
					Selector: map[string]string{
						"baz": "foz",
					},
				},
			},
			want: false,
		},
		{
			name: "session affinity was added",
			fields: &Service{
				FrontendIP: net.ParseIP("1.1.1.1"),
				IsHeadless: false,
				Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
					loadbalancer.FEPortName("foo"): {
						Protocol: loadbalancer.NONE,
						Port:     1,
					},
				},
				Labels: map[string]string{
					"foo": "bar",
				},
				Selector: map[string]string{
					"baz": "foz",
				},
				SessionAffinity: false,
			},
			args: args{
				o: &Service{
					FrontendIP: net.ParseIP("1.1.1.1"),
					IsHeadless: false,
					Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
						loadbalancer.FEPortName("foo"): {
							Protocol: loadbalancer.NONE,
							Port:     1,
						},
					},
					Labels: map[string]string{
						"foo": "bar",
					},
					Selector: map[string]string{
						"baz": "foz",
					},
					SessionAffinity: true,
				},
			},
			want: false,
		},
		{
			name: "session affinity timeout changed",
			fields: &Service{
				FrontendIP: net.ParseIP("1.1.1.1"),
				IsHeadless: false,
				Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
					loadbalancer.FEPortName("foo"): {
						Protocol: loadbalancer.NONE,
						Port:     1,
					},
				},
				Labels: map[string]string{
					"foo": "bar",
				},
				Selector: map[string]string{
					"baz": "foz",
				},
				SessionAffinity:           true,
				SessionAffinityTimeoutSec: 1,
			},
			args: args{
				o: &Service{
					FrontendIP: net.ParseIP("1.1.1.1"),
					IsHeadless: false,
					Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
						loadbalancer.FEPortName("foo"): {
							Protocol: loadbalancer.NONE,
							Port:     1,
						},
					},
					Labels: map[string]string{
						"foo": "bar",
					},
					Selector: map[string]string{
						"baz": "foz",
					},
					SessionAffinity:           true,
					SessionAffinityTimeoutSec: 2,
				},
			},
			want: false,
		},
		{
			name: "both nil",
			args: args{},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			si := tt.fields
			if got := si.DeepEquals(tt.args.o); got != tt.want {
				t.Errorf("Service.Equals() = %v, want %v", got, tt.want)
			}
		})
	}
}

func (s *K8sSuite) TestServiceString(c *check.C) {
	k8sSvc := &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
			Labels: map[string]string{
				"foo": "bar",
			},
		},
		Spec: slim_corev1.ServiceSpec{
			ClusterIP: "127.0.0.1",
			Selector: map[string]string{
				"foo": "bar",
			},
			Type: slim_corev1.ServiceTypeClusterIP,
		},
	}

	_, svc := ParseService(k8sSvc, fakeDatapath.NewNodeAddressing())
	c.Assert(svc.String(), check.Equals, "frontend:127.0.0.1/ports=[]/selector=map[foo:bar]")
}

func (s *K8sSuite) TestNewClusterService(c *check.C) {
	id, svc := ParseService(
		&slim_corev1.Service{
			ObjectMeta: slim_metav1.ObjectMeta{
				Name:      "foo",
				Namespace: "bar",
				Labels: map[string]string{
					"foo": "bar",
				},
			},
			Spec: slim_corev1.ServiceSpec{
				ClusterIP: "127.0.0.1",
				Selector: map[string]string{
					"foo": "bar",
				},
				Type: slim_corev1.ServiceTypeClusterIP,
			},
		}, fakeDatapath.NewNodeAddressing())

	_, endpoints := ParseEndpoints(&slim_corev1.Endpoints{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
		},
		Subsets: []slim_corev1.EndpointSubset{
			{
				Addresses: []slim_corev1.EndpointAddress{{IP: "2.2.2.2"}},
				Ports: []slim_corev1.EndpointPort{
					{
						Name:     "http-test-svc",
						Port:     8080,
						Protocol: slim_corev1.ProtocolTCP,
					},
				},
			},
		},
	})

	clusterService := NewClusterService(id, svc, endpoints)
	c.Assert(clusterService, check.DeepEquals, serviceStore.ClusterService{
		Name:      "foo",
		Namespace: "bar",
		Labels:    map[string]string{"foo": "bar"},
		Selector:  map[string]string{"foo": "bar"},
		Frontends: map[string]serviceStore.PortConfiguration{
			"127.0.0.1": {},
		},
		Backends: map[string]serviceStore.PortConfiguration{
			"2.2.2.2": {
				"http-test-svc": {Protocol: loadbalancer.TCP, Port: 8080},
			},
		},
	})
}

func TestParseServiceIDFrom(t *testing.T) {
	type args struct {
		dn string
	}
	tests := []struct {
		args args
		want *ServiceID
	}{
		{args: args{dn: "cilium-etcd-client.kube-system.svc"}, want: &ServiceID{Name: "cilium-etcd-client", Namespace: "kube-system"}},
		{args: args{dn: "1.kube-system"}, want: &ServiceID{Name: "1", Namespace: "kube-system"}},
		{args: args{dn: ".kube-system"}, want: &ServiceID{Name: "", Namespace: "kube-system"}},
		{args: args{dn: "..kube-system"}, want: &ServiceID{Name: "", Namespace: ""}},
		{args: args{dn: "2-..kube-system"}, want: &ServiceID{Name: "2-", Namespace: ""}},
		{args: args{dn: ""}, want: nil},
		{args: args{dn: "cilium-etcd-client.kube-system"}, want: &ServiceID{Name: "cilium-etcd-client", Namespace: "kube-system"}},
		{args: args{dn: "cilium-etcd-client"}, want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.args.dn, func(t *testing.T) {
			if got := ParseServiceIDFrom(tt.args.dn); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseServiceIDFrom() = %v, want %v", got, tt.want)
			}
		})
	}
}
