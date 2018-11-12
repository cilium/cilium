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

// +build !privileged_tests

package k8s

import (
	"net"
	"testing"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/service"

	"gopkg.in/check.v1"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (s *K8sSuite) TestGetAnnotationIncludeExternal(c *check.C) {
	svc := &v1.Service{ObjectMeta: metav1.ObjectMeta{
		Name: "foo",
	}}
	c.Assert(getAnnotationIncludeExternal(svc), check.Equals, false)

	svc = &v1.Service{ObjectMeta: metav1.ObjectMeta{
		Annotations: map[string]string{"io.cilium/global-service": "True"},
	}}
	c.Assert(getAnnotationIncludeExternal(svc), check.Equals, true)

	svc = &v1.Service{ObjectMeta: metav1.ObjectMeta{
		Annotations: map[string]string{"io.cilium/global-service": "false"},
	}}
	c.Assert(getAnnotationIncludeExternal(svc), check.Equals, false)

	svc = &v1.Service{ObjectMeta: metav1.ObjectMeta{
		Annotations: map[string]string{"io.cilium/global-service": ""},
	}}
	c.Assert(getAnnotationIncludeExternal(svc), check.Equals, false)
}

func (s *K8sSuite) TestParseServiceID(c *check.C) {
	svc := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
		},
	}

	c.Assert(ParseServiceID(svc), checker.DeepEquals, ServiceID{Namespace: "bar", Name: "foo"})
}

func (s *K8sSuite) TestParseService(c *check.C) {
	k8sSvc := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
			Labels: map[string]string{
				"foo": "bar",
			},
		},
		Spec: v1.ServiceSpec{
			ClusterIP: "127.0.0.1",
			Selector: map[string]string{
				"foo": "bar",
			},
			Type: v1.ServiceTypeClusterIP,
		},
	}

	id, svc := ParseService(k8sSvc)
	c.Assert(id, checker.DeepEquals, ServiceID{Namespace: "bar", Name: "foo"})
	c.Assert(svc, checker.DeepEquals, &Service{
		FrontendIP: net.ParseIP("127.0.0.1"),
		Selector:   map[string]string{"foo": "bar"},
		Labels:     map[string]string{"foo": "bar"},
		Ports:      map[loadbalancer.FEPortName]*loadbalancer.FEPort{},
	})

	k8sSvc = &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
			Labels: map[string]string{
				"foo": "bar",
			},
		},
		Spec: v1.ServiceSpec{
			ClusterIP: "none",
			Type:      v1.ServiceTypeClusterIP,
		},
	}

	id, svc = ParseService(k8sSvc)
	c.Assert(id, checker.DeepEquals, ServiceID{Namespace: "bar", Name: "foo"})
	c.Assert(svc, checker.DeepEquals, &Service{
		IsHeadless: true,
		Labels:     map[string]string{"foo": "bar"},
		Ports:      map[loadbalancer.FEPortName]*loadbalancer.FEPort{},
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
				Ports: map[loadbalancer.FEPortName]*loadbalancer.FEPort{
					loadbalancer.FEPortName("foo"): {
						L4Addr: &loadbalancer.L4Addr{
							Protocol: loadbalancer.NONE,
							Port:     1,
						},
					},
					loadbalancer.FEPortName("bar"): {
						L4Addr: &loadbalancer.L4Addr{
							Protocol: loadbalancer.NONE,
							Port:     2,
						},
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
				Ports: map[loadbalancer.FEPortName]*loadbalancer.FEPort{
					loadbalancer.FEPortName("foo"): {
						L4Addr: &loadbalancer.L4Addr{
							Protocol: loadbalancer.NONE,
							Port:     1,
						},
						ID: 1,
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
					Ports: map[loadbalancer.FEPortName]*loadbalancer.FEPort{
						loadbalancer.FEPortName("foo"): {
							L4Addr: &loadbalancer.L4Addr{
								Protocol: loadbalancer.NONE,
								Port:     1,
							},
							ID: 1,
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
				Ports: map[loadbalancer.FEPortName]*loadbalancer.FEPort{
					loadbalancer.FEPortName("foo"): {
						L4Addr: &loadbalancer.L4Addr{
							Protocol: loadbalancer.NONE,
							Port:     1,
						},
						ID: 1,
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
					Ports: map[loadbalancer.FEPortName]*loadbalancer.FEPort{
						loadbalancer.FEPortName("foo"): {
							L4Addr: &loadbalancer.L4Addr{
								Protocol: loadbalancer.NONE,
								Port:     1,
							},
							ID: 1,
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
				Ports: map[loadbalancer.FEPortName]*loadbalancer.FEPort{
					loadbalancer.FEPortName("foo"): {
						L4Addr: &loadbalancer.L4Addr{
							Protocol: loadbalancer.NONE,
							Port:     1,
						},
						ID: 1,
					},
				},
				Labels:   map[string]string{},
				Selector: map[string]string{},
			},
			args: args{
				o: &Service{
					FrontendIP: net.ParseIP("1.1.1.1"),
					IsHeadless: true,
					Ports: map[loadbalancer.FEPortName]*loadbalancer.FEPort{
						loadbalancer.FEPortName("foo"): {
							L4Addr: &loadbalancer.L4Addr{
								Protocol: loadbalancer.NONE,
								Port:     1,
							},
							ID: 1,
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
				Ports: map[loadbalancer.FEPortName]*loadbalancer.FEPort{
					loadbalancer.FEPortName("foz"): {
						L4Addr: &loadbalancer.L4Addr{
							Protocol: loadbalancer.NONE,
							Port:     1,
						},
						ID: 1,
					},
				},
				Labels:   map[string]string{},
				Selector: map[string]string{},
			},
			args: args{
				o: &Service{
					FrontendIP: net.ParseIP("1.1.1.1"),
					IsHeadless: true,
					Ports: map[loadbalancer.FEPortName]*loadbalancer.FEPort{
						loadbalancer.FEPortName("foo"): {
							L4Addr: &loadbalancer.L4Addr{
								Protocol: loadbalancer.NONE,
								Port:     1,
							},
							ID: 1,
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
				Ports: map[loadbalancer.FEPortName]*loadbalancer.FEPort{
					loadbalancer.FEPortName("foo"): {
						L4Addr: &loadbalancer.L4Addr{
							Protocol: loadbalancer.NONE,
							Port:     1,
						},
						ID: 1,
					},
				},
				Labels:   map[string]string{},
				Selector: map[string]string{},
			},
			args: args{
				o: &Service{
					FrontendIP: net.ParseIP("1.1.1.1"),
					IsHeadless: true,
					Ports: map[loadbalancer.FEPortName]*loadbalancer.FEPort{
						loadbalancer.FEPortName("foo"): {
							L4Addr: &loadbalancer.L4Addr{
								Protocol: loadbalancer.NONE,
								Port:     2,
							},
							ID: 1,
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
				Ports: map[loadbalancer.FEPortName]*loadbalancer.FEPort{
					loadbalancer.FEPortName("foo"): {
						L4Addr: &loadbalancer.L4Addr{
							Protocol: loadbalancer.NONE,
							Port:     1,
						},
						ID: 1,
					},
				},
				Labels:   map[string]string{},
				Selector: map[string]string{},
			},
			args: args{
				o: &Service{
					FrontendIP: net.ParseIP("1.1.1.1"),
					IsHeadless: true,
					Ports: map[loadbalancer.FEPortName]*loadbalancer.FEPort{
						loadbalancer.FEPortName("foo"): {
							L4Addr: &loadbalancer.L4Addr{
								Protocol: loadbalancer.NONE,
								Port:     1,
							},
							ID: 1,
						},
						loadbalancer.FEPortName("baz"): {
							L4Addr: &loadbalancer.L4Addr{
								Protocol: loadbalancer.NONE,
								Port:     2,
							},
							ID: 2,
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
					Ports: map[loadbalancer.FEPortName]*loadbalancer.FEPort{
						loadbalancer.FEPortName("foo"): {
							L4Addr: &loadbalancer.L4Addr{
								Protocol: loadbalancer.NONE,
								Port:     1,
							},
							ID: 1,
						},
					},
					Labels:   map[string]string{},
					Selector: map[string]string{},
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
	k8sSvc := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
			Labels: map[string]string{
				"foo": "bar",
			},
		},
		Spec: v1.ServiceSpec{
			ClusterIP: "127.0.0.1",
			Selector: map[string]string{
				"foo": "bar",
			},
			Type: v1.ServiceTypeClusterIP,
		},
	}

	_, svc := ParseService(k8sSvc)
	c.Assert(svc.String(), check.Equals, "frontend:127.0.0.1/ports=[]/selector=map[foo:bar]")
}

func (s *K8sSuite) TestNewClusterService(c *check.C) {
	id, svc := ParseService(&v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
			Labels: map[string]string{
				"foo": "bar",
			},
		},
		Spec: v1.ServiceSpec{
			ClusterIP: "127.0.0.1",
			Selector: map[string]string{
				"foo": "bar",
			},
			Type: v1.ServiceTypeClusterIP,
		},
	})

	_, endpoints := ParseEndpoints(&v1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
		},
		Subsets: []v1.EndpointSubset{
			{
				Addresses: []v1.EndpointAddress{{IP: "2.2.2.2"}},
				Ports: []v1.EndpointPort{
					{
						Name:     "http-test-svc",
						Port:     8080,
						Protocol: v1.ProtocolTCP,
					},
				},
			},
		},
	})

	clusterService := NewClusterService(id, svc, endpoints)
	c.Assert(clusterService, check.DeepEquals, service.ClusterService{
		Name:      "foo",
		Namespace: "bar",
		Labels:    map[string]string{"foo": "bar"},
		Selector:  map[string]string{"foo": "bar"},
		Frontends: map[string]service.PortConfiguration{
			"127.0.0.1": {},
		},
		Backends: map[string]service.PortConfiguration{
			"2.2.2.2": {
				"http-test-svc": {Protocol: loadbalancer.TCP, Port: 8080},
			},
		},
	})
}
