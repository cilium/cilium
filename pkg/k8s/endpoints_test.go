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

package k8s

import (
	"reflect"
	"testing"

	"github.com/cilium/cilium/pkg/checker"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/core/v1"
	slim_discovery_v1beta1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/discovery/v1beta1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/loadbalancer"
	serviceStore "github.com/cilium/cilium/pkg/service/store"

	"gopkg.in/check.v1"
)

func TestEndpoints_DeepEqual(t *testing.T) {
	type fields struct {
		svcEP *Endpoints
	}
	type args struct {
		o *Endpoints
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{

		{
			name: "both equal",
			fields: fields{
				svcEP: &Endpoints{
					Backends: map[string]*Backend{
						"172.20.0.1": {
							Ports: map[string]*loadbalancer.L4Addr{
								"foo": {
									Protocol: loadbalancer.TCP,
									Port:     1,
								},
							},
							NodeName: "k8s1",
						},
					},
				},
			},
			args: args{
				o: &Endpoints{
					Backends: map[string]*Backend{
						"172.20.0.1": {
							Ports: map[string]*loadbalancer.L4Addr{
								"foo": {
									Protocol: loadbalancer.TCP,
									Port:     1,
								},
							},
							NodeName: "k8s1",
						},
					},
				},
			},
			want: true,
		},
		{
			name: "different BE IPs",
			fields: fields{
				svcEP: &Endpoints{
					Backends: map[string]*Backend{
						"172.20.0.1": {
							Ports: map[string]*loadbalancer.L4Addr{
								"foo": {
									Protocol: loadbalancer.TCP,
									Port:     1,
								},
							},
						},
					},
				},
			},
			args: args{
				o: &Endpoints{
					Backends: map[string]*Backend{
						"172.20.0.2": {
							Ports: map[string]*loadbalancer.L4Addr{
								"foo": {
									Protocol: loadbalancer.TCP,
									Port:     1,
								},
							},
						},
					},
				},
			},
			want: false,
		},
		{
			name: "ports different name",
			fields: fields{
				svcEP: &Endpoints{
					Backends: map[string]*Backend{
						"172.20.0.1": {
							Ports: map[string]*loadbalancer.L4Addr{
								"foo": {
									Protocol: loadbalancer.TCP,
									Port:     1,
								},
							},
						},
					},
				},
			},
			args: args{
				o: &Endpoints{
					Backends: map[string]*Backend{
						"172.20.0.1": {
							Ports: map[string]*loadbalancer.L4Addr{
								"foz": {
									Protocol: loadbalancer.TCP,
									Port:     1,
								},
							},
						},
					},
				},
			},
			want: false,
		},
		{
			name: "ports different content",
			fields: fields{
				svcEP: &Endpoints{
					Backends: map[string]*Backend{
						"172.20.0.1": {
							Ports: map[string]*loadbalancer.L4Addr{
								"foo": {
									Protocol: loadbalancer.TCP,
									Port:     1,
								},
							},
						},
					},
				},
			},
			args: args{
				o: &Endpoints{
					Backends: map[string]*Backend{
						"172.20.0.1": {
							Ports: map[string]*loadbalancer.L4Addr{
								"foo": {
									Protocol: loadbalancer.TCP,
									Port:     2,
								},
							},
						},
					},
				},
			},
			want: false,
		},
		{
			name: "protocols different content",
			fields: fields{
				svcEP: &Endpoints{
					Backends: map[string]*Backend{
						"172.20.0.1": {
							Ports: map[string]*loadbalancer.L4Addr{
								"foo": {
									Protocol: loadbalancer.TCP,
									Port:     2,
								},
							},
						},
					},
				},
			},
			args: args{
				o: &Endpoints{
					Backends: map[string]*Backend{
						"172.20.0.1": {
							Ports: map[string]*loadbalancer.L4Addr{
								"foo": {
									Protocol: loadbalancer.UDP,
									Port:     2,
								},
							},
						},
					},
				},
			},
			want: false,
		},
		{
			name: "protocols different one none",
			fields: fields{
				svcEP: &Endpoints{
					Backends: map[string]*Backend{
						"172.20.0.1": {
							Ports: map[string]*loadbalancer.L4Addr{
								"foo": {
									Protocol: loadbalancer.TCP,
									Port:     2,
								},
							},
						},
					},
				},
			},
			args: args{
				o: &Endpoints{
					Backends: map[string]*Backend{
						"172.20.0.1": {
							Ports: map[string]*loadbalancer.L4Addr{
								"foo": {
									Protocol: loadbalancer.NONE,
									Port:     2,
								},
							},
						},
					},
				},
			},
			want: false,
		},
		{
			name: "ports different one is bigger",
			fields: fields{
				svcEP: &Endpoints{
					Backends: map[string]*Backend{
						"172.20.0.1": {
							Ports: map[string]*loadbalancer.L4Addr{
								"foo": {
									Protocol: loadbalancer.TCP,
									Port:     1,
								},
							},
						},
					},
				},
			},
			args: args{
				o: &Endpoints{
					Backends: map[string]*Backend{
						"172.20.0.1": {
							Ports: map[string]*loadbalancer.L4Addr{
								"foo": {
									Protocol: loadbalancer.TCP,
									Port:     1,
								},
								"baz": {
									Protocol: loadbalancer.TCP,
									Port:     2,
								},
							},
						},
					},
				},
			},
			want: false,
		},
		{
			name:   "backend different one is nil",
			fields: fields{},
			args: args{
				o: &Endpoints{
					Backends: map[string]*Backend{
						"172.20.0.1": {
							Ports: map[string]*loadbalancer.L4Addr{
								"foo": {
									Protocol: loadbalancer.TCP,
									Port:     1,
								},
							},
						},
					},
				},
			},
			want: false,
		},
		{
			name: "node name different",
			fields: fields{
				svcEP: &Endpoints{
					Backends: map[string]*Backend{
						"172.20.0.1": {
							NodeName: "k8s2",
						},
					},
				},
			}, args: args{
				o: &Endpoints{
					Backends: map[string]*Backend{
						"172.20.0.1": {
							NodeName: "k8s1",
						},
					},
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
			if got := tt.fields.svcEP.DeepEquals(tt.args.o); got != tt.want {
				t.Errorf("Endpoints.DeepEqual() = %v, want %v", got, tt.want)
			}
		})
	}
}

func (s *K8sSuite) Test_parseK8sEPv1(c *check.C) {
	nodeName := "k8s1"

	type args struct {
		eps *slim_corev1.Endpoints
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWanted func() *Endpoints
	}{
		{
			name: "empty endpoint",
			setupArgs: func() args {
				return args{
					eps: &slim_corev1.Endpoints{
						ObjectMeta: slim_metav1.ObjectMeta{
							Name:      "foo",
							Namespace: "bar",
						},
					},
				}
			},
			setupWanted: func() *Endpoints {
				return newEndpoints()
			},
		},
		{
			name: "endpoint with an address and port",
			setupArgs: func() args {
				return args{
					eps: &slim_corev1.Endpoints{
						ObjectMeta: slim_metav1.ObjectMeta{
							Name:      "foo",
							Namespace: "bar",
						},
						Subsets: []slim_corev1.EndpointSubset{
							{
								Addresses: []slim_corev1.EndpointAddress{
									{
										IP:       "172.0.0.1",
										NodeName: &nodeName,
									},
								},
								Ports: []slim_corev1.EndpointPort{
									{
										Name:     "http-test-svc",
										Port:     8080,
										Protocol: slim_corev1.ProtocolTCP,
									},
								},
							},
						},
					},
				}
			},
			setupWanted: func() *Endpoints {
				svcEP := newEndpoints()
				svcEP.Backends["172.0.0.1"] = &Backend{
					Ports: serviceStore.PortConfiguration{
						"http-test-svc": loadbalancer.NewL4Addr(loadbalancer.TCP, 8080),
					},
					NodeName: nodeName,
				}
				return svcEP
			},
		},
		{
			name: "endpoint with an address and 2 ports",
			setupArgs: func() args {
				return args{
					eps: &slim_corev1.Endpoints{
						ObjectMeta: slim_metav1.ObjectMeta{
							Name:      "foo",
							Namespace: "bar",
						},
						Subsets: []slim_corev1.EndpointSubset{
							{
								Addresses: []slim_corev1.EndpointAddress{
									{
										IP:       "172.0.0.1",
										NodeName: &nodeName,
									},
								},
								Ports: []slim_corev1.EndpointPort{
									{
										Name:     "http-test-svc",
										Port:     8080,
										Protocol: slim_corev1.ProtocolTCP,
									},
									{
										Name:     "http-test-svc-2",
										Port:     8081,
										Protocol: slim_corev1.ProtocolTCP,
									},
								},
							},
						},
					},
				}
			},
			setupWanted: func() *Endpoints {
				svcEP := newEndpoints()
				svcEP.Backends["172.0.0.1"] = &Backend{
					Ports: serviceStore.PortConfiguration{
						"http-test-svc":   loadbalancer.NewL4Addr(loadbalancer.TCP, 8080),
						"http-test-svc-2": loadbalancer.NewL4Addr(loadbalancer.TCP, 8081),
					},
					NodeName: nodeName,
				}
				return svcEP
			},
		},
		{
			name: "endpoint with 2 addresses and 2 ports",
			setupArgs: func() args {
				return args{
					eps: &slim_corev1.Endpoints{
						ObjectMeta: slim_metav1.ObjectMeta{
							Name:      "foo",
							Namespace: "bar",
						},
						Subsets: []slim_corev1.EndpointSubset{
							{
								Addresses: []slim_corev1.EndpointAddress{
									{
										IP:       "172.0.0.1",
										NodeName: &nodeName,
									},
									{
										IP: "172.0.0.2",
									},
								},
								Ports: []slim_corev1.EndpointPort{
									{
										Name:     "http-test-svc",
										Port:     8080,
										Protocol: slim_corev1.ProtocolTCP,
									},
									{
										Name:     "http-test-svc-2",
										Port:     8081,
										Protocol: slim_corev1.ProtocolTCP,
									},
								},
							},
						},
					},
				}
			},
			setupWanted: func() *Endpoints {
				svcEP := newEndpoints()
				svcEP.Backends["172.0.0.1"] = &Backend{
					Ports: serviceStore.PortConfiguration{
						"http-test-svc":   loadbalancer.NewL4Addr(loadbalancer.TCP, 8080),
						"http-test-svc-2": loadbalancer.NewL4Addr(loadbalancer.TCP, 8081),
					},
					NodeName: nodeName,
				}
				svcEP.Backends["172.0.0.2"] = &Backend{
					Ports: serviceStore.PortConfiguration{
						"http-test-svc":   loadbalancer.NewL4Addr(loadbalancer.TCP, 8080),
						"http-test-svc-2": loadbalancer.NewL4Addr(loadbalancer.TCP, 8081),
					},
				}
				return svcEP
			},
		},
		{
			name: "endpoint with 2 addresses, 1 address not ready and 2 ports",
			setupArgs: func() args {
				return args{
					eps: &slim_corev1.Endpoints{
						ObjectMeta: slim_metav1.ObjectMeta{
							Name:      "foo",
							Namespace: "bar",
						},
						Subsets: []slim_corev1.EndpointSubset{
							{
								Addresses: []slim_corev1.EndpointAddress{
									{
										IP:       "172.0.0.1",
										NodeName: &nodeName,
									},
									{
										IP: "172.0.0.2",
									},
								},
								Ports: []slim_corev1.EndpointPort{
									{
										Name:     "http-test-svc",
										Port:     8080,
										Protocol: slim_corev1.ProtocolTCP,
									},
									{
										Name:     "http-test-svc-2",
										Port:     8081,
										Protocol: slim_corev1.ProtocolTCP,
									},
								},
							},
						},
					},
				}
			},
			setupWanted: func() *Endpoints {
				svcEP := newEndpoints()
				svcEP.Backends["172.0.0.1"] = &Backend{
					Ports: serviceStore.PortConfiguration{
						"http-test-svc":   loadbalancer.NewL4Addr(loadbalancer.TCP, 8080),
						"http-test-svc-2": loadbalancer.NewL4Addr(loadbalancer.TCP, 8081),
					},
					NodeName: nodeName,
				}
				svcEP.Backends["172.0.0.2"] = &Backend{
					Ports: serviceStore.PortConfiguration{
						"http-test-svc":   loadbalancer.NewL4Addr(loadbalancer.TCP, 8080),
						"http-test-svc-2": loadbalancer.NewL4Addr(loadbalancer.TCP, 8081),
					},
				}
				return svcEP
			},
		},
	}
	for _, tt := range tests {
		args := tt.setupArgs()
		want := tt.setupWanted()
		_, got := ParseEndpoints(args.eps)
		c.Assert(got, checker.DeepEquals, want, check.Commentf("Test name: %q", tt.name))
	}
}

func (s *K8sSuite) TestEndpointsString(c *check.C) {
	endpoints := &slim_corev1.Endpoints{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
		},
		Subsets: []slim_corev1.EndpointSubset{
			{
				Addresses: []slim_corev1.EndpointAddress{
					{
						IP: "172.0.0.2",
					},
					{
						IP: "172.0.0.1",
					},
				},
				Ports: []slim_corev1.EndpointPort{
					{
						Name:     "http-test-svc-2",
						Port:     8081,
						Protocol: slim_corev1.ProtocolTCP,
					},
					{
						Name:     "http-test-svc",
						Port:     8080,
						Protocol: slim_corev1.ProtocolTCP,
					},
				},
			},
		},
	}

	_, ep := ParseEndpoints(endpoints)
	c.Assert(ep.String(), check.Equals, "172.0.0.1:8080/TCP,172.0.0.1:8081/TCP,172.0.0.2:8080/TCP,172.0.0.2:8081/TCP")
}

func (s *K8sSuite) Test_parseK8sEPSlicev1Beta1(c *check.C) {
	nodeName := "k8s1"

	type args struct {
		eps *slim_discovery_v1beta1.EndpointSlice
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWanted func() *Endpoints
	}{
		{
			name: "empty endpoint",
			setupArgs: func() args {
				return args{
					eps: &slim_discovery_v1beta1.EndpointSlice{
						ObjectMeta: slim_metav1.ObjectMeta{
							Name:      "foo",
							Namespace: "bar",
						},
					},
				}
			},
			setupWanted: func() *Endpoints {
				return newEndpoints()
			},
		},
		{
			name: "endpoint with an address and port",
			setupArgs: func() args {
				return args{
					eps: &slim_discovery_v1beta1.EndpointSlice{
						AddressType: slim_discovery_v1beta1.AddressTypeIPv4,
						ObjectMeta: slim_metav1.ObjectMeta{
							Name:      "foo",
							Namespace: "bar",
						},
						Endpoints: []slim_discovery_v1beta1.Endpoint{
							{
								Addresses: []string{
									"172.0.0.1",
								},
								Topology: map[string]string{
									"kubernetes.io/hostname": nodeName,
								},
							},
						},
						Ports: []slim_discovery_v1beta1.EndpointPort{
							{
								Name:     func() *string { a := "http-test-svc"; return &a }(),
								Protocol: func() *slim_corev1.Protocol { a := slim_corev1.ProtocolTCP; return &a }(),
								Port:     func() *int32 { a := int32(8080); return &a }(),
							},
						},
					},
				}
			},
			setupWanted: func() *Endpoints {
				svcEP := newEndpoints()
				svcEP.Backends["172.0.0.1"] = &Backend{
					Ports: serviceStore.PortConfiguration{
						"http-test-svc": loadbalancer.NewL4Addr(loadbalancer.TCP, 8080),
					},
					NodeName: nodeName,
				}
				return svcEP
			},
		},
		{
			name: "endpoint with an address and 2 ports",
			setupArgs: func() args {
				return args{
					eps: &slim_discovery_v1beta1.EndpointSlice{
						AddressType: slim_discovery_v1beta1.AddressTypeIPv4,
						ObjectMeta: slim_metav1.ObjectMeta{
							Name:      "foo",
							Namespace: "bar",
						},
						Endpoints: []slim_discovery_v1beta1.Endpoint{
							{
								Addresses: []string{
									"172.0.0.1",
								},
								Topology: map[string]string{
									"kubernetes.io/hostname": nodeName,
								},
							},
						},
						Ports: []slim_discovery_v1beta1.EndpointPort{
							{
								Name:     func() *string { a := "http-test-svc"; return &a }(),
								Protocol: func() *slim_corev1.Protocol { a := slim_corev1.ProtocolTCP; return &a }(),
								Port:     func() *int32 { a := int32(8080); return &a }(),
							},
							{
								Name:     func() *string { a := "http-test-svc-2"; return &a }(),
								Protocol: func() *slim_corev1.Protocol { a := slim_corev1.ProtocolTCP; return &a }(),
								Port:     func() *int32 { a := int32(8081); return &a }(),
							},
						},
					},
				}
			},
			setupWanted: func() *Endpoints {
				svcEP := newEndpoints()
				svcEP.Backends["172.0.0.1"] = &Backend{
					Ports: serviceStore.PortConfiguration{
						"http-test-svc":   loadbalancer.NewL4Addr(loadbalancer.TCP, 8080),
						"http-test-svc-2": loadbalancer.NewL4Addr(loadbalancer.TCP, 8081),
					},
					NodeName: nodeName,
				}
				return svcEP
			},
		},
		{
			name: "endpoint with 2 addresses and 2 ports",
			setupArgs: func() args {
				return args{
					eps: &slim_discovery_v1beta1.EndpointSlice{
						AddressType: slim_discovery_v1beta1.AddressTypeIPv4,
						ObjectMeta: slim_metav1.ObjectMeta{
							Name:      "foo",
							Namespace: "bar",
						},
						Endpoints: []slim_discovery_v1beta1.Endpoint{
							{
								Addresses: []string{
									"172.0.0.1",
								},
								Topology: map[string]string{
									"kubernetes.io/hostname": nodeName,
								},
							},
							{
								Addresses: []string{
									"172.0.0.2",
								},
							},
						},
						Ports: []slim_discovery_v1beta1.EndpointPort{
							{
								Name:     func() *string { a := "http-test-svc"; return &a }(),
								Protocol: func() *slim_corev1.Protocol { a := slim_corev1.ProtocolTCP; return &a }(),
								Port:     func() *int32 { a := int32(8080); return &a }(),
							},
							{
								Name:     func() *string { a := "http-test-svc-2"; return &a }(),
								Protocol: func() *slim_corev1.Protocol { a := slim_corev1.ProtocolTCP; return &a }(),
								Port:     func() *int32 { a := int32(8081); return &a }(),
							},
						},
					},
				}
			},
			setupWanted: func() *Endpoints {
				svcEP := newEndpoints()
				svcEP.Backends["172.0.0.1"] = &Backend{
					Ports: serviceStore.PortConfiguration{
						"http-test-svc":   loadbalancer.NewL4Addr(loadbalancer.TCP, 8080),
						"http-test-svc-2": loadbalancer.NewL4Addr(loadbalancer.TCP, 8081),
					},
					NodeName: nodeName,
				}
				svcEP.Backends["172.0.0.2"] = &Backend{
					Ports: serviceStore.PortConfiguration{
						"http-test-svc":   loadbalancer.NewL4Addr(loadbalancer.TCP, 8080),
						"http-test-svc-2": loadbalancer.NewL4Addr(loadbalancer.TCP, 8081),
					},
				}
				return svcEP
			},
		},
		{
			name: "endpoint with 2 addresses, 1 address not ready and 2 ports",
			setupArgs: func() args {
				return args{
					eps: &slim_discovery_v1beta1.EndpointSlice{
						ObjectMeta: slim_metav1.ObjectMeta{
							Name:      "foo",
							Namespace: "bar",
						},
						Endpoints: []slim_discovery_v1beta1.Endpoint{
							{
								Addresses: []string{
									"172.0.0.1",
								},
								Topology: map[string]string{
									"kubernetes.io/hostname": nodeName,
								},
							},
							{
								Addresses: []string{
									"172.0.0.2",
								},
							},
							{
								Conditions: slim_discovery_v1beta1.EndpointConditions{
									Ready: func() *bool { a := false; return &a }(),
								},
								Addresses: []string{
									"172.0.0.3",
								},
							},
						},
						Ports: []slim_discovery_v1beta1.EndpointPort{
							{
								Name:     func() *string { a := "http-test-svc"; return &a }(),
								Protocol: func() *slim_corev1.Protocol { a := slim_corev1.ProtocolTCP; return &a }(),
								Port:     func() *int32 { a := int32(8080); return &a }(),
							},
							{
								Name:     func() *string { a := "http-test-svc-2"; return &a }(),
								Protocol: func() *slim_corev1.Protocol { a := slim_corev1.ProtocolTCP; return &a }(),
								Port:     func() *int32 { a := int32(8081); return &a }(),
							},
						},
					},
				}
			},
			setupWanted: func() *Endpoints {
				svcEP := newEndpoints()
				svcEP.Backends["172.0.0.1"] = &Backend{
					Ports: serviceStore.PortConfiguration{
						"http-test-svc":   loadbalancer.NewL4Addr(loadbalancer.TCP, 8080),
						"http-test-svc-2": loadbalancer.NewL4Addr(loadbalancer.TCP, 8081),
					},
					NodeName: nodeName,
				}
				svcEP.Backends["172.0.0.2"] = &Backend{
					Ports: serviceStore.PortConfiguration{
						"http-test-svc":   loadbalancer.NewL4Addr(loadbalancer.TCP, 8080),
						"http-test-svc-2": loadbalancer.NewL4Addr(loadbalancer.TCP, 8081),
					},
				}
				return svcEP
			},
		},
	}
	for _, tt := range tests {
		args := tt.setupArgs()
		want := tt.setupWanted()
		_, got := ParseEndpointSlice(args.eps)
		c.Assert(got, checker.DeepEquals, want, check.Commentf("Test name: %q", tt.name))
	}
}

func Test_parseEndpointPort(t *testing.T) {
	type args struct {
		port slim_discovery_v1beta1.EndpointPort
	}
	tests := []struct {
		name     string
		args     args
		portName string
		l4Addr   *loadbalancer.L4Addr
	}{
		{
			name: "tcp-port",
			args: args{
				port: slim_discovery_v1beta1.EndpointPort{
					Name:     func() *string { a := "http-test-svc"; return &a }(),
					Protocol: func() *slim_corev1.Protocol { a := slim_corev1.ProtocolTCP; return &a }(),
					Port:     func() *int32 { a := int32(8080); return &a }(),
				},
			},
			portName: "http-test-svc",
			l4Addr: &loadbalancer.L4Addr{
				Protocol: loadbalancer.TCP,
				Port:     8080,
			},
		},
		{
			name: "udp-port",
			args: args{
				port: slim_discovery_v1beta1.EndpointPort{
					Name:     func() *string { a := "http-test-svc"; return &a }(),
					Protocol: func() *slim_corev1.Protocol { a := slim_corev1.ProtocolUDP; return &a }(),
					Port:     func() *int32 { a := int32(8080); return &a }(),
				},
			},
			portName: "http-test-svc",
			l4Addr: &loadbalancer.L4Addr{
				Protocol: loadbalancer.UDP,
				Port:     8080,
			},
		},
		{
			name: "unset-protocol-should-have-tcp-port",
			args: args{
				port: slim_discovery_v1beta1.EndpointPort{
					Name: func() *string { a := "http-test-svc"; return &a }(),
					Port: func() *int32 { a := int32(8080); return &a }(),
				},
			},
			portName: "http-test-svc",
			l4Addr: &loadbalancer.L4Addr{
				Protocol: loadbalancer.TCP,
				Port:     8080,
			},
		},
		{
			name: "unset-port-number-should-fail",
			args: args{
				port: slim_discovery_v1beta1.EndpointPort{
					Name: func() *string { a := "http-test-svc"; return &a }(),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPortName, gotL4Addr := parseEndpointPort(tt.args.port)
			if gotPortName != tt.portName {
				t.Errorf("parseEndpointPort() got = %v, want %v", gotPortName, tt.portName)
			}
			if !reflect.DeepEqual(gotL4Addr, tt.l4Addr) {
				t.Errorf("parseEndpointPort() got1 = %v, want %v", gotL4Addr, tt.l4Addr)
			}
		})
	}
}
