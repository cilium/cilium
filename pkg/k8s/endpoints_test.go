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
	"testing"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/service"

	"gopkg.in/check.v1"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
					Backends: map[string]service.PortConfiguration{
						"172.20.0.1": map[string]*loadbalancer.L4Addr{
							"foo": {
								Protocol: loadbalancer.NONE,
								Port:     1,
							},
						},
					},
				},
			},
			args: args{
				o: &Endpoints{
					Backends: map[string]service.PortConfiguration{
						"172.20.0.1": map[string]*loadbalancer.L4Addr{
							"foo": {
								Protocol: loadbalancer.NONE,
								Port:     1,
							},
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
					Backends: map[string]service.PortConfiguration{
						"172.20.0.1": map[string]*loadbalancer.L4Addr{
							"foo": {
								Protocol: loadbalancer.NONE,
								Port:     1,
							},
						},
					},
				},
			},
			args: args{
				o: &Endpoints{
					Backends: map[string]service.PortConfiguration{
						"172.20.0.2": map[string]*loadbalancer.L4Addr{
							"foo": {
								Protocol: loadbalancer.NONE,
								Port:     1,
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
					Backends: map[string]service.PortConfiguration{
						"172.20.0.1": map[string]*loadbalancer.L4Addr{
							"foo": {
								Protocol: loadbalancer.NONE,
								Port:     1,
							},
						},
					},
				},
			},
			args: args{
				o: &Endpoints{
					Backends: map[string]service.PortConfiguration{
						"172.20.0.1": map[string]*loadbalancer.L4Addr{
							"foz": {
								Protocol: loadbalancer.NONE,
								Port:     1,
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
					Backends: map[string]service.PortConfiguration{
						"172.20.0.1": map[string]*loadbalancer.L4Addr{
							"foo": {
								Protocol: loadbalancer.NONE,
								Port:     1,
							},
						},
					},
				},
			},
			args: args{
				o: &Endpoints{
					Backends: map[string]service.PortConfiguration{
						"172.20.0.1": map[string]*loadbalancer.L4Addr{
							"foo": {
								Protocol: loadbalancer.NONE,
								Port:     2,
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
					Backends: map[string]service.PortConfiguration{
						"172.20.0.1": map[string]*loadbalancer.L4Addr{
							"foo": {
								Protocol: loadbalancer.NONE,
								Port:     1,
							},
						},
					},
				},
			},
			args: args{
				o: &Endpoints{
					Backends: map[string]service.PortConfiguration{
						"172.20.0.1": map[string]*loadbalancer.L4Addr{
							"foo": {
								Protocol: loadbalancer.NONE,
								Port:     1,
							},
							"baz": {
								Protocol: loadbalancer.NONE,
								Port:     2,
							},
						},
					},
				},
			},
			want: false,
		},
		{
			name:   "ports different one is nil",
			fields: fields{},
			args: args{
				o: &Endpoints{
					Backends: map[string]service.PortConfiguration{
						"172.20.0.1": map[string]*loadbalancer.L4Addr{
							"foo": {
								Protocol: loadbalancer.NONE,
								Port:     1,
							},
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
	type args struct {
		eps *types.Endpoints
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
					eps: &types.Endpoints{
						Endpoints: &v1.Endpoints{
							ObjectMeta: metav1.ObjectMeta{
								Name:      "foo",
								Namespace: "bar",
							},
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
					eps: &types.Endpoints{
						Endpoints: &v1.Endpoints{
							ObjectMeta: metav1.ObjectMeta{
								Name:      "foo",
								Namespace: "bar",
							},
							Subsets: []v1.EndpointSubset{
								{
									Addresses: []v1.EndpointAddress{
										{
											IP: "172.0.0.1",
										},
									},
									Ports: []v1.EndpointPort{
										{
											Name:     "http-test-svc",
											Port:     8080,
											Protocol: v1.ProtocolTCP,
										},
									},
								},
							},
						},
					},
				}
			},
			setupWanted: func() *Endpoints {
				svcEP := newEndpoints()
				svcEP.Backends["172.0.0.1"] = service.PortConfiguration{
					"http-test-svc": loadbalancer.NewL4Addr(loadbalancer.TCP, 8080),
				}
				return svcEP
			},
		},
		{
			name: "endpoint with an address and 2 ports",
			setupArgs: func() args {
				return args{
					eps: &types.Endpoints{
						Endpoints: &v1.Endpoints{
							ObjectMeta: metav1.ObjectMeta{
								Name:      "foo",
								Namespace: "bar",
							},
							Subsets: []v1.EndpointSubset{
								{
									Addresses: []v1.EndpointAddress{
										{
											IP: "172.0.0.1",
										},
									},
									Ports: []v1.EndpointPort{
										{
											Name:     "http-test-svc",
											Port:     8080,
											Protocol: v1.ProtocolTCP,
										},
										{
											Name:     "http-test-svc-2",
											Port:     8081,
											Protocol: v1.ProtocolTCP,
										},
									},
								},
							},
						},
					},
				}
			},
			setupWanted: func() *Endpoints {
				svcEP := newEndpoints()
				svcEP.Backends["172.0.0.1"] = service.PortConfiguration{
					"http-test-svc":   loadbalancer.NewL4Addr(loadbalancer.TCP, 8080),
					"http-test-svc-2": loadbalancer.NewL4Addr(loadbalancer.TCP, 8081),
				}
				return svcEP
			},
		},
		{
			name: "endpoint with 2 addresses and 2 ports",
			setupArgs: func() args {
				return args{
					eps: &types.Endpoints{
						Endpoints: &v1.Endpoints{
							ObjectMeta: metav1.ObjectMeta{
								Name:      "foo",
								Namespace: "bar",
							},
							Subsets: []v1.EndpointSubset{
								{
									Addresses: []v1.EndpointAddress{
										{
											IP: "172.0.0.1",
										},
										{
											IP: "172.0.0.2",
										},
									},
									Ports: []v1.EndpointPort{
										{
											Name:     "http-test-svc",
											Port:     8080,
											Protocol: v1.ProtocolTCP,
										},
										{
											Name:     "http-test-svc-2",
											Port:     8081,
											Protocol: v1.ProtocolTCP,
										},
									},
								},
							},
						},
					},
				}
			},
			setupWanted: func() *Endpoints {
				svcEP := newEndpoints()
				svcEP.Backends["172.0.0.1"] = service.PortConfiguration{
					"http-test-svc":   loadbalancer.NewL4Addr(loadbalancer.TCP, 8080),
					"http-test-svc-2": loadbalancer.NewL4Addr(loadbalancer.TCP, 8081),
				}
				svcEP.Backends["172.0.0.2"] = service.PortConfiguration{
					"http-test-svc":   loadbalancer.NewL4Addr(loadbalancer.TCP, 8080),
					"http-test-svc-2": loadbalancer.NewL4Addr(loadbalancer.TCP, 8081),
				}
				return svcEP
			},
		},
		{
			name: "endpoint with 2 addresses, 1 address not ready and 2 ports",
			setupArgs: func() args {
				return args{
					eps: &types.Endpoints{
						Endpoints: &v1.Endpoints{
							ObjectMeta: metav1.ObjectMeta{
								Name:      "foo",
								Namespace: "bar",
							},
							Subsets: []v1.EndpointSubset{
								{
									NotReadyAddresses: []v1.EndpointAddress{
										{
											IP: "172.0.0.3",
										},
									},
									Addresses: []v1.EndpointAddress{
										{
											IP: "172.0.0.1",
										},
										{
											IP: "172.0.0.2",
										},
									},
									Ports: []v1.EndpointPort{
										{
											Name:     "http-test-svc",
											Port:     8080,
											Protocol: v1.ProtocolTCP,
										},
										{
											Name:     "http-test-svc-2",
											Port:     8081,
											Protocol: v1.ProtocolTCP,
										},
									},
								},
							},
						},
					},
				}
			},
			setupWanted: func() *Endpoints {
				svcEP := newEndpoints()
				svcEP.Backends["172.0.0.1"] = service.PortConfiguration{
					"http-test-svc":   loadbalancer.NewL4Addr(loadbalancer.TCP, 8080),
					"http-test-svc-2": loadbalancer.NewL4Addr(loadbalancer.TCP, 8081),
				}
				svcEP.Backends["172.0.0.2"] = service.PortConfiguration{
					"http-test-svc":   loadbalancer.NewL4Addr(loadbalancer.TCP, 8080),
					"http-test-svc-2": loadbalancer.NewL4Addr(loadbalancer.TCP, 8081),
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
	endpoints := &types.Endpoints{
		Endpoints: &v1.Endpoints{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "foo",
				Namespace: "bar",
			},
			Subsets: []v1.EndpointSubset{
				{
					Addresses: []v1.EndpointAddress{
						{
							IP: "172.0.0.2",
						},
						{
							IP: "172.0.0.1",
						},
					},
					Ports: []v1.EndpointPort{
						{
							Name:     "http-test-svc-2",
							Port:     8081,
							Protocol: v1.ProtocolTCP,
						},
						{
							Name:     "http-test-svc",
							Port:     8080,
							Protocol: v1.ProtocolTCP,
						},
					},
				},
			},
		},
	}

	_, ep := ParseEndpoints(endpoints)
	c.Assert(ep.String(), check.Equals, "172.0.0.1:8080/TCP,172.0.0.1:8081/TCP,172.0.0.2:8080/TCP,172.0.0.2:8081/TCP")
}

func (s *K8sSuite) TestEndpointsMerge(c *check.C) {
	eps1 := &Endpoints{
		Backends: map[string]service.PortConfiguration{
			"172.20.0.1": map[string]*loadbalancer.L4Addr{
				"foo": {
					Protocol: loadbalancer.NONE,
					Port:     1,
				},
			},
		},
	}
	eps2 := &Endpoints{
		Backends: map[string]service.PortConfiguration{
			"172.20.0.2": map[string]*loadbalancer.L4Addr{
				"foo": {
					Protocol: loadbalancer.NONE,
					Port:     1,
				},
			},
		},
	}

	epsWant := &Endpoints{
		Backends: map[string]service.PortConfiguration{
			"172.20.0.1": map[string]*loadbalancer.L4Addr{
				"foo": {
					Protocol: loadbalancer.NONE,
					Port:     1,
				},
			},
			"172.20.0.2": map[string]*loadbalancer.L4Addr{
				"foo": {
					Protocol: loadbalancer.NONE,
					Port:     1,
				},
			},
		},
	}

	// Simple merge
	c.Assert(eps1.Merge(eps2), checker.DeepEquals, epsWant)

	eps1 = &Endpoints{
		Backends: map[string]service.PortConfiguration{
			"172.20.0.1": map[string]*loadbalancer.L4Addr{
				"foo": {
					Protocol: loadbalancer.NONE,
					Port:     1,
				},
			},
			"172.20.0.2": map[string]*loadbalancer.L4Addr{
				"foo": {
					Protocol: loadbalancer.NONE,
					Port:     1,
				},
			},
		},
	}
	eps2 = &Endpoints{
		Backends: map[string]service.PortConfiguration{
			"172.20.0.1": map[string]*loadbalancer.L4Addr{
				"foo": {
					Protocol: loadbalancer.NONE,
					Port:     2,
				},
			},
			"172.20.0.2": map[string]*loadbalancer.L4Addr{
				"foo": {
					Protocol: loadbalancer.NONE,
					Port:     1,
				},
				"bar": {
					Protocol: loadbalancer.NONE,
					Port:     1,
				},
			},
		},
	}

	epsWant = &Endpoints{
		Backends: map[string]service.PortConfiguration{
			"172.20.0.1": map[string]*loadbalancer.L4Addr{
				"foo": {
					Protocol: loadbalancer.NONE,
					Port:     2,
				},
			},
			"172.20.0.2": map[string]*loadbalancer.L4Addr{
				"foo": {
					Protocol: loadbalancer.NONE,
					Port:     1,
				},
				"bar": {
					Protocol: loadbalancer.NONE,
					Port:     1,
				},
			},
		},
	}

	// Existing ports should be merged into existing frontend
	c.Assert(eps1.Merge(eps2), checker.DeepEquals, epsWant)

	// Nil endpoints should keep the same eps1 intact
	c.Assert(eps1.Merge(nil), checker.DeepEquals, epsWant)
}
