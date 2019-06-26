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
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/loadbalancer"

	"gopkg.in/check.v1"
	"k8s.io/api/extensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func (s *K8sSuite) TestParseIngressID(c *check.C) {
	k8sIngress := &types.Ingress{
		Ingress: &v1beta1.Ingress{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "bar",
			},
			Spec: v1beta1.IngressSpec{
				Backend: &v1beta1.IngressBackend{
					ServiceName: "foo",
				},
			},
		},
	}

	c.Assert(ParseIngressID(k8sIngress), checker.DeepEquals, ServiceID{Namespace: "bar", Name: "foo"})
}

func (s *K8sSuite) TestParseIngress(c *check.C) {
	k8sIngress := &types.Ingress{
		Ingress: &v1beta1.Ingress{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "bar",
			},
			Spec: v1beta1.IngressSpec{
				Backend: &v1beta1.IngressBackend{
					ServiceName: "svc1",
					ServicePort: intstr.IntOrString{
						IntVal: 8080,
						StrVal: "foo",
						Type:   intstr.Int,
					},
				},
			},
		},
	}
	host := net.ParseIP("172.0.0.1")

	id, ingress, err := ParseIngress(k8sIngress, host)
	c.Assert(err, check.IsNil)
	c.Assert(id, checker.DeepEquals, ServiceID{Namespace: "bar", Name: "svc1"})
	c.Assert(ingress, checker.DeepEquals, &Service{
		FrontendIP: net.ParseIP("172.0.0.1"),
		Ports: map[loadbalancer.FEPortName]*loadbalancer.FEPort{
			loadbalancer.FEPortName("svc1/8080"): {
				L4Addr: &loadbalancer.L4Addr{
					Protocol: loadbalancer.TCP,
					Port:     8080,
				},
			},
		},
		NodePorts: map[loadbalancer.FEPortName]map[string]*loadbalancer.L3n4AddrID{},
	})
}

func (s *K8sSuite) Test_parsingV1beta1(c *check.C) {
	type args struct {
		i    *types.Ingress
		host net.IP
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWanted func() (*Service, error)
	}{
		{
			name: "Parse a normal Single Service Ingress with no ports",
			setupArgs: func() args {
				return args{
					i: &types.Ingress{
						Ingress: &v1beta1.Ingress{
							Spec: v1beta1.IngressSpec{
								Backend: &v1beta1.IngressBackend{
									ServiceName: "svc1",
								},
							},
						},
					},
					host: net.ParseIP("172.0.0.1"),
				}
			},
			setupWanted: func() (*Service, error) {
				return nil, fmt.Errorf("invalid port number")
			},
		},
		{
			name: "Parse a normal Single Service Ingress with ports",
			setupArgs: func() args {
				return args{
					i: &types.Ingress{
						Ingress: &v1beta1.Ingress{
							Spec: v1beta1.IngressSpec{
								Backend: &v1beta1.IngressBackend{
									ServiceName: "svc1",
									ServicePort: intstr.IntOrString{
										IntVal: 8080,
										StrVal: "foo",
										Type:   intstr.Int,
									},
								},
							},
						},
					},
					host: net.ParseIP("172.0.0.1"),
				}
			},
			setupWanted: func() (*Service, error) {
				return &Service{
					FrontendIP: net.ParseIP("172.0.0.1"),
					Ports: map[loadbalancer.FEPortName]*loadbalancer.FEPort{
						loadbalancer.FEPortName("svc1/8080"): {
							L4Addr: &loadbalancer.L4Addr{
								Protocol: loadbalancer.TCP,
								Port:     8080,
							},
						},
					},
					NodePorts: map[loadbalancer.FEPortName]map[string]*loadbalancer.L3n4AddrID{},
				}, nil
			},
		},
	}
	for _, tt := range tests {
		args := tt.setupArgs()
		wantK8sSvcInfo, wantError := tt.setupWanted()
		_, gotK8sSvcInfo, gotError := ParseIngress(args.i, args.host)
		c.Assert(gotError, checker.DeepEquals, wantError, check.Commentf("Test name: %q", tt.name))
		c.Assert(gotK8sSvcInfo, checker.DeepEquals, wantK8sSvcInfo, check.Commentf("Test name: %q", tt.name))
	}
}

func (s *K8sSuite) Test_supportV1beta1(c *check.C) {
	type args struct {
		i *types.Ingress
	}
	tests := []struct {
		name      string
		setupArgs func() args
		want      bool
	}{
		{
			name: "We only support Single Service Ingress, which means Spec.Backend is not nil",
			setupArgs: func() args {
				return args{
					i: &types.Ingress{
						Ingress: &v1beta1.Ingress{
							Spec: v1beta1.IngressSpec{
								Backend: &v1beta1.IngressBackend{
									ServiceName: "svc1",
								},
							},
						},
					},
				}
			},
			want: true,
		},
		{
			name: "We don't support any other ingress type",
			setupArgs: func() args {
				return args{
					i: &types.Ingress{
						Ingress: &v1beta1.Ingress{
							Spec: v1beta1.IngressSpec{
								Rules: []v1beta1.IngressRule{
									{
										Host: "hostless",
									},
								},
							},
						},
					},
				}
			},
			want: false,
		},
	}
	for _, tt := range tests {
		args := tt.setupArgs()
		want := tt.want
		got := supportV1beta1(args.i)
		c.Assert(got, checker.DeepEquals, want, check.Commentf("Test name: %q", tt.name))
	}
}
