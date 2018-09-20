// Copyright 2017 Authors of Cilium
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

package main

import (
	"net"
	"time"

	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/versioned"

	. "gopkg.in/check.v1"
	core_v1 "k8s.io/api/core/v1"
	"k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (ds *DaemonSuite) TestK8sErrorLogTimeout(c *C) {
	errstr := "I am an error string"

	// ensure k8sErrMsg is empty for tests that use it
	k8sErrMsgMU.Lock()
	k8sErrMsg = map[string]time.Time{}
	k8sErrMsgMU.Unlock()

	// Returns true because it's the first time we see this message
	startTime := time.Now()
	c.Assert(k8sErrorUpdateCheckUnmuteTime(errstr, startTime), Equals, true)

	// Returns false because <= k8sErrLogTimeout time has passed
	noLogTime := startTime.Add(k8sErrLogTimeout)
	c.Assert(k8sErrorUpdateCheckUnmuteTime(errstr, noLogTime), Equals, false)

	// Returns true because k8sErrLogTimeout has passed
	shouldLogTime := startTime.Add(k8sErrLogTimeout).Add(time.Nanosecond)
	c.Assert(k8sErrorUpdateCheckUnmuteTime(errstr, shouldLogTime), Equals, true)
}

func (ds *DaemonSuite) Test_missingK8sNetworkPolicyV1(c *C) {
	type args struct {
		m    versioned.Map
		repo *policy.Repository
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWanted func() versioned.Map
	}{
		{
			name: "both equal",
			setupArgs: func() args {
				p1 := policy.NewPolicyRepository()
				return args{
					repo: p1,
					m:    versioned.NewMap(),
				}
			},
			setupWanted: func() versioned.Map {
				return versioned.NewMap()
			},
		},
		{
			name: "repository is missing a policy",
			setupArgs: func() args {
				p1 := policy.NewPolicyRepository()

				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: &v1.NetworkPolicy{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "bar",
							Namespace: "foo",
						},
					},
				})

				return args{
					m:    m,
					repo: p1,
				}
			},
			setupWanted: func() versioned.Map {
				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: &v1.NetworkPolicy{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "bar",
							Namespace: "foo",
						},
					},
				})
				return m
			},
		},
		{
			name: "repository contains all policies",
			setupArgs: func() args {
				p1 := policy.NewPolicyRepository()
				_, err := p1.Add(api.Rule{
					EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("id=a")),
					Labels: labels.LabelArray{labels.NewLabel(k8sConst.PolicyLabelName, "bar", labels.LabelSourceK8s),
						labels.NewLabel(k8sConst.PolicyLabelNamespace, "foo", labels.LabelSourceK8s)},
				})
				c.Assert(err, IsNil)

				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: &v1.NetworkPolicy{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "bar",
							Namespace: "foo",
						},
					},
				})

				return args{
					m:    m,
					repo: p1,
				}
			},
			setupWanted: func() versioned.Map {
				return versioned.NewMap()
			},
		},
	}
	for _, tt := range tests {
		args := tt.setupArgs()
		want := tt.setupWanted()
		ds.d.policy = args.repo
		got := ds.d.missingK8sNetworkPolicyV1(args.m)
		c.Assert(got, DeepEquals, want, Commentf("Test name: %q", tt.name))
	}
}

func (ds *DaemonSuite) Test_missingCNPv2(c *C) {
	type args struct {
		m    versioned.Map
		repo *policy.Repository
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWanted func() versioned.Map
	}{
		{
			name: "both equal",
			setupArgs: func() args {
				p1 := policy.NewPolicyRepository()
				return args{
					repo: p1,
					m:    versioned.NewMap(),
				}
			},
			setupWanted: func() versioned.Map {
				return versioned.NewMap()
			},
		},
		{
			name: "repository is missing a policy",
			setupArgs: func() args {
				p1 := policy.NewPolicyRepository()

				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: &v2.CiliumNetworkPolicy{
						Spec: &api.Rule{
							EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("id=a")),
							Labels:           labels.ParseLabelArray("k8s:name=bar", "k8s:namespace=bar"),
						},
					},
				})

				return args{
					m:    m,
					repo: p1,
				}
			},
			setupWanted: func() versioned.Map {
				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: &v2.CiliumNetworkPolicy{
						Spec: &api.Rule{
							EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("id=a")),
							Labels:           labels.ParseLabelArray("k8s:name=bar", "k8s:namespace=bar"),
						},
					},
				})
				return m
			},
		},
		{
			name: "repository contains all policies",
			setupArgs: func() args {
				p1 := policy.NewPolicyRepository()
				_, err := p1.Add(api.Rule{
					EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("id=a")),
					Labels:           labels.ParseLabelArray("k8s:name=bar", "k8s:namespace=bar"),
				})
				c.Assert(err, IsNil)

				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: &v2.CiliumNetworkPolicy{
						Spec: &api.Rule{
							EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("id=a")),
							Labels:           labels.ParseLabelArray("k8s:name=bar", "k8s:namespace=bar"),
						},
					},
				})

				return args{
					m:    m,
					repo: p1,
				}
			},
			setupWanted: func() versioned.Map {
				return versioned.NewMap()
			},
		},
	}
	for _, tt := range tests {
		args := tt.setupArgs()
		want := tt.setupWanted()
		ds.d.policy = args.repo
		got := ds.d.missingCNPv2(args.m)
		c.Assert(got, DeepEquals, want, Commentf("Test name: %q", tt.name))
	}
}

func (ds *DaemonSuite) Test_parseK8sEPv1(c *C) {
	type args struct {
		eps *core_v1.Endpoints
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWanted func() *loadbalancer.K8sServiceEndpoint
	}{
		{
			name: "empty endpoint",
			setupArgs: func() args {
				return args{
					eps: &core_v1.Endpoints{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo",
							Namespace: "bar",
						},
					},
				}
			},
			setupWanted: func() *loadbalancer.K8sServiceEndpoint {
				return loadbalancer.NewK8sServiceEndpoint()
			},
		},
		{
			name: "endpoint with an address and port",
			setupArgs: func() args {
				return args{
					eps: &core_v1.Endpoints{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo",
							Namespace: "bar",
						},
						Subsets: []core_v1.EndpointSubset{
							{
								Addresses: []core_v1.EndpointAddress{
									{
										IP: "172.0.0.1",
									},
								},
								Ports: []core_v1.EndpointPort{
									{
										Name:     "http-test-svc",
										Port:     8080,
										Protocol: core_v1.ProtocolTCP,
									},
								},
							},
						},
					},
				}
			},
			setupWanted: func() *loadbalancer.K8sServiceEndpoint {
				svcEP := loadbalancer.NewK8sServiceEndpoint()
				p, err := loadbalancer.NewL4Addr(loadbalancer.TCP, 8080)
				c.Assert(err, IsNil)
				svcEP.Ports["http-test-svc"] = p
				svcEP.BEIPs["172.0.0.1"] = true
				return svcEP
			},
		},
		{
			name: "endpoint with an address and 2 ports",
			setupArgs: func() args {
				return args{
					eps: &core_v1.Endpoints{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo",
							Namespace: "bar",
						},
						Subsets: []core_v1.EndpointSubset{
							{
								Addresses: []core_v1.EndpointAddress{
									{
										IP: "172.0.0.1",
									},
								},
								Ports: []core_v1.EndpointPort{
									{
										Name:     "http-test-svc",
										Port:     8080,
										Protocol: core_v1.ProtocolTCP,
									},
									{
										Name:     "http-test-svc-2",
										Port:     8081,
										Protocol: core_v1.ProtocolTCP,
									},
								},
							},
						},
					},
				}
			},
			setupWanted: func() *loadbalancer.K8sServiceEndpoint {
				svcEP := loadbalancer.NewK8sServiceEndpoint()
				p, err := loadbalancer.NewL4Addr(loadbalancer.TCP, 8080)
				c.Assert(err, IsNil)
				svcEP.Ports["http-test-svc"] = p
				p, err = loadbalancer.NewL4Addr(loadbalancer.TCP, 8081)
				c.Assert(err, IsNil)
				svcEP.Ports["http-test-svc-2"] = p
				svcEP.BEIPs["172.0.0.1"] = true
				return svcEP
			},
		},
		{
			name: "endpoint with 2 addresses and 2 ports",
			setupArgs: func() args {
				return args{
					eps: &core_v1.Endpoints{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo",
							Namespace: "bar",
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
								Ports: []core_v1.EndpointPort{
									{
										Name:     "http-test-svc",
										Port:     8080,
										Protocol: core_v1.ProtocolTCP,
									},
									{
										Name:     "http-test-svc-2",
										Port:     8081,
										Protocol: core_v1.ProtocolTCP,
									},
								},
							},
						},
					},
				}
			},
			setupWanted: func() *loadbalancer.K8sServiceEndpoint {
				svcEP := loadbalancer.NewK8sServiceEndpoint()
				p, err := loadbalancer.NewL4Addr(loadbalancer.TCP, 8080)
				c.Assert(err, IsNil)
				svcEP.Ports["http-test-svc"] = p
				p, err = loadbalancer.NewL4Addr(loadbalancer.TCP, 8081)
				c.Assert(err, IsNil)
				svcEP.Ports["http-test-svc-2"] = p
				svcEP.BEIPs["172.0.0.1"] = true
				svcEP.BEIPs["172.0.0.2"] = true
				return svcEP
			},
		},
		{
			name: "endpoint with 2 addresses, 1 address not ready and 2 ports",
			setupArgs: func() args {
				return args{
					eps: &core_v1.Endpoints{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo",
							Namespace: "bar",
						},
						Subsets: []core_v1.EndpointSubset{
							{
								NotReadyAddresses: []core_v1.EndpointAddress{
									{
										IP: "172.0.0.3",
									},
								},
								Addresses: []core_v1.EndpointAddress{
									{
										IP: "172.0.0.1",
									},
									{
										IP: "172.0.0.2",
									},
								},
								Ports: []core_v1.EndpointPort{
									{
										Name:     "http-test-svc",
										Port:     8080,
										Protocol: core_v1.ProtocolTCP,
									},
									{
										Name:     "http-test-svc-2",
										Port:     8081,
										Protocol: core_v1.ProtocolTCP,
									},
								},
							},
						},
					},
				}
			},
			setupWanted: func() *loadbalancer.K8sServiceEndpoint {
				svcEP := loadbalancer.NewK8sServiceEndpoint()
				p, err := loadbalancer.NewL4Addr(loadbalancer.TCP, 8080)
				c.Assert(err, IsNil)
				svcEP.Ports["http-test-svc"] = p
				p, err = loadbalancer.NewL4Addr(loadbalancer.TCP, 8081)
				c.Assert(err, IsNil)
				svcEP.Ports["http-test-svc-2"] = p
				svcEP.BEIPs["172.0.0.1"] = true
				svcEP.BEIPs["172.0.0.2"] = true
				return svcEP
			},
		},
		{
			name: "endpoint with 2 addresses, 1 address not ready, 1 good port and 1 port with unknown protocol",
			setupArgs: func() args {
				return args{
					eps: &core_v1.Endpoints{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo",
							Namespace: "bar",
						},
						Subsets: []core_v1.EndpointSubset{
							{
								NotReadyAddresses: []core_v1.EndpointAddress{
									{
										IP: "172.0.0.3",
									},
								},
								Addresses: []core_v1.EndpointAddress{
									{
										IP: "172.0.0.1",
									},
									{
										IP: "172.0.0.2",
									},
								},
								Ports: []core_v1.EndpointPort{
									{
										Name:     "http-test-svc",
										Port:     8080,
										Protocol: core_v1.ProtocolTCP,
									},
									{
										Name:     "http-test-svc-2",
										Port:     8081,
										Protocol: core_v1.Protocol("foo"),
									},
								},
							},
						},
					},
				}
			},
			setupWanted: func() *loadbalancer.K8sServiceEndpoint {
				svcEP := loadbalancer.NewK8sServiceEndpoint()
				p, err := loadbalancer.NewL4Addr(loadbalancer.TCP, 8080)
				c.Assert(err, IsNil)
				svcEP.Ports["http-test-svc"] = p
				svcEP.BEIPs["172.0.0.1"] = true
				svcEP.BEIPs["172.0.0.2"] = true
				return svcEP
			},
		},
	}
	for _, tt := range tests {
		args := tt.setupArgs()
		want := tt.setupWanted()
		got := parseK8sEPv1(args.eps)
		c.Assert(got, DeepEquals, want, Commentf("Test name: %q", tt.name))
	}
}

func (ds *DaemonSuite) Test_missingK8sEndpointsV1(c *C) {
	type args struct {
		m  versioned.Map
		lb *loadbalancer.LoadBalancer
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWanted func() versioned.Map
	}{
		{
			name: "both equal",
			setupArgs: func() args {
				lb := loadbalancer.NewLoadBalancer()
				return args{
					lb: lb,
					m:  versioned.NewMap(),
				}
			},
			setupWanted: func() versioned.Map {
				return versioned.NewMap()
			},
		},
		{
			name: "loadbalancer is missing an endpoint",
			setupArgs: func() args {
				lb := loadbalancer.NewLoadBalancer()

				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: &core_v1.Endpoints{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo",
							Namespace: "bar",
						},
					},
				})

				return args{
					m:  m,
					lb: lb,
				}
			},
			setupWanted: func() versioned.Map {
				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: &core_v1.Endpoints{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo",
							Namespace: "bar",
						},
					},
				})
				return m
			},
		},
		{
			name: "loadbalancer contains all endpoints",
			setupArgs: func() args {
				lb := loadbalancer.NewLoadBalancer()
				lb.K8sMU.Lock()
				svcNS := loadbalancer.K8sServiceNamespace{
					ServiceName: "foo",
					Namespace:   "bar",
				}
				lb.K8sEndpoints[svcNS] = parseK8sEPv1(&core_v1.Endpoints{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "foo",
						Namespace: "bar",
					},
				})
				lb.K8sMU.Unlock()

				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: &core_v1.Endpoints{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo",
							Namespace: "bar",
						},
					},
				})

				return args{
					m:  m,
					lb: lb,
				}
			},
			setupWanted: func() versioned.Map {
				return versioned.NewMap()
			},
		},
	}
	for _, tt := range tests {
		args := tt.setupArgs()
		want := tt.setupWanted()
		ds.d.loadBalancer = args.lb
		got := ds.d.missingK8sEndpointsV1(args.m)
		c.Assert(got, DeepEquals, want, Commentf("Test name: %q", tt.name))
	}
}

func (ds *DaemonSuite) Test_missingK8sServicesV1(c *C) {
	type args struct {
		m  versioned.Map
		lb *loadbalancer.LoadBalancer
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWanted func() versioned.Map
	}{
		{
			name: "both equal",
			setupArgs: func() args {
				lb := loadbalancer.NewLoadBalancer()
				return args{
					lb: lb,
					m:  versioned.NewMap(),
				}
			},
			setupWanted: func() versioned.Map {
				return versioned.NewMap()
			},
		},
		{
			name: "loadbalancer is missing a service",
			setupArgs: func() args {
				lb := loadbalancer.NewLoadBalancer()

				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: &core_v1.Service{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo",
							Namespace: "bar",
						},
						Spec: core_v1.ServiceSpec{
							Type: core_v1.ServiceTypeClusterIP,
						},
					},
				})

				return args{
					m:  m,
					lb: lb,
				}
			},
			setupWanted: func() versioned.Map {
				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: &core_v1.Service{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo",
							Namespace: "bar",
						},
						Spec: core_v1.ServiceSpec{
							Type: core_v1.ServiceTypeClusterIP,
						},
					},
				})
				return m
			},
		},
		{
			name: "loadbalancer contains all services",
			setupArgs: func() args {
				lb := loadbalancer.NewLoadBalancer()
				lb.K8sMU.Lock()
				svcNS := loadbalancer.K8sServiceNamespace{
					ServiceName: "foo",
					Namespace:   "bar",
				}
				lb.K8sServices[svcNS] = loadbalancer.NewK8sServiceInfo(
					net.ParseIP("127.0.0.1"),
					false,
					map[string]string{
						"foo": "bar",
					},
					map[string]string{
						"foo": "bar",
					})
				lb.K8sMU.Unlock()

				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: &core_v1.Service{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo",
							Namespace: "bar",
							Labels: map[string]string{
								"foo": "bar",
							},
						},
						Spec: core_v1.ServiceSpec{
							ClusterIP: "127.0.0.1",
							Selector: map[string]string{
								"foo": "bar",
							},
							Type: core_v1.ServiceTypeClusterIP,
						},
					},
				})

				return args{
					m:  m,
					lb: lb,
				}
			},
			setupWanted: func() versioned.Map {
				return versioned.NewMap()
			},
		},
	}
	for _, tt := range tests {
		args := tt.setupArgs()
		want := tt.setupWanted()
		ds.d.loadBalancer = args.lb
		got := ds.d.missingK8sServiceV1(args.m)
		c.Assert(got, DeepEquals, want, Commentf("Test name: %q", tt.name))
	}
}
