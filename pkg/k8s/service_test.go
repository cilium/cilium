// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"net"
	"reflect"
	"testing"

	check "github.com/cilium/checkmate"
	corev1 "k8s.io/api/core/v1"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/cidr"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	fakeDatapath "github.com/cilium/cilium/pkg/datapath/fake"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/option"
	serviceStore "github.com/cilium/cilium/pkg/service/store"
)

func (s *K8sSuite) TestGetAnnotationIncludeExternal(c *check.C) {
	svc := &slim_corev1.Service{ObjectMeta: slim_metav1.ObjectMeta{
		Name: "foo",
	}}
	c.Assert(getAnnotationIncludeExternal(svc), check.Equals, false)

	svc = &slim_corev1.Service{ObjectMeta: slim_metav1.ObjectMeta{
		Annotations: map[string]string{"service.cilium.io/global": "True"},
	}}
	c.Assert(getAnnotationIncludeExternal(svc), check.Equals, true)

	svc = &slim_corev1.Service{ObjectMeta: slim_metav1.ObjectMeta{
		Annotations: map[string]string{"service.cilium.io/global": "false"},
	}}
	c.Assert(getAnnotationIncludeExternal(svc), check.Equals, false)

	svc = &slim_corev1.Service{ObjectMeta: slim_metav1.ObjectMeta{
		Annotations: map[string]string{"service.cilium.io/global": ""},
	}}
	c.Assert(getAnnotationIncludeExternal(svc), check.Equals, false)

	svc = &slim_corev1.Service{ObjectMeta: slim_metav1.ObjectMeta{
		Annotations: map[string]string{"io.cilium/global-service": "True"},
	}}
	c.Assert(getAnnotationIncludeExternal(svc), check.Equals, true)
}

func (s *K8sSuite) TestGetAnnotationShared(c *check.C) {
	svc := &slim_corev1.Service{ObjectMeta: slim_metav1.ObjectMeta{
		Name: "foo",
	}}
	c.Assert(getAnnotationShared(svc), check.Equals, false)
	svc = &slim_corev1.Service{ObjectMeta: slim_metav1.ObjectMeta{
		Annotations: map[string]string{"service.cilium.io/global": "true"},
	}}
	c.Assert(getAnnotationShared(svc), check.Equals, true)

	svc = &slim_corev1.Service{ObjectMeta: slim_metav1.ObjectMeta{
		Annotations: map[string]string{"service.cilium.io/shared": "true"},
	}}
	c.Assert(getAnnotationShared(svc), check.Equals, false)

	svc = &slim_corev1.Service{ObjectMeta: slim_metav1.ObjectMeta{
		Annotations: map[string]string{"service.cilium.io/global": "true", "service.cilium.io/shared": "True"},
	}}
	c.Assert(getAnnotationShared(svc), check.Equals, true)

	svc = &slim_corev1.Service{ObjectMeta: slim_metav1.ObjectMeta{
		Annotations: map[string]string{"service.cilium.io/global": "true", "service.cilium.io/shared": "false"},
	}}
	c.Assert(getAnnotationShared(svc), check.Equals, false)

	svc = &slim_corev1.Service{ObjectMeta: slim_metav1.ObjectMeta{
		Annotations: map[string]string{"service.cilium.io/global": "true", "io.cilium/shared-service": "false"},
	}}
	c.Assert(getAnnotationShared(svc), check.Equals, false)
}

func (s *K8sSuite) TestGetAnnotationServiceAffinity(c *check.C) {
	svc := &slim_corev1.Service{ObjectMeta: slim_metav1.ObjectMeta{
		Annotations: map[string]string{"service.cilium.io/global": "true", "service.cilium.io/affinity": "local"},
	}}
	c.Assert(getAnnotationServiceAffinity(svc), check.Equals, serviceAffinityLocal)

	svc = &slim_corev1.Service{ObjectMeta: slim_metav1.ObjectMeta{
		Annotations: map[string]string{"service.cilium.io/global": "true", "service.cilium.io/affinity": "remote"},
	}}
	c.Assert(getAnnotationServiceAffinity(svc), check.Equals, serviceAffinityRemote)

	svc = &slim_corev1.Service{ObjectMeta: slim_metav1.ObjectMeta{
		Annotations: map[string]string{"service.cilium.io/global": "true", "io.cilium/service-affinity": "local"},
	}}
	c.Assert(getAnnotationServiceAffinity(svc), check.Equals, serviceAffinityLocal)

	svc = &slim_corev1.Service{ObjectMeta: slim_metav1.ObjectMeta{
		Annotations: map[string]string{"service.cilium.io/affinity": "remote"},
	}}
	c.Assert(getAnnotationServiceAffinity(svc), check.Equals, serviceAffinityNone)

	svc = &slim_corev1.Service{ObjectMeta: slim_metav1.ObjectMeta{
		Annotations: map[string]string{},
	}}
	c.Assert(getAnnotationServiceAffinity(svc), check.Equals, serviceAffinityNone)
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
	objMeta := slim_metav1.ObjectMeta{
		Name:      "foo",
		Namespace: "bar",
		Labels: map[string]string{
			"foo": "bar",
		},
	}

	k8sSvc := &slim_corev1.Service{
		ObjectMeta: objMeta,
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
		ExtTrafficPolicy:         loadbalancer.SVCTrafficPolicyCluster,
		IntTrafficPolicy:         loadbalancer.SVCTrafficPolicyCluster,
		FrontendIPs:              []net.IP{net.ParseIP("127.0.0.1")},
		Selector:                 map[string]string{"foo": "bar"},
		Labels:                   map[string]string{"foo": "bar"},
		Ports:                    map[loadbalancer.FEPortName]*loadbalancer.L4Addr{},
		NodePorts:                map[loadbalancer.FEPortName]NodePortToFrontend{},
		LoadBalancerSourceRanges: map[string]*cidr.CIDR{},
		Type:                     loadbalancer.SVCTypeClusterIP,
	})

	k8sSvc = &slim_corev1.Service{
		ObjectMeta: objMeta,
		Spec: slim_corev1.ServiceSpec{
			ClusterIP: "none",
			Type:      slim_corev1.ServiceTypeClusterIP,
		},
	}

	id, svc = ParseService(k8sSvc, fakeDatapath.NewNodeAddressing())
	c.Assert(id, checker.DeepEquals, ServiceID{Namespace: "bar", Name: "foo"})
	c.Assert(svc, checker.DeepEquals, &Service{
		IsHeadless:               true,
		ExtTrafficPolicy:         loadbalancer.SVCTrafficPolicyCluster,
		IntTrafficPolicy:         loadbalancer.SVCTrafficPolicyCluster,
		Labels:                   map[string]string{"foo": "bar"},
		Ports:                    map[loadbalancer.FEPortName]*loadbalancer.L4Addr{},
		NodePorts:                map[loadbalancer.FEPortName]NodePortToFrontend{},
		LoadBalancerSourceRanges: map[string]*cidr.CIDR{},
		Type:                     loadbalancer.SVCTypeClusterIP,
	})

	k8sSvc = &slim_corev1.Service{
		ObjectMeta: objMeta,
		Spec: slim_corev1.ServiceSpec{
			ClusterIP:             "127.0.0.1",
			Type:                  slim_corev1.ServiceTypeNodePort,
			ExternalTrafficPolicy: slim_corev1.ServiceExternalTrafficPolicyTypeLocal,
			InternalTrafficPolicy: slim_corev1.ServiceInternalTrafficPolicyTypeLocal,
		},
	}

	id, svc = ParseService(k8sSvc, fakeDatapath.NewNodeAddressing())
	c.Assert(id, checker.DeepEquals, ServiceID{Namespace: "bar", Name: "foo"})
	c.Assert(svc, checker.DeepEquals, &Service{
		FrontendIPs:              []net.IP{net.ParseIP("127.0.0.1")},
		ExtTrafficPolicy:         loadbalancer.SVCTrafficPolicyLocal,
		IntTrafficPolicy:         loadbalancer.SVCTrafficPolicyLocal,
		Labels:                   map[string]string{"foo": "bar"},
		Ports:                    map[loadbalancer.FEPortName]*loadbalancer.L4Addr{},
		NodePorts:                map[loadbalancer.FEPortName]NodePortToFrontend{},
		LoadBalancerSourceRanges: map[string]*cidr.CIDR{},
		Type:                     loadbalancer.SVCTypeNodePort,
	})

	oldNodePort := option.Config.EnableNodePort
	option.Config.EnableNodePort = true
	defer func() {
		option.Config.EnableNodePort = oldNodePort
	}()
	objMeta.Annotations = map[string]string{
		corev1.AnnotationTopologyAwareHints: "auto",
	}
	k8sSvc = &slim_corev1.Service{
		ObjectMeta: objMeta,
		Spec: slim_corev1.ServiceSpec{
			ClusterIP: "127.0.0.1",
			Type:      slim_corev1.ServiceTypeLoadBalancer,
			Ports: []slim_corev1.ServicePort{
				{
					Name:     "http",
					Port:     80,
					NodePort: 31111,
					Protocol: slim_corev1.ProtocolTCP,
				},
				{
					// NodePort should not be allocated for this entry.
					Name:     "tftp",
					Port:     69,
					NodePort: 0,
					Protocol: slim_corev1.ProtocolUDP,
				},
			},
		},
	}

	ipv4ZeroAddrCluster := cmtypes.MustParseAddrCluster("0.0.0.0")
	ipv4InternalAddrCluster := cmtypes.MustAddrClusterFromIP(fakeDatapath.IPv4InternalAddress)
	ipv4NodePortAddrCluster := cmtypes.MustAddrClusterFromIP(fakeDatapath.IPv4NodePortAddress)

	lbID := loadbalancer.ID(0)
	tcpProto := loadbalancer.L4Type(slim_corev1.ProtocolTCP)
	zeroFE := loadbalancer.NewL3n4AddrID(tcpProto, ipv4ZeroAddrCluster, 31111,
		loadbalancer.ScopeExternal, lbID)
	internalFE := loadbalancer.NewL3n4AddrID(tcpProto, ipv4InternalAddrCluster, 31111,
		loadbalancer.ScopeExternal, lbID)
	nodePortFE := loadbalancer.NewL3n4AddrID(tcpProto, ipv4NodePortAddrCluster, 31111,
		loadbalancer.ScopeExternal, lbID)

	id, svc = ParseService(k8sSvc, fakeDatapath.NewIPv4OnlyNodeAddressing())
	c.Assert(id, checker.DeepEquals, ServiceID{Namespace: "bar", Name: "foo"})
	c.Assert(svc, checker.DeepEquals, &Service{
		FrontendIPs: []net.IP{net.ParseIP("127.0.0.1")},
		Labels:      map[string]string{"foo": "bar"},
		Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
			"http": loadbalancer.NewL4Addr(loadbalancer.L4Type(slim_corev1.ProtocolTCP), uint16(80)),
			"tftp": loadbalancer.NewL4Addr(loadbalancer.L4Type(slim_corev1.ProtocolUDP), uint16(69)),
		},
		ExtTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
		IntTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
		NodePorts: map[loadbalancer.FEPortName]NodePortToFrontend{
			"http": {
				zeroFE.String():     zeroFE,
				internalFE.String(): internalFE,
				nodePortFE.String(): nodePortFE,
			},
		},
		LoadBalancerSourceRanges: map[string]*cidr.CIDR{},
		K8sExternalIPs:           map[string]net.IP{},
		LoadBalancerIPs:          map[string]net.IP{},
		Type:                     loadbalancer.SVCTypeLoadBalancer,
		TopologyAware:            true,
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
				FrontendIPs: []net.IP{net.ParseIP("1.1.1.1")},
				IsHeadless:  true,
				Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
					loadbalancer.FEPortName("foo"): {
						Protocol: loadbalancer.NONE,
						Port:     1,
					},
				},
				Shared:          true,
				IncludeExternal: true,
				NodePorts: map[loadbalancer.FEPortName]NodePortToFrontend{
					loadbalancer.FEPortName("foo"): {
						"0.0.0.0:31000": {
							L3n4Addr: loadbalancer.L3n4Addr{
								L4Addr: loadbalancer.L4Addr{
									Protocol: loadbalancer.NONE,
									Port:     31000,
								},
								AddrCluster: cmtypes.MustParseAddrCluster("0.0.0.0"),
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
					FrontendIPs: []net.IP{net.ParseIP("1.1.1.1")},
					IsHeadless:  true,
					Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
						loadbalancer.FEPortName("foo"): {
							Protocol: loadbalancer.NONE,
							Port:     1,
						},
					},
					Shared:          true,
					IncludeExternal: true,
					NodePorts: map[loadbalancer.FEPortName]NodePortToFrontend{
						loadbalancer.FEPortName("foo"): {
							"0.0.0.0:31000": {
								L3n4Addr: loadbalancer.L3n4Addr{
									L4Addr: loadbalancer.L4Addr{
										Protocol: loadbalancer.NONE,
										Port:     31000,
									},
									AddrCluster: cmtypes.MustParseAddrCluster("0.0.0.0"),
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
				FrontendIPs: []net.IP{net.ParseIP("1.1.1.1")},
				IsHeadless:  true,
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
					FrontendIPs: []net.IP{net.ParseIP("1.1.1.1")},
					IsHeadless:  true,
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
			name: "different shared",
			fields: &Service{
				FrontendIPs: []net.IP{net.ParseIP("1.1.1.1")},
				IsHeadless:  true,
				Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
					loadbalancer.FEPortName("foo"): {
						Protocol: loadbalancer.NONE,
						Port:     1,
					},
				},
				Shared:   true,
				Labels:   map[string]string{},
				Selector: map[string]string{},
			},
			args: args{
				o: &Service{
					FrontendIPs: []net.IP{net.ParseIP("1.1.1.1")},
					IsHeadless:  true,
					Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
						loadbalancer.FEPortName("foo"): {
							Protocol: loadbalancer.NONE,
							Port:     1,
						},
					},
					Shared: false,
					Labels: map[string]string{},
					Selector: map[string]string{
						"baz": "foz",
					},
				},
			},
			want: false,
		},
		{
			name: "different include external",
			fields: &Service{
				FrontendIPs: []net.IP{net.ParseIP("1.1.1.1")},
				IsHeadless:  true,
				Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
					loadbalancer.FEPortName("foo"): {
						Protocol: loadbalancer.NONE,
						Port:     1,
					},
				},
				IncludeExternal: true,
				Labels:          map[string]string{},
				Selector:        map[string]string{},
			},
			args: args{
				o: &Service{
					FrontendIPs: []net.IP{net.ParseIP("1.1.1.1")},
					IsHeadless:  true,
					Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
						loadbalancer.FEPortName("foo"): {
							Protocol: loadbalancer.NONE,
							Port:     1,
						},
					},
					IncludeExternal: false,
					Labels:          map[string]string{},
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
				FrontendIPs: []net.IP{net.ParseIP("1.1.1.1")},
				IsHeadless:  true,
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
					FrontendIPs: []net.IP{net.ParseIP("1.1.1.1")},
					IsHeadless:  true,
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
				FrontendIPs: []net.IP{net.ParseIP("1.1.1.1")},
				IsHeadless:  true,
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
					FrontendIPs: []net.IP{net.ParseIP("1.1.1.1")},
					IsHeadless:  true,
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
				FrontendIPs: []net.IP{net.ParseIP("1.1.1.1")},
				IsHeadless:  true,
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
					FrontendIPs: []net.IP{net.ParseIP("1.1.1.1")},
					IsHeadless:  true,
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
				FrontendIPs: []net.IP{net.ParseIP("1.1.1.1")},
				IsHeadless:  true,
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
					FrontendIPs: []net.IP{net.ParseIP("1.1.1.1")},
					IsHeadless:  true,
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
				FrontendIPs: []net.IP{net.ParseIP("1.1.1.1")},
				IsHeadless:  true,
				Labels:      map[string]string{},
				Selector:    map[string]string{},
			},
			args: args{
				o: &Service{
					FrontendIPs: []net.IP{net.ParseIP("1.1.1.1")},
					IsHeadless:  true,
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
				FrontendIPs: []net.IP{net.ParseIP("1.1.1.1")},
				IsHeadless:  true,
				Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
					loadbalancer.FEPortName("foo"): {
						Protocol: loadbalancer.NONE,
						Port:     1,
					},
				},
				NodePorts: map[loadbalancer.FEPortName]NodePortToFrontend{
					loadbalancer.FEPortName("foo"): {
						"1.1.1.1:31000": {
							L3n4Addr: loadbalancer.L3n4Addr{
								L4Addr: loadbalancer.L4Addr{
									Protocol: loadbalancer.NONE,
									Port:     31000,
								},
								AddrCluster: cmtypes.MustParseAddrCluster("1.1.1.1"),
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
					FrontendIPs: []net.IP{net.ParseIP("1.1.1.1")},
					IsHeadless:  true,
					Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
						loadbalancer.FEPortName("foo"): {
							Protocol: loadbalancer.NONE,
							Port:     1,
						},
					},
					NodePorts: map[loadbalancer.FEPortName]NodePortToFrontend{
						loadbalancer.FEPortName("foo"): {
							"0.0.0.0:31000": {
								L3n4Addr: loadbalancer.L3n4Addr{
									L4Addr: loadbalancer.L4Addr{
										Protocol: loadbalancer.NONE,
										Port:     31000,
									},
									AddrCluster: cmtypes.MustParseAddrCluster("0.0.0.0"),
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
				FrontendIPs: []net.IP{net.ParseIP("1.1.1.1")},
				IsHeadless:  false,
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
					FrontendIPs: []net.IP{net.ParseIP("1.1.1.1")},
					IsHeadless:  false,
					Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
						loadbalancer.FEPortName("foo"): {
							Protocol: loadbalancer.NONE,
							Port:     1,
						},
					},
					K8sExternalIPs: map[string]net.IP{
						"10.0.0.2": net.ParseIP("10.0.0.2"),
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
				FrontendIPs: []net.IP{net.ParseIP("1.1.1.1")},
				IsHeadless:  false,
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
					FrontendIPs: []net.IP{net.ParseIP("1.1.1.1")},
					IsHeadless:  false,
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
				FrontendIPs: []net.IP{net.ParseIP("1.1.1.1")},
				IsHeadless:  false,
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
					FrontendIPs: []net.IP{net.ParseIP("1.1.1.1")},
					IsHeadless:  false,
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
			if got := si.DeepEqual(tt.args.o); got != tt.want {
				t.Errorf("Service.Equals() = %v, want %v", got, tt.want)
			}
		})
	}
}

func (s *K8sSuite) TestServiceString(c *check.C) {
	tests := []struct {
		name      string
		service   *slim_corev1.Service
		svcString string
		equals    bool
	}{
		{
			name: "k8s-ipv4-only-clusterip-service",
			service: &slim_corev1.Service{
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
			},
			svcString: "frontends:[127.0.0.1]/ports=[]/selector=map[foo:bar]",
			equals:    true,
		},

		{
			name: "k8s-dual-stack-clusterip-service",
			service: &slim_corev1.Service{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name:      "foo",
					Namespace: "bar",
					Labels: map[string]string{
						"foo": "bar",
					},
				},
				Spec: slim_corev1.ServiceSpec{
					ClusterIP: "127.0.0.1",
					ClusterIPs: []string{
						"127.0.0.1",
						"fd00::1",
					},
					IPFamilies: []slim_corev1.IPFamily{
						slim_corev1.IPv4Protocol,
						slim_corev1.IPv6Protocol,
					},
					Selector: map[string]string{
						"foo": "bar",
					},
					Type: slim_corev1.ServiceTypeClusterIP,
				},
			},
			svcString: "frontends:[127.0.0.1 fd00::1]/ports=[]/selector=map[foo:bar]",
			equals:    true,
		},
	}

	nodeAddressing := fakeDatapath.NewNodeAddressing()
	for _, tt := range tests {
		_, svc := ParseService(tt.service, nodeAddressing)
		c.Assert(svc.String(), check.Equals, tt.svcString)
	}
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
				Addresses: []slim_corev1.EndpointAddress{{IP: "10.0.0.2"}},
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
			"10.0.0.2": {
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
