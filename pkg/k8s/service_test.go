// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"net"
	"net/netip"
	"reflect"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/cidr"
	serviceStore "github.com/cilium/cilium/pkg/clustermesh/store"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	fakeTypes "github.com/cilium/cilium/pkg/datapath/fake/types"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
)

func TestGetTopologyAware(t *testing.T) {
	tests := []struct {
		name                string
		annotations         map[string]string
		trafficDistribution string
		expectTopologyAware bool
	}{{
		name: "hints annotation == auto",
		annotations: map[string]string{
			corev1.DeprecatedAnnotationTopologyAwareHints: "auto",
		},
		expectTopologyAware: true,
	}, {
		name: "hints annotation == Auto",
		annotations: map[string]string{
			corev1.DeprecatedAnnotationTopologyAwareHints: "Auto",
		},
		expectTopologyAware: true,
	}, {
		name: "hints annotation == Disabled",
		annotations: map[string]string{
			corev1.DeprecatedAnnotationTopologyAwareHints: "Disabled",
		},
		expectTopologyAware: false,
	}, {
		name: "mode annotation == auto",
		annotations: map[string]string{
			corev1.AnnotationTopologyMode: "auto",
		},
		expectTopologyAware: true,
	}, {
		name: "mode annotation == Auto",
		annotations: map[string]string{
			corev1.AnnotationTopologyMode: "Auto",
		},
		expectTopologyAware: true,
	}, {
		name: "mode annotation == Disabled",
		annotations: map[string]string{
			corev1.AnnotationTopologyMode: "Disabled",
		},
		expectTopologyAware: false,
	}, {
		name: "mode annotation == example.com/custom",
		annotations: map[string]string{
			corev1.AnnotationTopologyMode: "example.com/custom",
		},
		expectTopologyAware: true,
	}, {
		name:                "trafficDistribution == PreferClose",
		trafficDistribution: corev1.ServiceTrafficDistributionPreferClose,
		expectTopologyAware: true,
	}, {
		name:                "trafficDistribution == SomethingElse",
		trafficDistribution: "SomethingElse",
		expectTopologyAware: false,
	}, {
		name: "mode annotation == Disabled, trafficDistribution == PreferClose",
		annotations: map[string]string{
			corev1.AnnotationTopologyMode: "Disabled",
		},
		trafficDistribution: corev1.ServiceTrafficDistributionPreferClose,
		expectTopologyAware: true,
	}, {
		name: "hints annotation == Disabled, trafficDistribution == PreferClose",
		annotations: map[string]string{
			corev1.DeprecatedAnnotationTopologyAwareHints: "Disabled",
		},
		trafficDistribution: corev1.ServiceTrafficDistributionPreferClose,
		expectTopologyAware: true,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc := &slim_corev1.Service{
				ObjectMeta: slim_metav1.ObjectMeta{
					Annotations: map[string]string{},
				},
				Spec: slim_corev1.ServiceSpec{},
			}
			if tc.annotations != nil {
				svc.Annotations = tc.annotations
			}
			if tc.trafficDistribution != "" {
				svc.Spec.TrafficDistribution = &tc.trafficDistribution
			}

			require.Equal(t, tc.expectTopologyAware, getTopologyAware(svc))
		})
	}
}

func TestGetAnnotationTopologyAwareHints(t *testing.T) {
	svc := &slim_corev1.Service{ObjectMeta: slim_metav1.ObjectMeta{
		Annotations: map[string]string{},
	}}
	require.False(t, getAnnotationTopologyAwareHints(svc))

	svc = &slim_corev1.Service{ObjectMeta: slim_metav1.ObjectMeta{
		Annotations: map[string]string{
			corev1.DeprecatedAnnotationTopologyAwareHints: "auto",
		},
	}}
	require.True(t, getAnnotationTopologyAwareHints(svc))

	svc = &slim_corev1.Service{ObjectMeta: slim_metav1.ObjectMeta{
		Annotations: map[string]string{
			corev1.DeprecatedAnnotationTopologyAwareHints: "Auto",
		},
	}}
	require.True(t, getAnnotationTopologyAwareHints(svc))

	svc = &slim_corev1.Service{ObjectMeta: slim_metav1.ObjectMeta{
		Annotations: map[string]string{
			corev1.AnnotationTopologyMode: "auto",
		},
	}}
	require.True(t, getAnnotationTopologyAwareHints(svc))

	svc = &slim_corev1.Service{ObjectMeta: slim_metav1.ObjectMeta{
		Annotations: map[string]string{
			corev1.AnnotationTopologyMode: "PreferZone",
		},
	}}
	require.True(t, getAnnotationTopologyAwareHints(svc))

	// v1.DeprecatedAnnotationTopologyAwareHints has precedence over v1.AnnotationTopologyMode.
	svc = &slim_corev1.Service{ObjectMeta: slim_metav1.ObjectMeta{
		Annotations: map[string]string{
			corev1.DeprecatedAnnotationTopologyAwareHints: "disabled",
			corev1.AnnotationTopologyMode:                 "auto",
		},
	}}
	require.False(t, getAnnotationTopologyAwareHints(svc))

	svc = &slim_corev1.Service{ObjectMeta: slim_metav1.ObjectMeta{
		Annotations: map[string]string{
			corev1.DeprecatedAnnotationTopologyAwareHints: "auto",
			corev1.AnnotationTopologyMode:                 "deprecated",
		},
	}}
	require.True(t, getAnnotationTopologyAwareHints(svc))
}

func TestParseServiceID(t *testing.T) {
	svc := &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
		},
	}

	require.Equal(t, ServiceID{Namespace: "bar", Name: "foo"}, ParseServiceID(svc))
}

func TestParseServiceWithServiceTypeExposure(t *testing.T) {
	objMeta := slim_metav1.ObjectMeta{
		Name:      "foo",
		Namespace: "bar",
		Labels: map[string]string{
			"foo": "bar",
		},
		Annotations: map[string]string{},
	}

	k8sSvc := &slim_corev1.Service{
		ObjectMeta: objMeta,
		Spec: slim_corev1.ServiceSpec{
			ClusterIP: "10.96.0.1",
			Type:      slim_corev1.ServiceTypeLoadBalancer,
			Ports: []slim_corev1.ServicePort{
				{
					Name:     "http",
					Port:     80,
					NodePort: 31111,
					Protocol: slim_corev1.ProtocolTCP,
				},
			},
		},
		Status: slim_corev1.ServiceStatus{
			LoadBalancer: slim_corev1.LoadBalancerStatus{
				Ingress: []slim_corev1.LoadBalancerIngress{
					{IP: "3.3.3.3"},
				},
			},
		},
	}

	ipv4InternalAddrCluster := cmtypes.MustAddrClusterFromIP(fakeTypes.IPv4InternalAddress)
	addrs := []netip.Addr{
		ipv4InternalAddrCluster.Addr(),
	}

	oldNodePort := option.Config.EnableNodePort
	option.Config.EnableNodePort = true
	defer func() {
		option.Config.EnableNodePort = oldNodePort
	}()

	lbcfg := loadbalancer.DefaultConfig

	_, svc := ParseService(hivetest.Logger(t), lbcfg, k8sSvc, addrs)
	require.Len(t, svc.FrontendIPs, 1)
	require.Len(t, svc.NodePorts, 1)
	require.Len(t, svc.LoadBalancerIPs, 1)

	// Expose only ClusterIP

	k8sSvc.Annotations[annotation.ServiceTypeExposure] = "ClusterIP"
	_, svc = ParseService(hivetest.Logger(t), lbcfg, k8sSvc, addrs)
	require.Len(t, svc.FrontendIPs, 1)
	require.Empty(t, svc.NodePorts)
	require.Empty(t, svc.LoadBalancerIPs)
	require.Len(t, svc.Ports, 1)

	// Expose only NodePort

	k8sSvc.Annotations[annotation.ServiceTypeExposure] = "NodePort"
	_, svc = ParseService(hivetest.Logger(t), lbcfg, k8sSvc, addrs)
	require.Empty(t, svc.FrontendIPs)
	require.Len(t, svc.NodePorts, 1)
	require.Empty(t, svc.LoadBalancerIPs)
	require.Len(t, svc.Ports, 1)

	// Expose only LoadBalancer

	k8sSvc.Annotations[annotation.ServiceTypeExposure] = "LoadBalancer"
	_, svc = ParseService(hivetest.Logger(t), lbcfg, k8sSvc, addrs)
	require.Empty(t, svc.FrontendIPs)
	require.Empty(t, svc.NodePorts)
	require.Len(t, svc.LoadBalancerIPs, 1)
	require.Len(t, svc.Ports, 1)

	// Expose all

	delete(k8sSvc.Annotations, annotation.ServiceTypeExposure)
	_, svc = ParseService(hivetest.Logger(t), lbcfg, k8sSvc, addrs)
	require.Len(t, svc.FrontendIPs, 1)
	require.Len(t, svc.NodePorts, 1)
	require.Len(t, svc.LoadBalancerIPs, 1)
	require.Len(t, svc.Ports, 1)
}

func TestParseService(t *testing.T) {
	lbcfg := loadbalancer.DefaultConfig
	lbcfg.LBMode = loadbalancer.LBModeSNAT

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

	id, svc := ParseService(hivetest.Logger(t), lbcfg, k8sSvc, nil)
	require.Equal(t, ServiceID{Namespace: "bar", Name: "foo"}, id)
	require.Equal(t, &Service{
		ExtTrafficPolicy:         loadbalancer.SVCTrafficPolicyCluster,
		IntTrafficPolicy:         loadbalancer.SVCTrafficPolicyCluster,
		FrontendIPs:              []net.IP{net.ParseIP("127.0.0.1")},
		Selector:                 map[string]string{"foo": "bar"},
		Labels:                   map[string]string{"foo": "bar"},
		Ports:                    map[loadbalancer.FEPortName]*loadbalancer.L4Addr{},
		NodePorts:                map[loadbalancer.FEPortName]NodePortToFrontend{},
		LoadBalancerSourceRanges: map[string]*cidr.CIDR{},
		SourceRangesPolicy:       loadbalancer.SVCSourceRangesPolicyAllow,
		ProxyDelegation:          loadbalancer.SVCProxyDelegationNone,
		Type:                     loadbalancer.SVCTypeClusterIP,
		ForwardingMode:           loadbalancer.SVCForwardingModeSNAT,
		LoadBalancerAlgorithm:    loadbalancer.SVCLoadBalancingAlgorithmRandom,
	}, svc)

	k8sSvc = &slim_corev1.Service{
		ObjectMeta: objMeta,
		Spec: slim_corev1.ServiceSpec{
			ClusterIP: "none",
			Type:      slim_corev1.ServiceTypeClusterIP,
		},
	}

	id, svc = ParseService(hivetest.Logger(t), lbcfg, k8sSvc, nil)
	require.Equal(t, ServiceID{Namespace: "bar", Name: "foo"}, id)
	require.Equal(t, &Service{
		IsHeadless:               true,
		ExtTrafficPolicy:         loadbalancer.SVCTrafficPolicyCluster,
		IntTrafficPolicy:         loadbalancer.SVCTrafficPolicyCluster,
		Labels:                   map[string]string{"foo": "bar"},
		Ports:                    map[loadbalancer.FEPortName]*loadbalancer.L4Addr{},
		NodePorts:                map[loadbalancer.FEPortName]NodePortToFrontend{},
		LoadBalancerSourceRanges: map[string]*cidr.CIDR{},
		SourceRangesPolicy:       loadbalancer.SVCSourceRangesPolicyAllow,
		ProxyDelegation:          loadbalancer.SVCProxyDelegationNone,
		Type:                     loadbalancer.SVCTypeClusterIP,
		ForwardingMode:           loadbalancer.SVCForwardingModeSNAT,
		LoadBalancerAlgorithm:    loadbalancer.SVCLoadBalancingAlgorithmRandom,
	}, svc)

	k8sSvc = &slim_corev1.Service{
		ObjectMeta: *objMeta.DeepCopy(),
		Spec: slim_corev1.ServiceSpec{
			Type:      slim_corev1.ServiceTypeClusterIP,
			ClusterIP: "127.0.0.1",
		},
	}
	k8sSvc.ObjectMeta.Labels[corev1.IsHeadlessService] = ""

	id, svc = ParseService(hivetest.Logger(t), lbcfg, k8sSvc, nil)
	require.Equal(t, ServiceID{Namespace: "bar", Name: "foo"}, id)
	require.Equal(t, &Service{
		IsHeadless:               true,
		ExtTrafficPolicy:         loadbalancer.SVCTrafficPolicyCluster,
		IntTrafficPolicy:         loadbalancer.SVCTrafficPolicyCluster,
		FrontendIPs:              []net.IP{net.ParseIP("127.0.0.1")},
		Labels:                   map[string]string{"foo": "bar", corev1.IsHeadlessService: ""},
		Ports:                    map[loadbalancer.FEPortName]*loadbalancer.L4Addr{},
		NodePorts:                map[loadbalancer.FEPortName]NodePortToFrontend{},
		LoadBalancerSourceRanges: map[string]*cidr.CIDR{},
		SourceRangesPolicy:       loadbalancer.SVCSourceRangesPolicyAllow,
		ProxyDelegation:          loadbalancer.SVCProxyDelegationNone,
		Type:                     loadbalancer.SVCTypeClusterIP,
		ForwardingMode:           loadbalancer.SVCForwardingModeSNAT,
		LoadBalancerAlgorithm:    loadbalancer.SVCLoadBalancingAlgorithmRandom,
	}, svc)

	serviceInternalTrafficPolicyLocal := slim_corev1.ServiceInternalTrafficPolicyLocal
	k8sSvc = &slim_corev1.Service{
		ObjectMeta: objMeta,
		Spec: slim_corev1.ServiceSpec{
			ClusterIP:             "127.0.0.1",
			Type:                  slim_corev1.ServiceTypeNodePort,
			ExternalTrafficPolicy: slim_corev1.ServiceExternalTrafficPolicyLocal,
			InternalTrafficPolicy: &serviceInternalTrafficPolicyLocal,
		},
	}

	id, svc = ParseService(hivetest.Logger(t), lbcfg, k8sSvc, nil)
	require.Equal(t, ServiceID{Namespace: "bar", Name: "foo"}, id)
	require.Equal(t, &Service{
		FrontendIPs:              []net.IP{net.ParseIP("127.0.0.1")},
		ExtTrafficPolicy:         loadbalancer.SVCTrafficPolicyLocal,
		IntTrafficPolicy:         loadbalancer.SVCTrafficPolicyLocal,
		Labels:                   map[string]string{"foo": "bar"},
		Ports:                    map[loadbalancer.FEPortName]*loadbalancer.L4Addr{},
		NodePorts:                map[loadbalancer.FEPortName]NodePortToFrontend{},
		LoadBalancerSourceRanges: map[string]*cidr.CIDR{},
		SourceRangesPolicy:       loadbalancer.SVCSourceRangesPolicyAllow,
		ProxyDelegation:          loadbalancer.SVCProxyDelegationNone,
		Type:                     loadbalancer.SVCTypeNodePort,
		ForwardingMode:           loadbalancer.SVCForwardingModeSNAT,
		LoadBalancerAlgorithm:    loadbalancer.SVCLoadBalancingAlgorithmRandom,
	}, svc)

	oldNodePort := option.Config.EnableNodePort
	option.Config.EnableNodePort = true
	defer func() {
		option.Config.EnableNodePort = oldNodePort
	}()
	objMeta.Annotations = map[string]string{
		corev1.DeprecatedAnnotationTopologyAwareHints: "auto",
	}
	loadbalancerIngressIP := "127.0.0.1"
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
		Status: slim_corev1.ServiceStatus{
			LoadBalancer: slim_corev1.LoadBalancerStatus{
				Ingress: []slim_corev1.LoadBalancerIngress{
					{
						IP: loadbalancerIngressIP,
					},
				},
			},
		},
	}

	ipv4ZeroAddrCluster := cmtypes.MustParseAddrCluster("0.0.0.0")
	ipv4InternalAddrCluster := cmtypes.MustAddrClusterFromIP(fakeTypes.IPv4InternalAddress)
	ipv4NodePortAddrCluster := cmtypes.MustAddrClusterFromIP(fakeTypes.IPv4NodePortAddress)

	lbID := loadbalancer.ID(0)
	tcpProto := loadbalancer.L4Type(slim_corev1.ProtocolTCP)
	zeroFE := loadbalancer.NewL3n4AddrID(tcpProto, ipv4ZeroAddrCluster, 31111,
		loadbalancer.ScopeExternal, lbID)
	internalFE := loadbalancer.NewL3n4AddrID(tcpProto, ipv4InternalAddrCluster, 31111,
		loadbalancer.ScopeExternal, lbID)
	nodePortFE := loadbalancer.NewL3n4AddrID(tcpProto, ipv4NodePortAddrCluster, 31111,
		loadbalancer.ScopeExternal, lbID)

	addrs := []netip.Addr{
		ipv4InternalAddrCluster.Addr(),
		ipv4NodePortAddrCluster.Addr(),
	}

	lbcfg.AlgorithmAnnotation = true
	lbcfg.LBAlgorithm = loadbalancer.LBAlgorithmMaglev

	id, svc = ParseService(hivetest.Logger(t), lbcfg, k8sSvc, addrs)
	require.Equal(t, ServiceID{Namespace: "bar", Name: "foo"}, id)
	require.Equal(t, &Service{
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
		LoadBalancerIPs:          map[string]net.IP{loadbalancerIngressIP: net.ParseIP(loadbalancerIngressIP)},
		Type:                     loadbalancer.SVCTypeLoadBalancer,
		TopologyAware:            true,
		SourceRangesPolicy:       loadbalancer.SVCSourceRangesPolicyAllow,
		ProxyDelegation:          loadbalancer.SVCProxyDelegationNone,
		ForwardingMode:           loadbalancer.SVCForwardingModeSNAT,
		Annotations:              map[string]string{"service.kubernetes.io/topology-aware-hints": "auto"},
		LoadBalancerAlgorithm:    loadbalancer.SVCLoadBalancingAlgorithmMaglev,
	}, svc)

	objMeta.Annotations[annotation.ServiceLoadBalancingAlgorithm] = loadbalancer.LBAlgorithmRandom

	ipMode := slim_corev1.LoadBalancerIPModeProxy
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
		Status: slim_corev1.ServiceStatus{
			LoadBalancer: slim_corev1.LoadBalancerStatus{
				Ingress: []slim_corev1.LoadBalancerIngress{
					{
						IP:     loadbalancerIngressIP,
						IPMode: &ipMode,
					},
				},
			},
		},
	}
	id, svc = ParseService(hivetest.Logger(t), lbcfg, k8sSvc, addrs)
	require.Equal(t, ServiceID{Namespace: "bar", Name: "foo"}, id)
	require.Equal(t, &Service{
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
		SourceRangesPolicy:       loadbalancer.SVCSourceRangesPolicyAllow,
		ProxyDelegation:          loadbalancer.SVCProxyDelegationNone,
		Type:                     loadbalancer.SVCTypeLoadBalancer,
		ForwardingMode:           loadbalancer.SVCForwardingModeSNAT,
		TopologyAware:            true,
		Annotations: map[string]string{
			"service.kubernetes.io/topology-aware-hints": "auto",
			annotation.ServiceLoadBalancingAlgorithm:     loadbalancer.LBAlgorithmRandom,
		},
		LoadBalancerAlgorithm: loadbalancer.SVCLoadBalancingAlgorithmRandom,
	}, svc)

	// Same as the previous test, but LB service status is empty.
	// This is to simulate the delay while waiting for cloud provider to assign IP.
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
	id, svc = ParseService(hivetest.Logger(t), lbcfg, k8sSvc, addrs)
	require.Equal(t, ServiceID{Namespace: "bar", Name: "foo"}, id)
	require.Equal(t, &Service{
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
		SourceRangesPolicy:       loadbalancer.SVCSourceRangesPolicyAllow,
		ProxyDelegation:          loadbalancer.SVCProxyDelegationNone,
		Type:                     loadbalancer.SVCTypeLoadBalancer,
		ForwardingMode:           loadbalancer.SVCForwardingModeSNAT,
		TopologyAware:            true,
		Annotations: map[string]string{
			"service.kubernetes.io/topology-aware-hints": "auto",
			annotation.ServiceLoadBalancingAlgorithm:     loadbalancer.LBAlgorithmRandom,
		},
		LoadBalancerAlgorithm: loadbalancer.SVCLoadBalancingAlgorithmRandom,
	}, svc)
}

func TestIsK8ServiceExternal(t *testing.T) {
	si := Service{}

	require.True(t, si.IsExternal())

	si.Selector = map[string]string{"l": "v"}
	require.False(t, si.IsExternal())
}

func TestServiceUniquePorts(t *testing.T) {
	type testMatrix struct {
		input    Service
		expected map[string]bool
	}

	matrix := []testMatrix{
		{
			input:    Service{},
			expected: map[string]bool{},
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
			expected: map[string]bool{
				"1/NONE": true,
				"2/NONE": true,
			},
		},
	}

	for _, m := range matrix {
		require.Equal(t, m.expected, m.input.UniquePorts())
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

func TestServiceString(t *testing.T) {
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

	for _, tt := range tests {
		_, svc := ParseService(hivetest.Logger(t), loadbalancer.DefaultConfig, tt.service, nil)
		require.Equal(t, tt.svcString, svc.String())
	}
}

func TestNewClusterService(t *testing.T) {
	id, svc := ParseService(hivetest.Logger(t), loadbalancer.DefaultConfig, &slim_corev1.Service{
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
	}, nil)

	endpoints := ParseEndpoints(&slim_corev1.Endpoints{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
		},
		Subsets: []slim_corev1.EndpointSubset{
			{
				Addresses: []slim_corev1.EndpointAddress{{IP: "10.0.0.2", Hostname: "hostname-1"}},
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
	require.Equal(t, serviceStore.ClusterService{
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
		Hostnames: map[string]string{"10.0.0.2": "hostname-1"},
	}, clusterService)
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

func TestCheckServiceNodeExposure(t *testing.T) {
	tests := []struct {
		name           string // description of this test case
		nodeLabels     map[string]string
		svcAnnotations map[string]string
		wantExposed    bool
	}{
		{
			name:           "no annotation matches all nodes",
			nodeLabels:     map[string]string{},
			svcAnnotations: map[string]string{},
			wantExposed:    true,
		},
		{
			name:           "match via service.cilium.io/node annotation",
			nodeLabels:     map[string]string{"service.cilium.io/node": "beefy"},
			svcAnnotations: map[string]string{annotation.ServiceNodeExposure: "beefy"},
			wantExposed:    true,
		},
		{
			name:           "no match via service.cilium.io/node annotation",
			nodeLabels:     map[string]string{"service.cilium.io/node": "beefy"},
			svcAnnotations: map[string]string{annotation.ServiceNodeExposure: "slow"},
			wantExposed:    false,
		},
		{
			name:           "exact match via service.cilium.io/node-selector annotation",
			nodeLabels:     map[string]string{"service.cilium.io/node": "beefy"},
			svcAnnotations: map[string]string{annotation.ServiceNodeSelectorExposure: "service.cilium.io/node == beefy"},
			wantExposed:    true,
		},
		{
			name:           "no match via exact service.cilium.io/node-selector annotation",
			nodeLabels:     map[string]string{"service.cilium.io/node": "beefy"},
			svcAnnotations: map[string]string{annotation.ServiceNodeSelectorExposure: "service.cilium.io/node == slow"},
			wantExposed:    false,
		},
		{
			name:           "in match via service.cilium.io/node-selector annotation",
			nodeLabels:     map[string]string{"service.cilium.io/node": "beefy"},
			svcAnnotations: map[string]string{annotation.ServiceNodeSelectorExposure: "service.cilium.io/node in ( beefy , slow )"},
			wantExposed:    true,
		},
		{
			name:           "in match via service.cilium.io/node-selector annotation 2",
			nodeLabels:     map[string]string{"service.cilium.io/node": "slow"},
			svcAnnotations: map[string]string{annotation.ServiceNodeSelectorExposure: "service.cilium.io/node in ( beefy , slow )"},
			wantExposed:    true,
		},
		{
			name:           "no match via in service.cilium.io/node-selector annotation",
			nodeLabels:     map[string]string{"service.cilium.io/node": "another"},
			svcAnnotations: map[string]string{annotation.ServiceNodeSelectorExposure: "service.cilium.io/node in ( beefy , slow )"},
			wantExposed:    false,
		},
		{
			name:       "no match via via node annotation if node-selector exists and doesn't match",
			nodeLabels: map[string]string{"service.cilium.io/node": "another"},
			svcAnnotations: map[string]string{
				annotation.ServiceNodeSelectorExposure: "service.cilium.io/node in ( beefy , slow )",
				annotation.ServiceNodeExposure:         "another",
			},
			wantExposed: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exposedOnLocalNode, err := CheckServiceNodeExposure(
				node.NewTestLocalNodeStore(node.LocalNode{Node: types.Node{Labels: tt.nodeLabels}}),
				tt.svcAnnotations,
			)
			assert.NoError(t, err)
			assert.Equal(t, tt.wantExposed, exposedOnLocalNode)
		})
	}
}
