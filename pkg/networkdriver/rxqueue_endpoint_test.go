// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"net/netip"
	"testing"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	datapathTables "github.com/cilium/cilium/pkg/datapath/tables"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/loadbalancer"

	"github.com/cilium/cilium/pkg/networkdriver/types"
)

func TestValidateRXQueueConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  *types.RXQueueConfig
		wantErr string
	}{
		{
			name:    "missing endpoint",
			config:  &types.RXQueueConfig{},
			wantErr: "exactly one of podEndpoint or serviceEndpoint is required",
		},
		{
			name: "both endpoints",
			config: &types.RXQueueConfig{
				PodEndpoint:     &types.RXQueuePodEndpoint{Port: "9000", Protocol: corev1.ProtocolTCP},
				ServiceEndpoint: &types.RXQueueServiceEndpoint{ServiceName: "storage", Port: "rpc"},
			},
			wantErr: "mutually exclusive",
		},
		{
			name: "unsupported pod protocol",
			config: &types.RXQueueConfig{
				PodEndpoint: &types.RXQueuePodEndpoint{Port: "9000", Protocol: corev1.ProtocolSCTP},
			},
			wantErr: "protocol must be TCP or UDP",
		},
		{
			name: "invalid pod port",
			config: &types.RXQueueConfig{
				PodEndpoint: &types.RXQueuePodEndpoint{Port: "0", Protocol: corev1.ProtocolTCP},
			},
			wantErr: "between 1 and 65535",
		},
		{
			name: "missing service name",
			config: &types.RXQueueConfig{
				ServiceEndpoint: &types.RXQueueServiceEndpoint{Port: "rpc"},
			},
			wantErr: "serviceName is required",
		},
		{
			name: "valid pod endpoint",
			config: &types.RXQueueConfig{
				PodEndpoint: &types.RXQueuePodEndpoint{Port: "rpc", Protocol: corev1.ProtocolTCP},
			},
		},
		{
			name: "valid service endpoint",
			config: &types.RXQueueConfig{
				ServiceEndpoint: &types.RXQueueServiceEndpoint{ServiceName: "storage", Port: "9000"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRXQueueConfig(tt.config)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
			require.ErrorIs(t, err, errUnexpectedInput)
		})
	}
}

type rxQueueServiceFixture struct {
	db            *statedb.DB
	services      statedb.RWTable[*loadbalancer.Service]
	frontends     statedb.RWTable[*loadbalancer.Frontend]
	nodeAddresses statedb.RWTable[datapathTables.NodeAddress]
	resolver      rxQueueFlowResolver
}

func newRXQueueServiceFixture(t *testing.T) rxQueueServiceFixture {
	db := statedb.New()
	services, err := loadbalancer.NewServicesTable(loadbalancer.DefaultConfig, db)
	require.NoError(t, err)
	frontends, err := loadbalancer.NewFrontendsTable(loadbalancer.DefaultConfig, db)
	require.NoError(t, err)
	nodeAddresses, err := datapathTables.NewNodeAddressTable(db)
	require.NoError(t, err)
	return rxQueueServiceFixture{
		db: db, services: services, frontends: frontends, nodeAddresses: nodeAddresses,
		resolver: rxQueueFlowResolver{
			services: services, frontends: frontends, nodeAddresses: nodeAddresses,
			kubeProxyReplacement: true,
		},
	}
}

func (f rxQueueServiceFixture) upsert(service *loadbalancer.Service, frontends ...*loadbalancer.Frontend) {
	wtxn := f.db.WriteTxn(f.services, f.frontends)
	f.services.Insert(wtxn, service)
	for _, frontend := range frontends {
		frontend.ServiceName = service.Name
		frontend.Service = service
		f.frontends.Insert(wtxn, frontend)
	}
	wtxn.Commit()
}

func (f rxQueueServiceFixture) resolve(pod *slim_corev1.Pod, config *types.RXQueueConfig) ([]types.RXQueueFlow, error) {
	return f.resolver.resolve(f.db.ReadTxn(), statedb.NewWatchSet(), pod, config)
}

func rxQueueTestPod() *slim_corev1.Pod {
	return &slim_corev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{Namespace: "default", Name: "storage-0"},
		Spec: slim_corev1.PodSpec{
			Containers: []slim_corev1.Container{{
				Ports: []slim_corev1.ContainerPort{
					{Name: "rpc", ContainerPort: 8080},
					{Name: "dns", ContainerPort: 5353, Protocol: slim_corev1.ProtocolUDP},
				},
			}},
		},
		Status: slim_corev1.PodStatus{
			PodIPs: []slim_corev1.PodIP{{IP: "2001:db8::10"}, {IP: "192.0.2.10"}, {IP: "192.0.2.10"}},
		},
	}
}

func rxQueueTestBackend(protocol, addr string, port uint16, portNames ...string) *loadbalancer.Backend {
	return &loadbalancer.Backend{
		Address: loadbalancer.NewL3n4Addr(protocol, cmtypes.MustParseAddrCluster(addr),
			port, loadbalancer.ScopeExternal),
		PortNames: portNames,
	}
}

func rxQueueTestFrontend(kind loadbalancer.SVCType, addr string, port uint16, backends ...*loadbalancer.Backend) *loadbalancer.Frontend {
	return &loadbalancer.Frontend{
		FrontendParams: loadbalancer.FrontendParams{
			Type: kind, PortName: "rpc", ServicePort: 9000,
			Address: loadbalancer.NewL3n4Addr(loadbalancer.TCP, cmtypes.MustParseAddrCluster(addr), port, loadbalancer.ScopeExternal),
		},
		Status: reconciler.StatusDone(), ID: 1,
		Backends: func(yield func(*loadbalancer.Backend, statedb.Revision) bool) {
			for _, backend := range backends {
				if !yield(backend, 0) {
					return
				}
			}
		},
	}
}

func TestResolveRXQueuePodEndpoint(t *testing.T) {
	f := newRXQueueServiceFixture(t)
	pod := rxQueueTestPod()

	flows, err := f.resolve(pod, &types.RXQueueConfig{
		PodEndpoint: &types.RXQueuePodEndpoint{Port: "9000", Protocol: corev1.ProtocolTCP},
	})
	require.NoError(t, err)
	require.Equal(t, []types.RXQueueFlow{
		{DestinationIP: netip.MustParseAddr("192.0.2.10"), DestinationPort: 9000, Protocol: corev1.ProtocolTCP},
		{DestinationIP: netip.MustParseAddr("2001:db8::10"), DestinationPort: 9000, Protocol: corev1.ProtocolTCP},
	}, flows)

	flows, err = f.resolve(pod, &types.RXQueueConfig{
		PodEndpoint: &types.RXQueuePodEndpoint{Port: "dns", Protocol: corev1.ProtocolUDP},
	})
	require.NoError(t, err)
	require.Equal(t, uint16(5353), flows[0].DestinationPort)

	_, err = f.resolve(pod, &types.RXQueueConfig{
		PodEndpoint: &types.RXQueuePodEndpoint{Port: "dns", Protocol: corev1.ProtocolTCP},
	})
	require.ErrorContains(t, err, "no TCP port named")

	pod.Status.PodIPs = nil
	_, err = f.resolve(pod, &types.RXQueueConfig{
		PodEndpoint: &types.RXQueuePodEndpoint{Port: "9000", Protocol: corev1.ProtocolTCP},
	})
	require.ErrorContains(t, err, "has no IP addresses")
}

func TestResolveRXQueueServiceEndpoint(t *testing.T) {
	f := newRXQueueServiceFixture(t)
	pod := rxQueueTestPod()
	service := &loadbalancer.Service{
		Name:      loadbalancer.NewServiceName("default", "storage"),
		PortNames: map[string]uint16{"rpc": 9000}, ExtTrafficPolicy: loadbalancer.SVCTrafficPolicyLocal,
	}
	be4 := rxQueueTestBackend(loadbalancer.TCP, "192.0.2.10", 8080, "rpc")
	be6 := rxQueueTestBackend(loadbalancer.TCP, "2001:db8::10", 8080, "rpc")
	internal := rxQueueTestFrontend(loadbalancer.SVCTypeLoadBalancer, "192.0.2.100", 9000)
	internal.Address = loadbalancer.NewL3n4Addr(loadbalancer.TCP, cmtypes.MustParseAddrCluster("192.0.2.100"), 9000, loadbalancer.ScopeInternal)
	f.upsert(service,
		rxQueueTestFrontend(loadbalancer.SVCTypeClusterIP, "10.96.0.10", 9000, be4),
		rxQueueTestFrontend(loadbalancer.SVCTypeClusterIP, "fd00:96::10", 9000, be6),
		rxQueueTestFrontend(loadbalancer.SVCTypeLoadBalancer, "192.0.2.100", 9000, be4),
		rxQueueTestFrontend(loadbalancer.SVCTypeLoadBalancer, "2001:db8::100", 9000, be6),
		rxQueueTestFrontend(loadbalancer.SVCTypeExternalIPs, "192.0.2.101", 9000, be4),
		rxQueueTestFrontend(loadbalancer.SVCTypeExternalIPs, "2001:db8::101", 9000, be6),
		rxQueueTestFrontend(loadbalancer.SVCTypeNodePort, "0.0.0.0", 30900, be4),
		rxQueueTestFrontend(loadbalancer.SVCTypeNodePort, "::", 30900, be6), internal,
	)
	wtxn := f.db.WriteTxn(f.nodeAddresses)
	for _, addr := range []datapathTables.NodeAddress{
		{Addr: netip.MustParseAddr("192.0.2.1"), DeviceName: "eth0", NodePort: true},
		{Addr: netip.MustParseAddr("192.0.2.1"), DeviceName: "eth1", NodePort: true},
		{Addr: netip.MustParseAddr("2001:db8::1"), NodePort: true},
		{Addr: netip.MustParseAddr("192.0.2.2"), NodePort: false},
	} {
		f.nodeAddresses.Insert(wtxn, addr)
	}
	wtxn.Commit()

	for _, externalClusterIP := range []bool{false, true} {
		f.resolver.externalClusterIP = externalClusterIP
		want := []types.RXQueueFlow{
			{DestinationIP: netip.MustParseAddr("192.0.2.1"), DestinationPort: 30900, Protocol: corev1.ProtocolTCP},
			{DestinationIP: netip.MustParseAddr("192.0.2.100"), DestinationPort: 9000, Protocol: corev1.ProtocolTCP},
			{DestinationIP: netip.MustParseAddr("192.0.2.101"), DestinationPort: 9000, Protocol: corev1.ProtocolTCP},
			{DestinationIP: netip.MustParseAddr("2001:db8::1"), DestinationPort: 30900, Protocol: corev1.ProtocolTCP},
			{DestinationIP: netip.MustParseAddr("2001:db8::100"), DestinationPort: 9000, Protocol: corev1.ProtocolTCP},
			{DestinationIP: netip.MustParseAddr("2001:db8::101"), DestinationPort: 9000, Protocol: corev1.ProtocolTCP},
		}
		if externalClusterIP {
			want = append([]types.RXQueueFlow{{DestinationIP: netip.MustParseAddr("10.96.0.10"), DestinationPort: 9000, Protocol: corev1.ProtocolTCP}}, want...)
			want = append(want, types.RXQueueFlow{DestinationIP: netip.MustParseAddr("fd00:96::10"), DestinationPort: 9000, Protocol: corev1.ProtocolTCP})
		}
		for _, port := range []string{"rpc", "9000"} {
			flows, err := f.resolve(pod, &types.RXQueueConfig{
				ServiceEndpoint: &types.RXQueueServiceEndpoint{ServiceName: "storage", Port: port},
			})
			require.NoError(t, err)
			require.Equal(t, want, flows)
		}
	}
}

func TestRXQueueServiceEndpointEligibility(t *testing.T) {
	tests := []struct {
		name, wantErr string
		change        func(*loadbalancer.Service, *loadbalancer.Frontend, *rxQueueFlowResolver)
	}{
		{"kube-proxy replacement disabled", "requires kube-proxy replacement", func(_ *loadbalancer.Service, _ *loadbalancer.Frontend, r *rxQueueFlowResolver) {
			r.kubeProxyReplacement = false
		}},
		{"cluster traffic policy", "externalTrafficPolicy: Local", func(s *loadbalancer.Service, _ *loadbalancer.Frontend, _ *rxQueueFlowResolver) {
			s.ExtTrafficPolicy = loadbalancer.SVCTrafficPolicyCluster
		}},
		{"frontend pending", "is not programmed", func(_ *loadbalancer.Service, f *loadbalancer.Frontend, _ *rxQueueFlowResolver) {
			f.Status = reconciler.StatusPending()
		}},
		{"frontend not a datapath candidate", "is not programmed", func(_ *loadbalancer.Service, f *loadbalancer.Frontend, _ *rxQueueFlowResolver) { f.ID = 0 }},
		{"no backends", "has no backends", func(_ *loadbalancer.Service, f *loadbalancer.Frontend, _ *rxQueueFlowResolver) {
			f.Backends = rxQueueTestFrontend(f.Type, "192.0.2.100", 9000).Backends
		}},
		{"another local Pod", "Pod holding this RX queue claim", func(_ *loadbalancer.Service, f *loadbalancer.Frontend, _ *rxQueueFlowResolver) {
			f.Backends = rxQueueTestFrontend(f.Type, "192.0.2.100", 9000,
				rxQueueTestBackend(loadbalancer.TCP, "192.0.2.10", 8080),
				rxQueueTestBackend(loadbalancer.TCP, "192.0.2.11", 8080)).Backends
		}},
		{"another cluster", "Pod holding this RX queue claim", func(_ *loadbalancer.Service, f *loadbalancer.Frontend, _ *rxQueueFlowResolver) {
			backend := rxQueueTestBackend(loadbalancer.TCP, "192.0.2.10", 8080)
			backend.ClusterID = 1
			f.Backends = rxQueueTestFrontend(f.Type, "192.0.2.100", 9000, backend).Backends
		}},
		{"ClusterIP permits remote backends", "Pod holding this RX queue claim", func(s *loadbalancer.Service, f *loadbalancer.Frontend, r *rxQueueFlowResolver) {
			r.externalClusterIP = true
			s.IntTrafficPolicy = loadbalancer.SVCTrafficPolicyCluster
			f.Type = loadbalancer.SVCTypeClusterIP
			backend := rxQueueTestBackend(loadbalancer.TCP, "192.0.2.11", 8080)
			backend.NodeName = "another-node"
			f.Backends = rxQueueTestFrontend(f.Type, "192.0.2.100", 9000, backend).Backends
		}},
		{"local redirect", "redirects", func(s *loadbalancer.Service, f *loadbalancer.Frontend, _ *rxQueueFlowResolver) {
			f.RedirectTo = &s.Name
		}},
		{"proxy redirect", "redirects", func(s *loadbalancer.Service, _ *loadbalancer.Frontend, _ *rxQueueFlowResolver) {
			s.ProxyRedirects = loadbalancer.ProxyRedirects{{ProxyPort: 10000}}
		}},
		{"headless Service", "no externally reachable frontend", func(_ *loadbalancer.Service, f *loadbalancer.Frontend, _ *rxQueueFlowResolver) {
			f.Type = loadbalancer.SVCTypeClusterIP // ClusterIP steering is disabled in this fixture.
		}},
		{"different Service port", "no externally reachable frontend", func(_ *loadbalancer.Service, f *loadbalancer.Frontend, _ *rxQueueFlowResolver) { f.ServicePort = 9100 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newRXQueueServiceFixture(t)
			service := &loadbalancer.Service{
				Name:      loadbalancer.NewServiceName("default", "storage"),
				PortNames: map[string]uint16{"rpc": 9000}, ExtTrafficPolicy: loadbalancer.SVCTrafficPolicyLocal,
			}
			frontend := rxQueueTestFrontend(loadbalancer.SVCTypeLoadBalancer, "192.0.2.100", 9000,
				rxQueueTestBackend(loadbalancer.TCP, "192.0.2.10", 8080))
			tt.change(service, frontend, &f.resolver)
			f.upsert(service, frontend)
			flows, err := f.resolve(rxQueueTestPod(), &types.RXQueueConfig{
				ServiceEndpoint: &types.RXQueueServiceEndpoint{ServiceName: "storage", Port: "rpc"},
			})
			require.ErrorContains(t, err, tt.wantErr)
			require.Empty(t, flows)
		})
	}
}

func TestRXQueueServiceEndpointUnnamedUDPPort(t *testing.T) {
	f := newRXQueueServiceFixture(t)
	frontend := rxQueueTestFrontend(loadbalancer.SVCTypeLoadBalancer, "192.0.2.100", 9000,
		rxQueueTestBackend(loadbalancer.UDP, "192.0.2.10", 9001))
	frontend.PortName = ""
	frontend.Address = loadbalancer.NewL3n4Addr(loadbalancer.UDP, cmtypes.MustParseAddrCluster("192.0.2.100"), 9000, loadbalancer.ScopeExternal)
	f.upsert(&loadbalancer.Service{
		Name:      loadbalancer.NewServiceName("default", "storage"),
		PortNames: map[string]uint16{"": 9000}, ExtTrafficPolicy: loadbalancer.SVCTrafficPolicyLocal,
	}, frontend)
	flows, err := f.resolve(rxQueueTestPod(), &types.RXQueueConfig{
		ServiceEndpoint: &types.RXQueueServiceEndpoint{ServiceName: "storage", Port: "9000"},
	})
	require.NoError(t, err)
	require.Equal(t, []types.RXQueueFlow{{
		DestinationIP: netip.MustParseAddr("192.0.2.100"), DestinationPort: 9000, Protocol: corev1.ProtocolUDP,
	}}, flows)
}

func TestRXQueueNodePortSkipsConcreteFrontends(t *testing.T) {
	f := newRXQueueServiceFixture(t)
	f.upsert(&loadbalancer.Service{
		Name:      loadbalancer.NewServiceName("default", "storage"),
		PortNames: map[string]uint16{"rpc": 9000}, ExtTrafficPolicy: loadbalancer.SVCTrafficPolicyLocal,
	}, rxQueueTestFrontend(loadbalancer.SVCTypeNodePort, "0.0.0.0", 30900,
		rxQueueTestBackend(loadbalancer.TCP, "192.0.2.10", 8080)))
	f.upsert(&loadbalancer.Service{Name: loadbalancer.NewServiceName("default", "other")},
		rxQueueTestFrontend(loadbalancer.SVCTypeExternalIPs, "192.0.2.1", 30900))
	wtxn := f.db.WriteTxn(f.nodeAddresses)
	for _, addr := range []string{"192.0.2.1", "192.0.2.2"} {
		f.nodeAddresses.Insert(wtxn, datapathTables.NodeAddress{Addr: netip.MustParseAddr(addr), NodePort: true})
	}
	wtxn.Commit()
	flows, err := f.resolve(rxQueueTestPod(), &types.RXQueueConfig{
		ServiceEndpoint: &types.RXQueueServiceEndpoint{ServiceName: "storage", Port: "rpc"},
	})
	require.NoError(t, err)
	require.Equal(t, []types.RXQueueFlow{{
		DestinationIP: netip.MustParseAddr("192.0.2.2"), DestinationPort: 30900, Protocol: corev1.ProtocolTCP,
	}}, flows)
}

func TestRXQueueServicePortReference(t *testing.T) {
	service := &loadbalancer.Service{
		Name:      loadbalancer.NewServiceName("default", "storage"),
		PortNames: map[string]uint16{"tcp": 9000, "udp": 9000},
	}
	_, err := servicePortName(service, "9000")
	require.ErrorContains(t, err, "multiple ports numbered")
	_, err = servicePortName(service, "missing")
	require.ErrorContains(t, err, "has no port")
	name, err := servicePortName(service, "udp")
	require.NoError(t, err)
	require.Equal(t, "udp", name)
}
