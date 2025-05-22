// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package legacy

import (
	"testing"

	_ "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/k8s"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/util/intstr"
	"github.com/cilium/cilium/pkg/loadbalancer"
)

func Test_convertToLBService(t *testing.T) {
	type args struct {
		svc *slim_corev1.Service
		ep  *k8s.Endpoints
	}
	tests := []struct {
		name string
		args args
		want []*loadbalancer.LegacySVC
	}{
		{
			name: "headless with one port and one address",
			args: args{
				svc: &slim_corev1.Service{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name:      "headless-service",
						Namespace: "default",
					},
					Spec: slim_corev1.ServiceSpec{
						ClusterIP: "None",
						Ports: []slim_corev1.ServicePort{
							{
								Name:       "http",
								Protocol:   "TCP",
								Port:       8080,
								TargetPort: intstr.FromInt32(3000),
							},
						},
					},
				},
				ep: &k8s.Endpoints{
					Backends: map[cmtypes.AddrCluster]*k8s.Backend{
						cmtypes.MustParseAddrCluster("10.0.0.1"): {
							Ports: map[string]*loadbalancer.L4Addr{
								"http": {
									Protocol: "TCP",
									Port:     3000,
								},
							},
						},
					},
				},
			},
			want: []*loadbalancer.LegacySVC{
				{
					Name: loadbalancer.ServiceName{
						Name:      "headless-service",
						Namespace: "default",
					},
					Frontend: loadbalancer.L3n4AddrID{
						L3n4Addr: loadbalancer.L3n4Addr{
							L4Addr: loadbalancer.L4Addr{
								Protocol: "TCP",
								Port:     8080,
							},
						},
					},
					Backends: []*loadbalancer.LegacyBackend{
						{
							FEPortName: "http",
							L3n4Addr: loadbalancer.L3n4Addr{
								AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.1"),
								L4Addr: loadbalancer.L4Addr{
									Protocol: "TCP",
									Port:     3000,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "headless with one port and two addresses",
			args: args{
				svc: &slim_corev1.Service{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name:      "headless-service",
						Namespace: "default",
					},
					Spec: slim_corev1.ServiceSpec{
						ClusterIP: "None",
						Ports: []slim_corev1.ServicePort{
							{
								Name:     "http",
								Protocol: "TCP",
								Port:     8080,
							},
						},
					},
				},
				ep: &k8s.Endpoints{
					Backends: map[cmtypes.AddrCluster]*k8s.Backend{
						cmtypes.MustParseAddrCluster("10.0.0.1"): {
							Ports: map[string]*loadbalancer.L4Addr{
								"http": {
									Protocol: "TCP",
									Port:     8080,
								},
							},
						},
						cmtypes.MustParseAddrCluster("10.0.0.2"): {
							Ports: map[string]*loadbalancer.L4Addr{
								"http": {
									Protocol: "TCP",
									Port:     8080,
								},
							},
						},
					},
				},
			},
			want: []*loadbalancer.LegacySVC{
				{
					Name: loadbalancer.ServiceName{
						Name:      "headless-service",
						Namespace: "default",
					},
					Frontend: loadbalancer.L3n4AddrID{
						L3n4Addr: loadbalancer.L3n4Addr{
							L4Addr: loadbalancer.L4Addr{
								Protocol: "TCP",
								Port:     8080,
							},
						},
					},
					Backends: []*loadbalancer.LegacyBackend{
						{
							FEPortName: "http",
							L3n4Addr: loadbalancer.L3n4Addr{
								AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.1"),
								L4Addr: loadbalancer.L4Addr{
									Protocol: "TCP",
									Port:     8080,
								},
							},
						},
						{
							FEPortName: "http",
							L3n4Addr: loadbalancer.L3n4Addr{
								AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
								L4Addr: loadbalancer.L4Addr{
									Protocol: "TCP",
									Port:     8080,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "headless with two ports and one address",
			args: args{
				svc: &slim_corev1.Service{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name:      "headless-service",
						Namespace: "default",
					},
					Spec: slim_corev1.ServiceSpec{
						ClusterIP: "None",
						Ports: []slim_corev1.ServicePort{
							{
								Name:     "http",
								Protocol: "TCP",
								Port:     8080,
							},
							{
								Name:     "https",
								Protocol: "TCP",
								Port:     8443,
							},
						},
					},
				},
				ep: &k8s.Endpoints{
					Backends: map[cmtypes.AddrCluster]*k8s.Backend{
						cmtypes.MustParseAddrCluster("10.0.0.1"): {
							Ports: map[string]*loadbalancer.L4Addr{
								"http": {
									Protocol: "TCP",
									Port:     8080,
								},
								"https": {
									Protocol: "TCP",
									Port:     8443,
								},
							},
						},
					},
				},
			},
			want: []*loadbalancer.LegacySVC{
				{
					Name: loadbalancer.ServiceName{
						Name:      "headless-service",
						Namespace: "default",
					},
					Frontend: loadbalancer.L3n4AddrID{
						L3n4Addr: loadbalancer.L3n4Addr{
							L4Addr: loadbalancer.L4Addr{
								Protocol: "TCP",
								Port:     8080,
							},
						},
					},
					Backends: []*loadbalancer.LegacyBackend{
						{
							FEPortName: "http",
							L3n4Addr: loadbalancer.L3n4Addr{
								AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.1"),
								L4Addr: loadbalancer.L4Addr{
									Protocol: "TCP",
									Port:     8080,
								},
							},
						},
					},
				},
				{
					Name: loadbalancer.ServiceName{
						Name:      "headless-service",
						Namespace: "default",
					},
					Frontend: loadbalancer.L3n4AddrID{
						L3n4Addr: loadbalancer.L3n4Addr{
							L4Addr: loadbalancer.L4Addr{
								Protocol: "TCP",
								Port:     8443,
							},
						},
					},
					Backends: []*loadbalancer.LegacyBackend{
						{
							FEPortName: "https",
							L3n4Addr: loadbalancer.L3n4Addr{
								AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.1"),
								L4Addr: loadbalancer.L4Addr{
									Protocol: "TCP",
									Port:     8443,
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svcs := convertToLBService(tt.args.svc, tt.args.ep)
			require.Len(t, svcs, len(tt.want))
			for i := range svcs {
				require.Equal(t, tt.want[i].Name, svcs[i].Name)
				require.Equal(t, tt.want[i].Frontend, svcs[i].Frontend)
				require.Len(t, svcs[i].Backends, len(tt.want[i].Backends))
				require.ElementsMatch(t, tt.want[i].Backends, svcs[i].Backends)
			}
		})
	}
}
