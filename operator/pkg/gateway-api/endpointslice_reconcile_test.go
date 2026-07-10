// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"log/slog"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	gwModel "github.com/cilium/cilium/operator/pkg/model/translation/gateway-api"
)

const (
	testNS          = "default"
	testBackendName = "backend-svc"
	testFrontendEPS = "frontend-eps"
)

// frontend builds a managed frontend EndpointSlice pointing at the given
// backend Service / port, with a single Port entry to be filled by the
// reconciler.
func frontend(portName string, proto corev1.Protocol, backendPort string) *discoveryv1.EndpointSlice {
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testFrontendEPS,
			Namespace: testNS,
			Labels: map[string]string{
				gwModel.EndpointSliceManagedByLabel: gwModel.EndpointSliceManagedByValue,
			},
			Annotations: map[string]string{
				gwModel.BackendServiceAnnotation: testNS + "/" + testBackendName,
				gwModel.BackendPortAnnotation:    backendPort,
			},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Ports: []discoveryv1.EndpointPort{
			{
				Name:     ptr.To(portName),
				Protocol: ptr.To(proto),
				Port:     ptr.To(int32(0)),
			},
		},
	}
}

func backendService(port int32, name string, proto corev1.Protocol, target intstr.IntOrString) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: testBackendName, Namespace: testNS},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Name:       name,
					Protocol:   proto,
					Port:       port,
					TargetPort: target,
				},
			},
		},
	}
}

// backendEPS builds an upstream (non-managed) backend EndpointSlice.
func backendEPS(name string, portName string, proto corev1.Protocol, port int32, addrs ...string) *discoveryv1.EndpointSlice {
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNS,
			Labels: map[string]string{
				gwModel.EndpointSliceServiceNameLabel: testBackendName,
			},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Ports: []discoveryv1.EndpointPort{
			{
				Name:     ptr.To(portName),
				Protocol: ptr.To(proto),
				Port:     ptr.To(port),
			},
		},
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: addrs},
		},
	}
}

func Test_endpointSliceReconciler_Reconcile(t *testing.T) {
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

	tests := []struct {
		name          string
		objects       []client.Object
		wantErr       bool
		wantPort      *int32
		wantNumPorts  int // expected number of frontend ports; 0 defaults to 1
		wantAddresses [][]string
	}{
		{
			name: "resolves port by name and populates endpoints",
			objects: []client.Object{
				frontend("http", corev1.ProtocolTCP, "80"),
				backendService(80, "http", corev1.ProtocolTCP, intstr.FromInt(8080)),
				backendEPS("backend-eps", "http", corev1.ProtocolTCP, 8080, "10.0.0.1"),
			},
			wantPort:      ptr.To(int32(8080)),
			wantAddresses: [][]string{{"10.0.0.1"}},
		},
		{
			name: "resolves port by numeric targetPort when name absent",
			objects: []client.Object{
				frontend("", corev1.ProtocolTCP, "80"),
				backendService(80, "", corev1.ProtocolTCP, intstr.FromInt(8080)),
				backendEPS("backend-eps", "", corev1.ProtocolTCP, 8080, "10.0.0.2"),
			},
			wantPort:      ptr.To(int32(8080)),
			wantAddresses: [][]string{{"10.0.0.2"}},
		},
		{
			name: "dedups and sorts addresses across backend slices",
			objects: []client.Object{
				frontend("http", corev1.ProtocolTCP, "80"),
				backendService(80, "http", corev1.ProtocolTCP, intstr.FromInt(8080)),
				backendEPS("backend-eps-b", "http", corev1.ProtocolTCP, 8080, "10.0.0.9"),
				backendEPS("backend-eps-a", "http", corev1.ProtocolTCP, 8080, "10.0.0.1"),
				backendEPS("backend-eps-dup", "http", corev1.ProtocolTCP, 8080, "10.0.0.1"),
			},
			wantPort:      ptr.To(int32(8080)),
			wantAddresses: [][]string{{"10.0.0.1"}, {"10.0.0.9"}},
		},
		{
			name: "backend Service missing clears endpoints",
			objects: []client.Object{
				frontend("http", corev1.ProtocolTCP, "80"),
			},
			wantPort:      ptr.To(int32(0)), // untouched, stays at seeded value
			wantAddresses: nil,
		},
		{
			name: "Service does not expose requested port clears endpoints",
			objects: []client.Object{
				frontend("http", corev1.ProtocolTCP, "80"),
				backendService(443, "https", corev1.ProtocolTCP, intstr.FromInt(8443)),
				backendEPS("backend-eps", "https", corev1.ProtocolTCP, 8443, "10.0.0.1"),
			},
			wantPort:      ptr.To(int32(0)),
			wantAddresses: nil,
		},
		{
			name: "no backend EndpointSlice keeps endpoints empty",
			objects: []client.Object{
				frontend("http", corev1.ProtocolTCP, "80"),
				backendService(80, "http", corev1.ProtocolTCP, intstr.FromInt(8080)),
				// Service exists and exposes the port, but no backend slice yet.
			},
			wantPort:      ptr.To(int32(0)),
			wantAddresses: nil,
		},
		{
			name: "invalid backend-port annotation errors",
			objects: []client.Object{
				frontend("http", corev1.ProtocolTCP, "not-a-number"),
				backendService(80, "http", corev1.ProtocolTCP, intstr.FromInt(8080)),
			},
			wantErr: true,
		},
		{
			name: "ignores managed frontend slices when resolving backends",
			objects: []client.Object{
				frontend("http", corev1.ProtocolTCP, "80"),
				backendService(80, "http", corev1.ProtocolTCP, intstr.FromInt(8080)),
				backendEPS("backend-eps", "http", corev1.ProtocolTCP, 8080, "10.0.0.1"),
				// a managed frontend slice that also carries the service-name
				// label must be skipped as a backend source.
				func() client.Object {
					f := frontend("http", corev1.ProtocolTCP, "80")
					f.Name = "other-frontend"
					f.Labels[gwModel.EndpointSliceServiceNameLabel] = testBackendName
					f.Endpoints = []discoveryv1.Endpoint{{Addresses: []string{"192.168.0.1"}}}
					f.Ports[0].Port = ptr.To(int32(9999))
					return f
				}(),
			},
			wantPort:      ptr.To(int32(8080)),
			wantAddresses: [][]string{{"10.0.0.1"}},
		},
		{
			name: "resolves UDP port end-to-end",
			objects: []client.Object{
				frontend("dns", corev1.ProtocolUDP, "53"),
				backendService(53, "dns", corev1.ProtocolUDP, intstr.FromInt(5353)),
				backendEPS("backend-eps", "dns", corev1.ProtocolUDP, 5353, "10.0.0.5"),
			},
			wantPort:      ptr.To(int32(5353)),
			wantAddresses: [][]string{{"10.0.0.5"}},
		},
		{
			name: "ignores backend slices of a different address family",
			objects: []client.Object{
				frontend("http", corev1.ProtocolTCP, "80"),
				backendService(80, "http", corev1.ProtocolTCP, intstr.FromInt(8080)),
				// IPv6 backend slice must be skipped for an IPv4 frontend.
				func() client.Object {
					be := backendEPS("backend-eps-v6", "http", corev1.ProtocolTCP, 8080, "2001:db8::1")
					be.AddressType = discoveryv1.AddressTypeIPv6
					return be
				}(),
				backendEPS("backend-eps-v4", "http", corev1.ProtocolTCP, 8080, "10.0.0.1"),
			},
			wantPort:      ptr.To(int32(8080)),
			wantAddresses: [][]string{{"10.0.0.1"}},
		},
		{
			name: "resolves IPv6 frontend from IPv6 backend slice",
			objects: []client.Object{
				func() client.Object {
					f := frontend("http", corev1.ProtocolTCP, "80")
					f.AddressType = discoveryv1.AddressTypeIPv6
					return f
				}(),
				backendService(80, "http", corev1.ProtocolTCP, intstr.FromInt(8080)),
				func() client.Object {
					be := backendEPS("backend-eps-v6", "http", corev1.ProtocolTCP, 8080, "2001:db8::1")
					be.AddressType = discoveryv1.AddressTypeIPv6
					return be
				}(),
				// an IPv4 backend slice that must be ignored for an IPv6 frontend.
				backendEPS("backend-eps-v4", "http", corev1.ProtocolTCP, 8080, "10.0.0.1"),
			},
			wantPort:      ptr.To(int32(8080)),
			wantAddresses: [][]string{{"2001:db8::1"}},
		},
		{
			// A managed frontend carrying several EndpointPort entries (all
			// sharing one backend Service port) must have the resolved target
			// port applied uniformly across every entry.
			name: "applies resolved port to every frontend port entry",
			objects: []client.Object{
				func() client.Object {
					f := frontend("http", corev1.ProtocolTCP, "80")
					f.Ports = append(f.Ports, discoveryv1.EndpointPort{
						Name:     ptr.To("http-2"),
						Protocol: ptr.To(corev1.ProtocolTCP),
						Port:     ptr.To(int32(0)),
					})
					return f
				}(),
				backendService(80, "http", corev1.ProtocolTCP, intstr.FromInt(8080)),
				backendEPS("backend-eps", "http", corev1.ProtocolTCP, 8080, "10.0.0.1"),
			},
			wantPort:      ptr.To(int32(8080)),
			wantNumPorts:  2,
			wantAddresses: [][]string{{"10.0.0.1"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := fake.NewClientBuilder().
				WithScheme(helpers.TestScheme(helpers.AllOptionalKinds)).
				WithObjects(tt.objects...).
				Build()

			r := &endpointSliceReconciler{
				Client: c,
				logger: logger,
			}

			result, err := r.Reconcile(t.Context(), ctrl.Request{
				NamespacedName: types.NamespacedName{Namespace: testNS, Name: testFrontendEPS},
			})
			require.Equal(t, tt.wantErr, err != nil, "error mismatch, error was %v", err)
			if tt.wantErr {
				return
			}
			require.Equal(t, ctrl.Result{}, result)

			got := &discoveryv1.EndpointSlice{}
			require.NoError(t, c.Get(t.Context(), types.NamespacedName{Namespace: testNS, Name: testFrontendEPS}, got))

			wantNumPorts := tt.wantNumPorts
			if wantNumPorts == 0 {
				wantNumPorts = 1
			}
			require.Len(t, got.Ports, wantNumPorts)
			// The resolved target port is applied uniformly across every
			// frontend port entry, so all entries must match wantPort.
			for i := range got.Ports {
				require.Equal(t, tt.wantPort, got.Ports[i].Port, "resolved port mismatch at index %d", i)
			}

			var gotAddrs [][]string
			for _, ep := range got.Endpoints {
				gotAddrs = append(gotAddrs, ep.Addresses)
			}
			require.Equal(t, tt.wantAddresses, gotAddrs, "endpoint addresses mismatch")
		})
	}
}

func Test_matchServicePort(t *testing.T) {
	ports := []corev1.ServicePort{
		{Name: "http", Protocol: corev1.ProtocolTCP, Port: 80},
		{Name: "dns", Protocol: corev1.ProtocolUDP, Port: 53},
		{Name: "noproto", Port: 8080},
	}

	tests := []struct {
		name  string
		want  uint16
		proto corev1.Protocol
		found bool
	}{
		{name: "matches port and proto", want: 80, proto: corev1.ProtocolTCP, found: true},
		{name: "matches udp", want: 53, proto: corev1.ProtocolUDP, found: true},
		{name: "proto mismatch", want: 80, proto: corev1.ProtocolUDP, found: false},
		{name: "empty service proto matches any", want: 8080, proto: corev1.ProtocolTCP, found: true},
		{name: "no such port", want: 9999, proto: corev1.ProtocolTCP, found: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchServicePort(ports, tt.want, tt.proto)
			if tt.found {
				require.NotNil(t, got)
				require.Equal(t, int32(tt.want), got.Port)
			} else {
				require.Nil(t, got)
			}
		})
	}
}

func Test_matchEndpointSlicePort(t *testing.T) {
	tcp := corev1.ProtocolTCP
	tests := []struct {
		name    string
		ports   []discoveryv1.EndpointPort
		svcPort corev1.ServicePort
		want    *int32
	}{
		{
			name: "name match preferred",
			ports: []discoveryv1.EndpointPort{
				{Name: ptr.To("http"), Protocol: &tcp, Port: ptr.To(int32(8080))},
				{Name: ptr.To("other"), Protocol: &tcp, Port: ptr.To(int32(9090))},
			},
			svcPort: corev1.ServicePort{Name: "http", Protocol: tcp, TargetPort: intstr.FromInt(1)},
			want:    ptr.To(int32(8080)),
		},
		{
			name: "numeric targetPort fallback",
			ports: []discoveryv1.EndpointPort{
				{Name: ptr.To(""), Protocol: &tcp, Port: ptr.To(int32(8080))},
			},
			svcPort: corev1.ServicePort{Protocol: tcp, TargetPort: intstr.FromInt(8080)},
			want:    ptr.To(int32(8080)),
		},
		{
			name: "single port no match uses first",
			ports: []discoveryv1.EndpointPort{
				{Name: ptr.To("mismatch"), Protocol: &tcp, Port: ptr.To(int32(7070))},
			},
			svcPort: corev1.ServicePort{Name: "http", Protocol: tcp, TargetPort: intstr.FromString("named")},
			want:    ptr.To(int32(7070)),
		},
		{
			name: "no match returns nil",
			ports: []discoveryv1.EndpointPort{
				{Name: ptr.To("a"), Protocol: &tcp, Port: ptr.To(int32(1))},
				{Name: ptr.To("b"), Protocol: &tcp, Port: ptr.To(int32(2))},
			},
			svcPort: corev1.ServicePort{Name: "http", Protocol: tcp, TargetPort: intstr.FromString("named")},
			want:    nil,
		},
		{
			// proto mismatch skips the port; with >1 port the single-port
			// fallback does not kick in, so the result is nil.
			name: "proto mismatch skips port",
			ports: []discoveryv1.EndpointPort{
				{Name: ptr.To("http"), Protocol: ptr.To(corev1.ProtocolUDP), Port: ptr.To(int32(8080))},
				{Name: ptr.To("extra"), Protocol: ptr.To(corev1.ProtocolUDP), Port: ptr.To(int32(9090))},
			},
			svcPort: corev1.ServicePort{Name: "http", Protocol: tcp, TargetPort: intstr.FromInt(8080)},
			want:    nil,
		},
		{
			// single-port fallback returns the only port even on proto mismatch.
			name: "single port fallback ignores proto",
			ports: []discoveryv1.EndpointPort{
				{Name: ptr.To("http"), Protocol: ptr.To(corev1.ProtocolUDP), Port: ptr.To(int32(8080))},
			},
			svcPort: corev1.ServicePort{Name: "nomatch", Protocol: tcp, TargetPort: intstr.FromString("named")},
			want:    ptr.To(int32(8080)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchEndpointSlicePort(tt.ports, tt.svcPort)
			require.Equal(t, tt.want, got)
		})
	}
}

func Test_portProtocol(t *testing.T) {
	require.Equal(t, corev1.ProtocolTCP, portProtocol(nil))
	require.Equal(t, corev1.ProtocolTCP, portProtocol([]discoveryv1.EndpointPort{{}}))
	require.Equal(t, corev1.ProtocolUDP, portProtocol([]discoveryv1.EndpointPort{
		{Protocol: ptr.To(corev1.ProtocolUDP)},
	}))
}
