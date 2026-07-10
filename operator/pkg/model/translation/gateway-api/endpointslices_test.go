// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/operator/pkg/model"
)

func testL4Source() *model.FullyQualifiedResource {
	return &model.FullyQualifiedResource{
		Name:      "my-gateway",
		Namespace: "default",
		Kind:      "Gateway",
		UID:       "uid-123",
	}
}

func testLBService(families ...corev1.IPFamily) *corev1.Service {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cilium-gateway-my-gateway",
			Namespace: "default",
		},
	}
	svc.Spec.IPFamilies = families
	return svc
}

func tcpListener(port uint32, routes ...model.L4Route) model.L4Listener {
	return model.L4Listener{
		Name:     "tcp",
		Port:     port,
		Protocol: model.L4ProtocolTCP,
		Routes:   routes,
	}
}

func udpListener(port uint32, routes ...model.L4Route) model.L4Listener {
	return model.L4Listener{
		Name:     "udp",
		Port:     port,
		Protocol: model.L4ProtocolUDP,
		Routes:   routes,
	}
}

func Test_desiredL4EndpointSlices_emptyInputs(t *testing.T) {
	trans := &gatewayAPITranslator{}

	tests := []struct {
		name      string
		listeners []model.L4Listener
		source    *model.FullyQualifiedResource
		lbSvc     *corev1.Service
	}{
		{name: "no listeners", listeners: nil, source: testL4Source(), lbSvc: testLBService()},
		{name: "nil source", listeners: []model.L4Listener{tcpListener(8080)}, source: nil, lbSvc: testLBService()},
		{name: "nil lbSvc", listeners: []model.L4Listener{tcpListener(8080)}, source: testL4Source(), lbSvc: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := trans.desiredL4EndpointSlices(tt.listeners, tt.source, tt.lbSvc)
			assert.Nil(t, got)
		})
	}
}

func Test_desiredL4EndpointSlices_singleTCP(t *testing.T) {
	trans := &gatewayAPITranslator{}

	listeners := []model.L4Listener{
		tcpListener(8080, model.L4Route{
			Name: "tcp-route",
			Backends: []model.Backend{
				{Name: "echo", Namespace: "default", Port: &model.BackendPort{Port: 9090}},
			},
		}),
	}

	got := trans.desiredL4EndpointSlices(listeners, testL4Source(), testLBService(corev1.IPv4Protocol))
	require.Len(t, got, 1)

	eps := got[0]
	assert.Equal(t, "default", eps.Namespace)
	assert.Equal(t, discoveryv1.AddressTypeIPv4, eps.AddressType)
	assert.Empty(t, eps.Endpoints)

	// Labels
	assert.Equal(t, "cilium-gateway-my-gateway", eps.Labels[EndpointSliceServiceNameLabel])
	assert.Equal(t, EndpointSliceManagedByValue, eps.Labels[EndpointSliceManagedByLabel])
	assert.NotEmpty(t, eps.Labels[gatewayNameLabel])

	// Annotations encode the backend service/port targeting.
	assert.Equal(t, "default/echo", eps.Annotations[BackendServiceAnnotation])
	assert.Equal(t, "9090", eps.Annotations[BackendPortAnnotation])

	// OwnerReference points back at the Gateway.
	require.Len(t, eps.OwnerReferences, 1)
	owner := eps.OwnerReferences[0]
	assert.Equal(t, "Gateway", owner.Kind)
	assert.Equal(t, "my-gateway", owner.Name)
	assert.True(t, ptr.Deref(owner.Controller, false))

	// One port entry; listener port exposed, protocol TCP, name matches ServicePort.
	require.Len(t, eps.Ports, 1)
	assert.Equal(t, "port-8080", ptr.Deref(eps.Ports[0].Name, ""))
	assert.Equal(t, int32(8080), ptr.Deref(eps.Ports[0].Port, 0))
	assert.Equal(t, corev1.ProtocolTCP, ptr.Deref(eps.Ports[0].Protocol, ""))
}

func Test_desiredL4EndpointSlices_dualStack(t *testing.T) {
	trans := &gatewayAPITranslator{}

	listeners := []model.L4Listener{
		tcpListener(8080, model.L4Route{
			Backends: []model.Backend{{Name: "echo", Namespace: "default", Port: &model.BackendPort{Port: 9090}}},
		}),
	}

	got := trans.desiredL4EndpointSlices(listeners, testL4Source(), testLBService(corev1.IPv4Protocol, corev1.IPv6Protocol))
	require.Len(t, got, 2)

	families := map[discoveryv1.AddressType]bool{}
	for _, eps := range got {
		families[eps.AddressType] = true
	}
	assert.True(t, families[discoveryv1.AddressTypeIPv4])
	assert.True(t, families[discoveryv1.AddressTypeIPv6])
	// Distinct names per family.
	assert.NotEqual(t, got[0].Name, got[1].Name)
}

func Test_desiredL4EndpointSlices_tcpAndUDPSamePortDistinctSlices(t *testing.T) {
	trans := &gatewayAPITranslator{}

	backend := model.Backend{Name: "echo", Namespace: "default", Port: &model.BackendPort{Port: 9090}}
	listeners := []model.L4Listener{
		tcpListener(8080, model.L4Route{Backends: []model.Backend{backend}}),
		udpListener(8080, model.L4Route{Backends: []model.Backend{backend}}),
	}

	got := trans.desiredL4EndpointSlices(listeners, testL4Source(), testLBService(corev1.IPv4Protocol))
	require.Len(t, got, 2)

	protocols := map[corev1.Protocol]bool{}
	for _, eps := range got {
		require.Len(t, eps.Ports, 1)
		protocols[ptr.Deref(eps.Ports[0].Protocol, "")] = true
	}
	assert.True(t, protocols[corev1.ProtocolTCP])
	assert.True(t, protocols[corev1.ProtocolUDP])
	assert.NotEqual(t, got[0].Name, got[1].Name, "TCP and UDP for same backend/port must not share a slice")
}

func Test_desiredL4EndpointSlices_mergeListenersSharingBackendTuple(t *testing.T) {
	trans := &gatewayAPITranslator{}

	backend := model.Backend{Name: "echo", Namespace: "default", Port: &model.BackendPort{Port: 9090}}
	// Two listeners on different ports route to the same backend Service+port.
	listeners := []model.L4Listener{
		tcpListener(8080, model.L4Route{Backends: []model.Backend{backend}}),
		tcpListener(8081, model.L4Route{Backends: []model.Backend{backend}}),
	}

	got := trans.desiredL4EndpointSlices(listeners, testL4Source(), testLBService(corev1.IPv4Protocol))
	require.Len(t, got, 1, "listeners sharing backend tuple merge into one slice")

	// One Ports entry per listener, sorted by name.
	require.Len(t, got[0].Ports, 2)
	assert.Equal(t, "port-8080", ptr.Deref(got[0].Ports[0].Name, ""))
	assert.Equal(t, "port-8081", ptr.Deref(got[0].Ports[1].Name, ""))
}

func Test_desiredL4EndpointSlices_dedupSamePortName(t *testing.T) {
	trans := &gatewayAPITranslator{}

	backend := model.Backend{Name: "echo", Namespace: "default", Port: &model.BackendPort{Port: 9090}}
	// Same listener port referenced via two routes -> single Ports entry.
	listeners := []model.L4Listener{
		tcpListener(8080,
			model.L4Route{Backends: []model.Backend{backend}},
			model.L4Route{Backends: []model.Backend{backend}},
		),
	}

	got := trans.desiredL4EndpointSlices(listeners, testL4Source(), testLBService(corev1.IPv4Protocol))
	require.Len(t, got, 1)
	require.Len(t, got[0].Ports, 1, "duplicate port name is deduped")
}

func Test_desiredL4EndpointSlices_weightAnnotation(t *testing.T) {
	trans := &gatewayAPITranslator{}

	tests := []struct {
		name      string
		weight    *int32
		wantSet   bool
		wantValue string
	}{
		{name: "weight set", weight: ptr.To(int32(50)), wantSet: true, wantValue: "50"},
		{name: "weight unset", weight: nil, wantSet: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listeners := []model.L4Listener{
				tcpListener(8080, model.L4Route{
					Backends: []model.Backend{{Name: "echo", Namespace: "default", Port: &model.BackendPort{Port: 9090}, Weight: tt.weight}},
				}),
			}

			got := trans.desiredL4EndpointSlices(listeners, testL4Source(), testLBService(corev1.IPv4Protocol))
			require.Len(t, got, 1)
			value, ok := got[0].Annotations[EndpointSliceWeightAnnotation]
			assert.Equal(t, tt.wantSet, ok)
			assert.Equal(t, tt.wantValue, value)
		})
	}
}

func Test_desiredL4EndpointSlices_noEnabledFamilies(t *testing.T) {
	trans := &gatewayAPITranslator{}

	svc := testLBService()
	// An unrecognized family yields no address types.
	svc.Spec.IPFamilies = []corev1.IPFamily{corev1.IPFamily("bogus")}

	listeners := []model.L4Listener{
		tcpListener(8080, model.L4Route{Backends: []model.Backend{{Name: "echo", Namespace: "default"}}}),
	}

	got := trans.desiredL4EndpointSlices(listeners, testL4Source(), svc)
	assert.Nil(t, got)
}

func Test_listenerPortName(t *testing.T) {
	assert.Equal(t, "port-8080", listenerPortName(tcpListener(8080)))
	assert.Equal(t, "port-53-udp", listenerPortName(udpListener(53)))
}

func Test_backendTargetPort(t *testing.T) {
	l := tcpListener(8080)

	// Explicit backend port wins.
	assert.Equal(t, uint32(9090), backendTargetPort(l, model.Backend{Port: &model.BackendPort{Port: 9090}}))
	// Unset backend port falls back to listener port.
	assert.Equal(t, uint32(8080), backendTargetPort(l, model.Backend{}))
	// Zero backend port falls back to listener port.
	assert.Equal(t, uint32(8080), backendTargetPort(l, model.Backend{Port: &model.BackendPort{Port: 0}}))
}

func Test_enabledAddressTypes(t *testing.T) {
	tests := []struct {
		name string
		svc  *corev1.Service
		want []discoveryv1.AddressType
	}{
		{name: "nil svc", svc: nil, want: nil},
		{name: "default to IPv4", svc: testLBService(), want: []discoveryv1.AddressType{discoveryv1.AddressTypeIPv4}},
		{name: "IPv4 only", svc: testLBService(corev1.IPv4Protocol), want: []discoveryv1.AddressType{discoveryv1.AddressTypeIPv4}},
		{name: "IPv6 only", svc: testLBService(corev1.IPv6Protocol), want: []discoveryv1.AddressType{discoveryv1.AddressTypeIPv6}},
		{name: "dual stack", svc: testLBService(corev1.IPv4Protocol, corev1.IPv6Protocol), want: []discoveryv1.AddressType{discoveryv1.AddressTypeIPv4, discoveryv1.AddressTypeIPv6}},
		{name: "unknown family dropped", svc: testLBService(corev1.IPFamily("bogus")), want: []discoveryv1.AddressType{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, enabledAddressTypes(tt.svc))
		})
	}
}

func Test_backendHash(t *testing.T) {
	b := model.Backend{Name: "echo", Namespace: "default"}

	h := backendHash(b, 9090, corev1.ProtocolTCP)
	assert.Len(t, h, 8)
	// Deterministic.
	assert.Equal(t, h, backendHash(b, 9090, corev1.ProtocolTCP))
	// Protocol differentiates.
	assert.NotEqual(t, h, backendHash(b, 9090, corev1.ProtocolUDP))
	// Port differentiates.
	assert.NotEqual(t, h, backendHash(b, 9091, corev1.ProtocolTCP))
	// Backend identity differentiates.
	assert.NotEqual(t, h, backendHash(model.Backend{Name: "other", Namespace: "default"}, 9090, corev1.ProtocolTCP))
}

func Test_normalizedWeight(t *testing.T) {
	assert.Nil(t, normalizedWeight(nil))
	assert.Equal(t, uint16(0), ptr.Deref(normalizedWeight(ptr.To(int32(0))), 1))
	assert.Equal(t, uint16(50), ptr.Deref(normalizedWeight(ptr.To(int32(50))), 0))
	// Capped to uint16 max.
	assert.Equal(t, uint16(65535), ptr.Deref(normalizedWeight(ptr.To(int32(1_000_000))), 0))
}

func Test_buildEndpointSlice_familySuffix(t *testing.T) {
	args := buildEPSArgs{
		svcName:     "cilium-gateway-my-gateway",
		gwShort:     "my-gateway",
		namespace:   "default",
		backend:     model.Backend{Name: "echo", Namespace: "default"},
		backendPort: 9090,
		protocol:    corev1.ProtocolTCP,
		ownerRef:    metav1.OwnerReference{Kind: "Gateway"},
	}

	v4 := buildEndpointSlice(func() buildEPSArgs { a := args; a.family = discoveryv1.AddressTypeIPv4; return a }())
	v6 := buildEndpointSlice(func() buildEPSArgs { a := args; a.family = discoveryv1.AddressTypeIPv6; return a }())

	assert.Contains(t, v4.Name, "ipv4")
	assert.Contains(t, v6.Name, "ipv6")
	assert.NotEqual(t, v4.Name, v6.Name)
	assert.Equal(t, discoveryv1.AddressTypeIPv4, v4.AddressType)
	assert.Equal(t, discoveryv1.AddressTypeIPv6, v6.AddressType)
}
