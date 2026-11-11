// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestIsRouteKindAllowedForListener(t *testing.T) {
	tests := []struct {
		name            string
		routes          []metav1.Object
		protocol        gatewayv1.ProtocolType
		allowedKinds    []gatewayv1.RouteGroupKind
		noAllowedRoutes bool
		expected        bool
	}{
		{
			name:            "Supported kinds for protocol are allowed without allowedRoutes",
			protocol:        gatewayv1.HTTPProtocolType,
			routes:          []metav1.Object{new(gatewayv1.HTTPRoute), new(gatewayv1.GRPCRoute)},
			noAllowedRoutes: true,
			expected:        true,
		},
		{
			name:            "Unsupported kinds for protocol are disallowed without allowedRoutes",
			protocol:        gatewayv1.HTTPProtocolType,
			routes:          []metav1.Object{new(gatewayv1.TLSRoute), new(gatewayv1.TCPRoute), new(gatewayv1.UDPRoute)},
			noAllowedRoutes: true,
			expected:        false,
		},
		{
			name:         "Unsupported kinds for protocol are disallowed regardless of allowed kinds",
			protocol:     gatewayv1.HTTPProtocolType,
			routes:       []metav1.Object{new(gatewayv1.HTTPRoute)},
			allowedKinds: GatewayRouteGroupKinds(KindTCPRoute),
			expected:     false,
		},
		{
			name:         "Disallows supported kinds not explicitly allowed",
			protocol:     gatewayv1.HTTPProtocolType,
			routes:       []metav1.Object{new(gatewayv1.HTTPRoute)},
			allowedKinds: GatewayRouteGroupKinds(KindGRPCRoute),
			expected:     false,
		},
		{
			name:     "HTTP/GRPCRoutes are allowed for HTTP protocol",
			protocol: gatewayv1.HTTPProtocolType,
			routes:   []metav1.Object{new(gatewayv1.HTTPRoute), new(gatewayv1.GRPCRoute)},
			expected: true,
		},
		{
			name:     "Non-HTTP/GRPCRoutes are disallowed for HTTP protocol",
			protocol: gatewayv1.HTTPProtocolType,
			routes:   []metav1.Object{new(gatewayv1.TLSRoute), new(gatewayv1.TCPRoute), new(gatewayv1.UDPRoute)},
			expected: false,
		},
		{
			name:     "TLSRoutes are allowed for TLS protocol",
			protocol: gatewayv1.TLSProtocolType,
			routes:   []metav1.Object{new(gatewayv1.TLSRoute)},
			expected: true,
		},
		{
			name:     "Non-TLSRoutes are disallowed for TLS protocol",
			protocol: gatewayv1.TLSProtocolType,
			routes:   []metav1.Object{new(gatewayv1.HTTPRoute), new(gatewayv1.GRPCRoute), new(gatewayv1.TCPRoute), new(gatewayv1.UDPRoute)},
			expected: false,
		},
		{
			name:     "TCPRoutes are allowed for TCP protocol",
			protocol: gatewayv1.TCPProtocolType,
			routes:   []metav1.Object{new(gatewayv1.TCPRoute)},
			expected: true,
		},
		{
			name:     "Non-TCPRoutes are disallowed for TCP protocol",
			protocol: gatewayv1.TCPProtocolType,
			routes:   []metav1.Object{new(gatewayv1.HTTPRoute), new(gatewayv1.GRPCRoute), new(gatewayv1.TLSRoute), new(gatewayv1.UDPRoute)},
			expected: false,
		},
		{
			name:     "UDPRoutes are allowed for UDP protocol",
			protocol: gatewayv1.UDPProtocolType,
			routes:   []metav1.Object{new(gatewayv1.UDPRoute)},
			expected: true,
		},
		{
			name:     "Non-UDPRoutes are disallowed for UDP protocol",
			protocol: gatewayv1.UDPProtocolType,
			routes:   []metav1.Object{new(gatewayv1.HTTPRoute), new(gatewayv1.GRPCRoute), new(gatewayv1.TLSRoute), new(gatewayv1.TCPRoute)},
			expected: false,
		},
		{
			name:     "TLSRoutes are allowed for TLS protocol",
			protocol: gatewayv1.TLSProtocolType,
			routes:   []metav1.Object{new(gatewayv1.TLSRoute)},
			expected: true,
		},
		{
			name:     "Non-TLSRoutes are disallowed for TLS protocol",
			protocol: gatewayv1.TLSProtocolType,
			routes:   []metav1.Object{new(gatewayv1.HTTPRoute), new(gatewayv1.GRPCRoute), new(gatewayv1.TCPRoute), new(gatewayv1.UDPRoute)},
			expected: false,
		},
		{
			name:     "Non-Route kinds are disallowed regardless of allowed kinds",
			protocol: gatewayv1.HTTPProtocolType,
			routes:   []metav1.Object{new(corev1.Secret)},
			allowedKinds: []gatewayv1.RouteGroupKind{
				{Group: new(gatewayv1.Group(corev1.GroupName)), Kind: "Secret"},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ln := gatewayv1.Listener{Protocol: tt.protocol}
			if !tt.noAllowedRoutes {
				ln.AllowedRoutes = &gatewayv1.AllowedRoutes{Kinds: tt.allowedKinds}
			}

			for _, route := range tt.routes {
				assert.Equal(t, tt.expected, IsRouteKindAllowedForListener(ln, route))
			}
		})
	}
}

func TestNormalizeAllowedGroupKinds(t *testing.T) {
	tests := []struct {
		name         string
		protocol     gatewayv1.ProtocolType
		allowedKinds []gatewayv1.RouteGroupKind
		expected     []gatewayv1.RouteGroupKind
	}{
		{
			name:     "Non-Gateway kinds are removed",
			protocol: gatewayv1.HTTPProtocolType,
			allowedKinds: []gatewayv1.RouteGroupKind{
				GatewayRouteGroupKind(KindHTTPRoute),
				{Group: new(gatewayv1.Group(corev1.GroupName)), Kind: "Secret"},
			},
			expected: GatewayRouteGroupKinds(KindHTTPRoute),
		}, {
			name:         "Kinds unsupported by protocol are removed",
			protocol:     gatewayv1.TCPProtocolType,
			allowedKinds: GatewayRouteGroupKinds(KindHTTPRoute, KindTCPRoute),
			expected:     GatewayRouteGroupKinds(KindTCPRoute),
		}, {
			name:     "Defaults group to gateway",
			protocol: gatewayv1.TLSProtocolType,
			allowedKinds: []gatewayv1.RouteGroupKind{
				{Kind: KindTLSRoute},
			},
			expected: []gatewayv1.RouteGroupKind{
				{Group: new(gatewayv1.Group(gatewayv1.GroupName)), Kind: KindTLSRoute},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := NormalizeAllowedGroupKinds(tt.protocol, tt.allowedKinds)
			assert.Equal(t, tt.expected, res)
		})
	}
}

func TestIsParentAttachable(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		reconcileParent metav1.Object
		route           metav1.Object
		parents         []gatewayv1.RouteParentStatus
		want            bool
	}{
		{
			name: "Gateway parent, all okay",
			reconcileParent: &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gateway",
					Namespace: "testns",
				},
			},
			route: httpRouteWithParentAndStatus("gammaRoute",
				"testns",
				"gateway",
				nil),
			parents: parentStatus("gateway",
				nil,
				true),
			want: true,
		},
		{
			name: "Gateway parent, Not Accepted",
			reconcileParent: &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gateway",
					Namespace: "testns",
				},
			},
			route: httpRouteWithParentAndStatus("gammaRoute",
				"testns",
				"gateway",
				nil),
			parents: parentStatus("gateway",
				nil,
				false),
			want: false,
		},
		{
			name: "Gateway parent, Accepted but namespace mismatch",
			reconcileParent: &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gateway",
					Namespace: "testns",
				},
			},
			route: httpRouteWithParentAndStatus("gammaRoute",
				"testns",
				"gateway",
				ptr.To("otherns")),
			parents: parentStatus("gateway",
				ptr.To("otherns"),
				true),
			want: false,
		},

		{
			name: "GAMMA Service parent, same namespace",
			reconcileParent: &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gammaParent",
					Namespace: "testns",
				},
			},
			route: httpRouteWithParentAndStatus("gammaRoute",
				"testns",
				"gammaParent",
				nil),
			parents: parentStatus("gammaParent",
				nil,
				true),

			want: true,
		},
		{
			name: "GAMMA Service parent, diff namespace",
			reconcileParent: &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gammaParent",
					Namespace: "otherns",
				},
			},
			route: httpRouteWithParentAndStatus("gammaRoute",
				"testns",
				"",
				ptr.To("otherns")),
			parents: parentStatus("gateway",
				ptr.To("otherns"),
				false),
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsParentAttachable(tt.reconcileParent, tt.route, tt.parents, nil)
			if tt.want != got {
				t.Errorf("IsParentAttachable() = %v, want %v", got, tt.want)
			}
		})
	}
}

func httpRouteWithParentAndStatus(name, ns, parentName string, parentNS *string) *gatewayv1.HTTPRoute {
	gwParentName := gatewayv1.ObjectName(parentName)
	var gwParentNS *gatewayv1.Namespace
	if parentNS != nil {
		tempNS := gatewayv1.Namespace(*parentNS)
		gwParentNS = &tempNS
	} else {
		gwParentNS = nil
	}

	parentRef := gatewayv1.ParentReference{
		Name:      gwParentName,
		Namespace: gwParentNS,
	}
	return &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					parentRef,
				},
			},
		},
	}
}

func parentStatus(parentName string, parentNS *string, status bool) []gatewayv1.RouteParentStatus {
	gwParentName := gatewayv1.ObjectName(parentName)
	var gwParentNS *gatewayv1.Namespace
	if parentNS != nil {
		tempNS := gatewayv1.Namespace(*parentNS)
		gwParentNS = &tempNS
	} else {
		gwParentNS = nil
	}

	parentRef := gatewayv1.ParentReference{
		Name:      gwParentName,
		Namespace: gwParentNS,
	}
	var condStatus metav1.ConditionStatus

	if status {
		condStatus = metav1.ConditionTrue
	} else {
		condStatus = metav1.ConditionFalse
	}

	return []gatewayv1.RouteParentStatus{
		{
			ParentRef: parentRef,
			Conditions: []metav1.Condition{
				{
					Type:   "Accepted",
					Status: condStatus,
				},
				{
					Type:   "ResolvedRefs",
					Status: condStatus,
				},
			},
		},
	}
}
