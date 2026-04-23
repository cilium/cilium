// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package routechecks

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// Gateway fixture with kind restrictions on each listener:
//
// - https: kinds [HTTPRoute]
// - grpcs: kinds [GRPCRoute]
//
// Used to test that CheckGatewayRouteKindAllowed evaluates only the
// listener targeted by parentRef.sectionName, not all listeners.
var kindRestrictedGateway = &gatewayv1.Gateway{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "kind-restricted-gateway",
		Namespace: "default",
	},
	Spec: gatewayv1.GatewaySpec{
		GatewayClassName: "cilium",
		Listeners: []gatewayv1.Listener{
			{
				Name:     "https",
				Port:     443,
				Protocol: gatewayv1.HTTPSProtocolType,
				AllowedRoutes: &gatewayv1.AllowedRoutes{
					Kinds: []gatewayv1.RouteGroupKind{
						{
							Group: ptr.To[gatewayv1.Group](gatewayv1.GroupName),
							Kind:  "HTTPRoute",
						},
					},
				},
			},
			{
				Name:     "grpcs",
				Port:     50051,
				Protocol: gatewayv1.HTTPSProtocolType,
				AllowedRoutes: &gatewayv1.AllowedRoutes{
					Kinds: []gatewayv1.RouteGroupKind{
						{
							Group: ptr.To[gatewayv1.Group](gatewayv1.GroupName),
							Kind:  "GRPCRoute",
						},
					},
				},
			},
		},
	},
}

// Gateway fixture with restrictive Selector listener first, permissive All
// listener second. Used to test that CheckGatewayAllowedForNamespace does not
// early-return on a Selector failure before checking remaining listeners.
var mixedNamespaceGateway = &gatewayv1.Gateway{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "mixed-ns-gateway",
		Namespace: "default",
	},
	Spec: gatewayv1.GatewaySpec{
		GatewayClassName: "cilium",
		Listeners: []gatewayv1.Listener{
			{
				Name:     "http-selector",
				Port:     8082,
				Protocol: gatewayv1.HTTPProtocolType,
				Hostname: ptr.To[gatewayv1.Hostname]("*.http-selector.io"),
				AllowedRoutes: &gatewayv1.AllowedRoutes{
					Namespaces: &gatewayv1.RouteNamespaces{
						From: ptr.To(gatewayv1.NamespacesFromSelector),
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"kubernetes.io/metadata.name": "default",
							},
						},
					},
				},
			},
			{
				Name:     "http-all",
				Port:     8081,
				Protocol: gatewayv1.HTTPProtocolType,
				Hostname: ptr.To[gatewayv1.Hostname]("*.http-all.io"),
				AllowedRoutes: &gatewayv1.AllowedRoutes{
					Namespaces: &gatewayv1.RouteNamespaces{
						From: ptr.To(gatewayv1.NamespacesFromAll),
					},
				},
			},
		},
	},
}

// Gateway fixture with no kind restrictions on any listener.
var noKindRestrictedGateway = &gatewayv1.Gateway{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "no-kind-restricted-gateway",
		Namespace: "default",
	},
	Spec: gatewayv1.GatewaySpec{
		GatewayClassName: "cilium",
		Listeners: []gatewayv1.Listener{
			{
				Name:     "http",
				Port:     80,
				Protocol: gatewayv1.HTTPProtocolType,
			},
		},
	},
}

var gatewayFixtures = []client.Object{
	// Gateway fixture with allow rules:
	//
	// - http-same: From same namespace
	// - http-all: From all namespaces
	// - http-selector: From namespace with label "allowed=true"
	// - https-same: From same namespace
	// - http-all: From all namespaces
	// - https-selector: From namespace with label "allowed=true"
	&gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "dummy-gateway",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "cilium",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http-same",
					Port:     8080,
					Hostname: ptr.To[gatewayv1.Hostname]("*.http-same.io"),
					AllowedRoutes: &gatewayv1.AllowedRoutes{
						Namespaces: &gatewayv1.RouteNamespaces{
							From: ptr.To(gatewayv1.NamespacesFromSame),
						},
					},
				},

				{
					Name:     "http-selector",
					Port:     8082,
					Hostname: ptr.To[gatewayv1.Hostname]("*.http-selector.io"),
					AllowedRoutes: &gatewayv1.AllowedRoutes{
						Namespaces: &gatewayv1.RouteNamespaces{
							From: ptr.To(gatewayv1.NamespacesFromSelector),
							Selector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"allowed": "true",
								},
							},
						},
					},
				},
				{
					Name:     "https-same",
					Port:     8443,
					Hostname: ptr.To[gatewayv1.Hostname]("*.https-same.io"),
					AllowedRoutes: &gatewayv1.AllowedRoutes{
						Namespaces: &gatewayv1.RouteNamespaces{
							From: ptr.To(gatewayv1.NamespacesFromSame),
						},
					},
				},

				{
					Name:     "https-selector",
					Port:     8445,
					Hostname: ptr.To[gatewayv1.Hostname]("*.https-selector.io"),
					AllowedRoutes: &gatewayv1.AllowedRoutes{
						Namespaces: &gatewayv1.RouteNamespaces{
							From: ptr.To(gatewayv1.NamespacesFromSelector),
							Selector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"allowed": "true",
								},
							},
						},
					},
				},
			},
		},
	},
	&gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "dummy-all-gateway",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "cilium",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http-all",
					Port:     8081,
					Hostname: ptr.To[gatewayv1.Hostname]("*.http-all.io"),
					AllowedRoutes: &gatewayv1.AllowedRoutes{
						Namespaces: &gatewayv1.RouteNamespaces{
							From: ptr.To(gatewayv1.NamespacesFromAll),
						},
					},
				},
				{
					Name:     "https-all",
					Port:     8444,
					Hostname: ptr.To[gatewayv1.Hostname]("*.https-all.io"),
					AllowedRoutes: &gatewayv1.AllowedRoutes{
						Namespaces: &gatewayv1.RouteNamespaces{
							From: ptr.To(gatewayv1.NamespacesFromAll),
						},
					},
				},
			},
		},
	},
}

var namespaceFixture = []client.Object{
	&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	},
	&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "allowed-1",
			Labels: map[string]string{
				"allowed": "true",
			},
		},
	},
	&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "allowed-2",
			Labels: map[string]string{
				"allowed": "true",
			},
		},
	},
	&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "disallowed-1",
		},
	},
	&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "disallowed-2",
			Labels: map[string]string{
				"allowed": "false",
			},
		},
	},
}

func TestCheckGatewayAllowedForNamespace(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = gatewayv1.Install(scheme)
	_ = corev1.AddToScheme(scheme)

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gatewayFixtures...).
		WithObjects(mixedNamespaceGateway).
		WithObjects(namespaceFixture...).
		WithObjects(&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "cross-ns",
			},
		}).
		WithStatusSubresource(&gatewayv1.HTTPRoute{}).
		Build()

	type args struct {
		input     Input
		parentRef gatewayv1.ParentReference
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "gateway not found",
			args: args{
				input: &HTTPRouteInput{
					HTTPRoute: &gatewayv1.HTTPRoute{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "default",
						},
						Spec: gatewayv1.HTTPRouteSpec{},
					},
					Client: c,
				},
				parentRef: gatewayv1.ParentReference{
					Name:      "non-existing-gateway",
					Namespace: ptr.To[gatewayv1.Namespace]("default"),
				},
			},
			want: false,
		},
		{
			name: "no listener matched due to section name mismatch",
			args: args{
				input: &HTTPRouteInput{
					Client: c,
					HTTPRoute: &gatewayv1.HTTPRoute{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "default",
						},
					},
				},
				parentRef: gatewayv1.ParentReference{
					Name:        "dummy-gateway",
					Namespace:   ptr.To[gatewayv1.Namespace]("default"),
					SectionName: ptr.To[gatewayv1.SectionName]("http-invalid"),
				},
			},
			want: false,
		},
		{
			name: "no listener matched due to port mismatch",
			args: args{
				input: &HTTPRouteInput{
					Client: c,
					HTTPRoute: &gatewayv1.HTTPRoute{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "default",
						},
					},
				},
				parentRef: gatewayv1.ParentReference{
					Name:        "dummy-gateway",
					Namespace:   ptr.To[gatewayv1.Namespace]("default"),
					SectionName: ptr.To[gatewayv1.SectionName]("http-invalid"),
				},
			},
			want: false,
		},
		{
			name: "no listener matched due to hostname mismatch",
			args: args{
				input: &HTTPRouteInput{
					Client: c,
					HTTPRoute: &gatewayv1.HTTPRoute{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "default",
						},
						Spec: gatewayv1.HTTPRouteSpec{
							Hostnames: []gatewayv1.Hostname{
								"*.non-matching-host-name.io",
							},
						},
					},
				},
				parentRef: gatewayv1.ParentReference{
					Name:      "dummy-gateway",
					Namespace: ptr.To[gatewayv1.Namespace]("default"),
				},
			},
			want: false,
		},
		{
			name: "listener with all namespaces (allowed)",
			args: args{
				input: &HTTPRouteInput{
					Client: c,
					HTTPRoute: &gatewayv1.HTTPRoute{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "another-ns",
						},
						Spec: gatewayv1.HTTPRouteSpec{
							Hostnames: []gatewayv1.Hostname{
								"*.http-all.io",
							},
						},
					},
				},
				parentRef: gatewayv1.ParentReference{
					Name:        "dummy-all-gateway",
					Namespace:   ptr.To[gatewayv1.Namespace]("default"),
					SectionName: ptr.To[gatewayv1.SectionName]("http-all"),
				},
			},
			want: true,
		},
		{
			name: "listener with same namespace (allowed)",
			args: args{
				input: &HTTPRouteInput{
					Client: c,
					HTTPRoute: &gatewayv1.HTTPRoute{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "default",
						},
						Spec: gatewayv1.HTTPRouteSpec{
							Hostnames: []gatewayv1.Hostname{
								"*.http-same.io",
							},
						},
					},
				},
				parentRef: gatewayv1.ParentReference{
					Name:        "dummy-gateway",
					Namespace:   ptr.To[gatewayv1.Namespace]("default"),
					SectionName: ptr.To[gatewayv1.SectionName]("http-same"),
				},
			},
			want: true,
		},
		{
			name: "listener with same namespace (disallowed)",
			args: args{
				input: &HTTPRouteInput{
					Client: c,
					HTTPRoute: &gatewayv1.HTTPRoute{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "another-ns",
						},
						Spec: gatewayv1.HTTPRouteSpec{
							Hostnames: []gatewayv1.Hostname{
								"*.http-same.io",
							},
						},
					},
				},
				parentRef: gatewayv1.ParentReference{
					Name:        "dummy-gateway",
					Namespace:   ptr.To[gatewayv1.Namespace]("default"),
					SectionName: ptr.To[gatewayv1.SectionName]("http-same"),
				},
			},
			want: false,
		},
		{
			name: "listener with selector namespace (allowed)",
			args: args{
				input: &HTTPRouteInput{
					Client: c,
					HTTPRoute: &gatewayv1.HTTPRoute{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "allowed-1",
						},
						Spec: gatewayv1.HTTPRouteSpec{
							Hostnames: []gatewayv1.Hostname{
								"*.http-selector.io",
							},
						},
					},
				},
				parentRef: gatewayv1.ParentReference{
					Name:        "dummy-gateway",
					Namespace:   ptr.To[gatewayv1.Namespace]("default"),
					SectionName: ptr.To[gatewayv1.SectionName]("http-selector"),
				},
			},
			want: true,
		},
		{
			name: "listener with selector namespace (disallowed)",
			args: args{
				input: &HTTPRouteInput{
					Client: c,
					HTTPRoute: &gatewayv1.HTTPRoute{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "disallowed-1",
						},
						Spec: gatewayv1.HTTPRouteSpec{
							Hostnames: []gatewayv1.Hostname{
								"*.http-selector.io",
							},
						},
					},
				},
				parentRef: gatewayv1.ParentReference{
					Name:        "dummy-gateway",
					Namespace:   ptr.To[gatewayv1.Namespace]("default"),
					SectionName: ptr.To[gatewayv1.SectionName]("http-selector"),
				},
			},
			want: false,
		},

		{
			name: "listener with selector label match not allowed and the section name omitted (allowed)",
			args: args{
				input: &HTTPRouteInput{
					Client: c,
					HTTPRoute: &gatewayv1.HTTPRoute{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "allowed-1",
						},
						Spec: gatewayv1.HTTPRouteSpec{},
					},
				},
				parentRef: gatewayv1.ParentReference{
					Name:      "dummy-gateway",
					Namespace: ptr.To[gatewayv1.Namespace]("default"),
				},
			},
			want: true,
		},
		{
			name: "listener with selector label match not allowed and the section name omitted (disallowed)",
			args: args{
				input: &HTTPRouteInput{
					Client: c,
					HTTPRoute: &gatewayv1.HTTPRoute{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "disallowed-2",
						},
						Spec: gatewayv1.HTTPRouteSpec{},
					},
				},
				parentRef: gatewayv1.ParentReference{
					Name:      "dummy-gateway",
					Namespace: ptr.To[gatewayv1.Namespace]("default"),
				},
			},
			want: false,
		},
		{
			name: "https listener with all namespaces (allowed)",
			args: args{
				input: &HTTPRouteInput{
					Client: c,
					HTTPRoute: &gatewayv1.HTTPRoute{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "another-ns",
						},
						Spec: gatewayv1.HTTPRouteSpec{
							Hostnames: []gatewayv1.Hostname{
								"*.https-all.io",
							},
						},
					},
				},
				parentRef: gatewayv1.ParentReference{
					Name:        "dummy-all-gateway",
					Namespace:   ptr.To[gatewayv1.Namespace]("default"),
					SectionName: ptr.To[gatewayv1.SectionName]("https-all"),
				},
			},
			want: true,
		},
		{
			name: "https listener with same namespace (allowed)",
			args: args{
				input: &HTTPRouteInput{
					Client: c,
					HTTPRoute: &gatewayv1.HTTPRoute{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "default",
						},
						Spec: gatewayv1.HTTPRouteSpec{
							Hostnames: []gatewayv1.Hostname{
								"*.https-same.io",
							},
						},
					},
				},
				parentRef: gatewayv1.ParentReference{
					Name:        "dummy-gateway",
					Namespace:   ptr.To[gatewayv1.Namespace]("default"),
					SectionName: ptr.To[gatewayv1.SectionName]("https-same"),
				},
			},
			want: true,
		},
		{
			name: "https listener with same namespace (disallowed)",
			args: args{
				input: &HTTPRouteInput{
					Client: c,
					HTTPRoute: &gatewayv1.HTTPRoute{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "another-ns",
						},
						Spec: gatewayv1.HTTPRouteSpec{
							Hostnames: []gatewayv1.Hostname{
								"*.https-same.io",
							},
						},
					},
				},
				parentRef: gatewayv1.ParentReference{
					Name:        "dummy-gateway",
					Namespace:   ptr.To[gatewayv1.Namespace]("default"),
					SectionName: ptr.To[gatewayv1.SectionName]("https-same"),
				},
			},
			want: false,
		},
		{
			name: "https listener with selector namespace (allowed)",
			args: args{
				input: &HTTPRouteInput{
					Client: c,
					HTTPRoute: &gatewayv1.HTTPRoute{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "allowed-2",
						},
						Spec: gatewayv1.HTTPRouteSpec{
							Hostnames: []gatewayv1.Hostname{
								"*.https-selector.io",
							},
						},
					},
				},
				parentRef: gatewayv1.ParentReference{
					Name:        "dummy-gateway",
					Namespace:   ptr.To[gatewayv1.Namespace]("default"),
					SectionName: ptr.To[gatewayv1.SectionName]("https-selector"),
				},
			},
			want: true,
		},
		{
			name: "https listener with selector namespace (disallowed)",
			args: args{
				input: &HTTPRouteInput{
					Client: c,
					HTTPRoute: &gatewayv1.HTTPRoute{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "disallowed-2",
						},
						Spec: gatewayv1.HTTPRouteSpec{
							Hostnames: []gatewayv1.Hostname{
								"*.https-selector.io",
							},
						},
					},
				},
				parentRef: gatewayv1.ParentReference{
					Name:        "dummy-gateway",
					Namespace:   ptr.To[gatewayv1.Namespace]("default"),
					SectionName: ptr.To[gatewayv1.SectionName]("https-selector"),
				},
			},
			want: false,
		},
		{
			name: "selector-first then all-second without sectionName, cross-namespace (allowed by all listener)",
			args: args{
				input: &HTTPRouteInput{
					Client: c,
					HTTPRoute: &gatewayv1.HTTPRoute{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "cross-ns",
						},
					},
				},
				parentRef: gatewayv1.ParentReference{
					Name:      "mixed-ns-gateway",
					Namespace: ptr.To[gatewayv1.Namespace]("default"),
				},
			},
			want: true,
		},
		{
			name: "selector-first then all-second with sectionName targeting all listener (allowed)",
			args: args{
				input: &HTTPRouteInput{
					Client: c,
					HTTPRoute: &gatewayv1.HTTPRoute{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "cross-ns",
						},
						Spec: gatewayv1.HTTPRouteSpec{
							Hostnames: []gatewayv1.Hostname{
								"*.http-all.io",
							},
						},
					},
				},
				parentRef: gatewayv1.ParentReference{
					Name:        "mixed-ns-gateway",
					Namespace:   ptr.To[gatewayv1.Namespace]("default"),
					SectionName: ptr.To[gatewayv1.SectionName]("http-all"),
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CheckGatewayAllowedForNamespace(tt.args.input, tt.args.parentRef)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckGatewayAllowedForNamespace() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("CheckGatewayAllowedForNamespace() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckGatewayRouteKindAllowed(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = gatewayv1.Install(scheme)

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(kindRestrictedGateway, noKindRestrictedGateway).
		WithStatusSubresource(&gatewayv1.HTTPRoute{}).
		Build()

	type args struct {
		input     Input
		parentRef gatewayv1.ParentReference
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "gateway not found",
			args: args{
				input: &HTTPRouteInput{
					Client: c,
					HTTPRoute: &gatewayv1.HTTPRoute{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "default",
						},
					},
				},
				parentRef: gatewayv1.ParentReference{
					Name:      "non-existing-gateway",
					Namespace: ptr.To[gatewayv1.Namespace]("default"),
				},
			},
			want: false,
		},
		{
			name: "no kind restrictions on listener (allowed)",
			args: args{
				input: &HTTPRouteInput{
					Client: c,
					HTTPRoute: &gatewayv1.HTTPRoute{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "default",
						},
					},
				},
				parentRef: gatewayv1.ParentReference{
					Name:        "no-kind-restricted-gateway",
					Namespace:   ptr.To[gatewayv1.Namespace]("default"),
					SectionName: ptr.To[gatewayv1.SectionName]("http"),
				},
			},
			want: true,
		},
		{
			name: "HTTPRoute targeting https listener with kinds [HTTPRoute] (allowed)",
			args: args{
				input: &HTTPRouteInput{
					Client: c,
					HTTPRoute: &gatewayv1.HTTPRoute{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "default",
						},
					},
				},
				parentRef: gatewayv1.ParentReference{
					Name:        "kind-restricted-gateway",
					Namespace:   ptr.To[gatewayv1.Namespace]("default"),
					SectionName: ptr.To[gatewayv1.SectionName]("https"),
				},
			},
			want: true,
		},
		{
			name: "HTTPRoute targeting grpcs listener with kinds [GRPCRoute] (rejected)",
			args: args{
				input: &HTTPRouteInput{
					Client: c,
					HTTPRoute: &gatewayv1.HTTPRoute{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "default",
						},
					},
				},
				parentRef: gatewayv1.ParentReference{
					Name:        "kind-restricted-gateway",
					Namespace:   ptr.To[gatewayv1.Namespace]("default"),
					SectionName: ptr.To[gatewayv1.SectionName]("grpcs"),
				},
			},
			want: false,
		},
		{
			name: "HTTPRoute without sectionName on kind-restricted gateway (allowed by https listener)",
			args: args{
				input: &HTTPRouteInput{
					Client: c,
					HTTPRoute: &gatewayv1.HTTPRoute{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "default",
						},
					},
				},
				parentRef: gatewayv1.ParentReference{
					Name:      "kind-restricted-gateway",
					Namespace: ptr.To[gatewayv1.Namespace]("default"),
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CheckGatewayRouteKindAllowed(tt.args.input, tt.args.parentRef)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckGatewayRouteKindAllowed() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("CheckGatewayRouteKindAllowed() got = %v, want %v", got, tt.want)
			}
		})
	}
}
