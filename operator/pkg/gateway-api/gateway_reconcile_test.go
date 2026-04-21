// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"fmt"
	"log/slog"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
	"github.com/cilium/cilium/operator/pkg/model/translation"
	gatewayApiTranslation "github.com/cilium/cilium/operator/pkg/model/translation/gateway-api"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/shortener"
)

var (
	gatewayv1APIVersion = gatewayv1.GroupVersion.Group + "/" + gatewayv1.GroupVersion.Version
	gatewayTypeMeta     = metav1.TypeMeta{
		Kind:       "Gateway",
		APIVersion: gatewayv1APIVersion,
	}
	httpRouteTypeMeta = metav1.TypeMeta{
		Kind:       "HTTPRoute",
		APIVersion: gatewayv1APIVersion,
	}
	grpcRouteTypeMeta = metav1.TypeMeta{
		Kind:       "GRPCRoute",
		APIVersion: gatewayv1APIVersion,
	}
	tlsRouteTypeMeta = metav1.TypeMeta{
		Kind:       "TLSRoute",
		APIVersion: gatewayv1APIVersion,
	}
	backendTLSPolicyTypeMeta = metav1.TypeMeta{
		Kind:       "BackendTLSPolicy",
		APIVersion: gatewayv1APIVersion,
	}
)

func Test_Conformance(t *testing.T) {
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
	translatorCfg := translation.Config{
		RouteConfig: translation.RouteConfig{
			HostNameSuffixMatch: true,
		},
		ListenerConfig: translation.ListenerConfig{
			StreamIdleTimeoutSeconds: 300,
		},
		ClusterConfig: translation.ClusterConfig{
			IdleTimeoutSeconds: 60,
		},
		ServiceConfig: translation.ServiceConfig{
			ExternalTrafficPolicy: string(corev1.ServiceExternalTrafficPolicyCluster),
		},
	}
	reconcilerCfg := translation.Config{
		IPConfig: translation.IPConfig{
			IPv4Enabled: true,
		},
	}

	var (
		gatewaySameNamespace          = gwDetails{FullName: types.NamespacedName{Name: "same-namespace", Namespace: "gateway-conformance-infra"}}
		gatewaySameNamespaceWithHTTPS = gwDetails{FullName: types.NamespacedName{Name: "same-namespace-with-https-listener", Namespace: "gateway-conformance-infra"}}
		gatewayBackendNamespace       = gwDetails{FullName: types.NamespacedName{Name: "backend-namespaces", Namespace: "gateway-conformance-infra"}}
	)

	tests := []struct {
		name                 string
		gateway              []gwDetails
		disableServiceImport bool
		wantErr              bool
	}{
		{
			name: "gateway-http-listener-isolation",
			gateway: []gwDetails{
				{FullName: types.NamespacedName{Name: "http-listener-isolation", Namespace: "gateway-conformance-infra"}},
				{FullName: types.NamespacedName{Name: "http-listener-isolation-with-hostname-intersection", Namespace: "gateway-conformance-infra"}},
			},
		},
		{
			name:    "gateway-infrastructure",
			gateway: []gwDetails{{FullName: types.NamespacedName{Name: "gateway-with-infrastructure-metadata", Namespace: "gateway-conformance-infra"}}},
		},
		{
			name: "gateway-invalid-route-kind",
			gateway: []gwDetails{
				{FullName: types.NamespacedName{Name: "gateway-only-invalid-route-kind", Namespace: "gateway-conformance-infra"}, wantErr: true},
				{FullName: types.NamespacedName{Name: "gateway-supported-and-invalid-route-kind", Namespace: "gateway-conformance-infra"}},
			},
		},
		{
			name: "gateway-invalid-tls-configuration",
			gateway: []gwDetails{
				{FullName: types.NamespacedName{Name: "gateway-certificate-nonexistent-secret", Namespace: "gateway-conformance-infra"}, wantErr: true},
				{FullName: types.NamespacedName{Name: "gateway-certificate-unsupported-group", Namespace: "gateway-conformance-infra"}, wantErr: true},
				{FullName: types.NamespacedName{Name: "gateway-certificate-unsupported-kind", Namespace: "gateway-conformance-infra"}, wantErr: true},
				{FullName: types.NamespacedName{Name: "gateway-certificate-malformed-secret", Namespace: "gateway-conformance-infra"}, wantErr: true},
			},
		},
		{
			name: "gateway-modify-listeners",
			gateway: []gwDetails{
				{FullName: types.NamespacedName{Name: "gateway-add-listener", Namespace: "gateway-conformance-infra"}, wantErr: true},
				{FullName: types.NamespacedName{Name: "gateway-remove-listener", Namespace: "gateway-conformance-infra"}},
			},
		},
		{
			name: "gateway-observed-generation-bump",
			gateway: []gwDetails{
				{FullName: types.NamespacedName{Name: "gateway-observed-generation-bump", Namespace: "gateway-conformance-infra"}},
			},
		},
		{
			name: "gateway-secret-invalid-reference-grant",
			gateway: []gwDetails{
				{FullName: types.NamespacedName{Name: "gateway-secret-invalid-reference-grant", Namespace: "gateway-conformance-infra"}, wantErr: true},
			},
		},
		{
			name: "gateway-secret-missing-reference-grant",
			gateway: []gwDetails{
				{FullName: types.NamespacedName{Name: "gateway-secret-missing-reference-grant", Namespace: "gateway-conformance-infra"}, wantErr: true},
			},
		},
		// gateway-secret-reference-grant-all-in-namespace
		{
			name: "gateway-secret-reference-grant-all-in-namespace",
			gateway: []gwDetails{
				{FullName: types.NamespacedName{Name: "gateway-secret-reference-grant-all-in-namespace", Namespace: "gateway-conformance-infra"}},
			},
		},
		{
			name: "gateway-secret-reference-grant-specific",
			gateway: []gwDetails{
				{FullName: types.NamespacedName{Name: "gateway-secret-reference-grant-specific", Namespace: "gateway-conformance-infra"}},
			},
		},
		{
			name: "gateway-static-addresses",
			gateway: []gwDetails{
				{FullName: types.NamespacedName{Name: "gateway-static-addresses", Namespace: "gateway-conformance-infra"}},
			},
		},
		{
			name: "gateway-static-addresses",
			gateway: []gwDetails{
				{FullName: types.NamespacedName{Name: "gateway-static-addresses-invalid", Namespace: "gateway-conformance-infra"}, wantErr: true},
			},
		},
		{
			name: "gateway-with-attached-routes",
			gateway: []gwDetails{
				{FullName: types.NamespacedName{Name: "gateway-with-one-attached-route", Namespace: "gateway-conformance-infra"}},
				{FullName: types.NamespacedName{Name: "gateway-with-two-attached-routes", Namespace: "gateway-conformance-infra"}},
				{FullName: types.NamespacedName{Name: "unresolved-gateway-with-one-attached-unresolved-route", Namespace: "gateway-conformance-infra"}, wantErr: true},
			},
		},
		{
			name: "gateway-multiple-listeners",
			gateway: []gwDetails{
				{FullName: types.NamespacedName{
					Name:      "gateway-multiple-listeners",
					Namespace: "gateway-conformance-infra",
				}},
			},
		},
		{
			name: "gateway-omit-sectionName-listeners",
			gateway: []gwDetails{
				{FullName: types.NamespacedName{
					Name:      "gateway-omit-sectionName-listeners",
					Namespace: "gateway-conformance-infra-label",
				}},
			},
		},
		{name: "grpcroute-exact-method-matching", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "grpcroute-header-matching", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "grpcroute-listener-hostname-matching", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "grpcroute-listener-hostname-matching", Namespace: "gateway-conformance-infra"}}}},
		{name: "httproute-backend-protocol-h2c", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-backend-protocol-websocket", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-cross-namespace", gateway: []gwDetails{gatewayBackendNamespace}},
		{
			name:    "httproute-disallowed-kind",
			gateway: []gwDetails{{FullName: types.NamespacedName{Name: "tlsroutes-only", Namespace: "gateway-conformance-infra"}}},
		},
		{name: "httproute-exact-path-matching", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-header-matching", gateway: []gwDetails{gatewaySameNamespace}},
		{
			name: "httproute-hostname-intersection",
			gateway: []gwDetails{
				{FullName: types.NamespacedName{Name: "httproute-hostname-intersection", Namespace: "gateway-conformance-infra"}},
				{FullName: types.NamespacedName{Name: "httproute-hostname-intersection-all", Namespace: "gateway-conformance-infra"}},
			},
		},
		{name: "httproute-https-listener", gateway: []gwDetails{gatewaySameNamespaceWithHTTPS}},
		{name: "httproute-invalid-backendref-unknown-kind", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-invalid-backendref-missing-service-port", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-invalid-backendref-missing-serviceimport-port", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-invalid-cross-namespace-backend-ref", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-invalid-cross-namespace-parent-ref", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-invalid-nonexistent-backendref", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-invalid-parentref-not-matching-listener-port", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-invalid-parentref-not-matching-section-name", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-invalid-parentref-section-name-not-matching-port", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-invalid-reference-grant", gateway: []gwDetails{gatewaySameNamespace}},
		{
			name:    "httproute-listener-hostname-matching",
			gateway: []gwDetails{{FullName: types.NamespacedName{Name: "httproute-listener-hostname-matching", Namespace: "gateway-conformance-infra"}}},
		},
		{
			name:    "httproute-listener-port-matching",
			gateway: []gwDetails{{FullName: types.NamespacedName{Name: "httproute-listener-port-matching", Namespace: "gateway-conformance-infra"}}},
		},
		{name: "httproute-matching", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-matching-across-routes", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-method-matching", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-observed-generation-bump", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-partially-invalid-via-invalid-reference-grant", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-path-match-order", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-query-param-matching", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-redirect-host-and-status", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-redirect-path", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-redirect-port", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-redirect-port-and-scheme", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-redirect-scheme", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-reference-grant", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-request-header-modifier", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-request-header-modifier-backend-weights", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-request-mirror", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-request-multiple-mirrors", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-request-percentage-mirror", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-response-header-modifier", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-timeout-backend-request", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-timeout-request", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-weight", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-service-types", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-invalid-parentref-types", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-simple-same-namespace", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-serviceimport-backend", gateway: []gwDetails{gatewaySameNamespace}},
		{
			name: "httproute-invalid-serviceimport-no-crd", gateway: []gwDetails{gatewaySameNamespace},
			disableServiceImport: true,
		},
		{name: "httproute-backendtlspolicy-valid", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-backendtlspolicy-reencrypt", gateway: []gwDetails{gatewaySameNamespaceWithHTTPS}},
		{name: "httproute-backendtlspolicy-multiparent", gateway: []gwDetails{gatewaySameNamespace, gatewaySameNamespaceWithHTTPS}},
		{name: "httproute-backendtlspolicy-conflict-resolution", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-backendtlspolicy-invalid-ca-cert", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-backendtlspolicy-invalid-kind", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "tlsroute-invalid-reference-grant", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "gateway-tlsroute-referencegrant", Namespace: "gateway-conformance-infra"}}}},
		{name: "tlsroute-simple-same-namespace", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "gateway-tlsroute", Namespace: "gateway-conformance-infra"}}}},
		{name: "tlsroute-hostname-intersection", gateway: []gwDetails{
			{FullName: types.NamespacedName{Name: "gw-tlsroute-empty-hostname-x-4", Namespace: "gateway-conformance-infra"}},
			{FullName: types.NamespacedName{Name: "gw-tlsroute-exact-hostname-x-1", Namespace: "gateway-conformance-infra"}},
			{FullName: types.NamespacedName{Name: "gw-tlsroute-less-specific-wc-hostname-x-3", Namespace: "gateway-conformance-infra"}},
			{FullName: types.NamespacedName{Name: "gw-tlsroute-more-specific-wc-hostname-x-2", Namespace: "gateway-conformance-infra"}},
		}},
		{name: "tlsroute-invalid-no-matching-listener", gateway: []gwDetails{
			{FullName: types.NamespacedName{Name: "gateway-tlsroute-http-only", Namespace: "gateway-conformance-infra"}, wantErr: false},
			{FullName: types.NamespacedName{Name: "gateway-tlsroute-https-only", Namespace: "gateway-conformance-infra"}, wantErr: false},
			{FullName: types.NamespacedName{Name: "gateway-tlsroute-tls-passthrough-only", Namespace: "gateway-conformance-infra"}, wantErr: false},
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runGatewayConformanceTest(t, logger, tt.name, tt.gateway, translatorCfg, reconcilerCfg, tt.disableServiceImport)
		})
	}
}

func Test_gatewayReconciler_Reconcile_cleansUpResourcesOnHandoff(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name         string
		gatewayClass string
		objects      []client.Object
	}{
		{
			name:         "gatewayclass missing",
			gatewayClass: "missing",
		},
		{
			name:         "gatewayclass controller no longer matches",
			gatewayClass: "other",
			objects: []client.Object{
				&gatewayv1.GatewayClass{
					ObjectMeta: metav1.ObjectMeta{Name: "other"},
					Spec: gatewayv1.GatewayClassSpec{
						ControllerName: "example.com/other-controller",
					},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gw := &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "handoff-gateway",
					Namespace: "default",
					UID:       types.UID("gateway-uid"),
				},
				Spec: gatewayv1.GatewaySpec{
					GatewayClassName: gatewayv1.ObjectName(tc.gatewayClass),
				},
			}

			serviceName := shortener.ShortenK8sResourceName(gatewayApiTranslation.CiliumGatewayPrefix + gw.Name)
			shortGatewayName := shortener.ShortenK8sResourceName(gw.Name)
			svc := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      serviceName,
					Namespace: gw.Namespace,
					Labels: map[string]string{
						owningGatewayLabel:                       shortGatewayName,
						"gateway.networking.k8s.io/gateway-name": shortGatewayName,
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: gatewayv1.GroupVersion.String(),
							Kind:       "Gateway",
							Name:       gw.Name,
							UID:        gw.UID,
							Controller: ptr.To(true),
						},
					},
				},
			}
			cec := &ciliumv2.CiliumEnvoyConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name:      shortener.ShortenK8sResourceName(gatewayApiTranslation.CiliumGatewayPrefix + gw.Name),
					Namespace: gw.Namespace,
					Labels: map[string]string{
						"gateway.networking.k8s.io/gateway-name": shortGatewayName,
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: gatewayv1.GroupVersion.String(),
							Kind:       "Gateway",
							Name:       gw.Name,
							UID:        gw.UID,
							Controller: ptr.To(true),
						},
					},
				},
			}

			objects := append([]client.Object{gw, svc, cec}, tc.objects...)
			c := fake.NewClientBuilder().
				WithScheme(testScheme()).
				WithObjects(objects...).
				Build()

			r := &gatewayReconciler{
				Client: c,
				cfg:    translation.Config{IPConfig: translation.IPConfig{IPv4Enabled: true}},
				logger: hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug)),
			}

			result, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(gw)})
			require.NoError(t, err)
			require.Equal(t, ctrl.Result{}, result)

			err = c.Get(t.Context(), client.ObjectKeyFromObject(svc), &corev1.Service{})
			require.ErrorContains(t, err, "not found")

			err = c.Get(t.Context(), client.ObjectKeyFromObject(cec), &ciliumv2.CiliumEnvoyConfig{})
			require.ErrorContains(t, err, "not found")

			actualGateway := &gatewayv1.Gateway{}
			require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(gw), actualGateway))
		})
	}
}

func filterHTTPRoute(hrList *gatewayv1.HTTPRouteList, gatewayName string, namespace string) []gatewayv1.HTTPRoute {
	var filterList []gatewayv1.HTTPRoute
	for _, hr := range hrList.Items {
		if len(hr.Spec.CommonRouteSpec.ParentRefs) > 0 {
			for _, parentRef := range hr.Spec.CommonRouteSpec.ParentRefs {
				if string(parentRef.Name) == gatewayName &&
					((parentRef.Namespace == nil && hr.Namespace == namespace) || string(*parentRef.Namespace) == namespace) {
					filterList = append(filterList, hr)
					break
				}
			}
		}
	}
	return filterList
}

func filterGRPCRoute(hrList *gatewayv1.GRPCRouteList, gatewayName string, namespace string) []gatewayv1.GRPCRoute {
	var filterList []gatewayv1.GRPCRoute
	for _, grpcr := range hrList.Items {
		if len(grpcr.Spec.CommonRouteSpec.ParentRefs) > 0 {
			for _, parentRef := range grpcr.Spec.CommonRouteSpec.ParentRefs {
				if string(parentRef.Name) == gatewayName &&
					((parentRef.Namespace == nil && grpcr.Namespace == namespace) || string(*parentRef.Namespace) == namespace) {
					filterList = append(filterList, grpcr)
					break
				}
			}
		}
	}
	return filterList
}

func Test_sectionNameMatched(t *testing.T) {
	httpListener := &gatewayv1.Listener{
		Name:     "http",
		Port:     80,
		Hostname: ptr.To[gatewayv1.Hostname]("*.cilium.io"),
		Protocol: "HTTP",
	}
	httpNoMatchListener := &gatewayv1.Listener{
		Name:     "http-no-match",
		Port:     8080,
		Hostname: ptr.To[gatewayv1.Hostname]("*.cilium.io"),
		Protocol: "HTTP",
	}
	gw := &gatewayv1.Gateway{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Gateway",
			APIVersion: gatewayv1.GroupName,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "valid-gateway",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "cilium",
			Listeners: []gatewayv1.Listener{
				*httpListener,
				*httpNoMatchListener,
			},
		},
	}
	type args struct {
		routeNamespace string
		listener       *gatewayv1.Listener
		refs           []gatewayv1.ParentReference
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Matching Section name",
			args: args{
				listener: httpListener,
				refs: []gatewayv1.ParentReference{
					{
						Kind:        (*gatewayv1.Kind)(ptr.To("Gateway")),
						Name:        "valid-gateway",
						SectionName: (*gatewayv1.SectionName)(ptr.To("http")),
					},
				},
			},
			want: true,
		},
		{
			name: "Not matching Section name",
			args: args{
				listener: httpNoMatchListener,
				refs: []gatewayv1.ParentReference{
					{
						Kind:        (*gatewayv1.Kind)(ptr.To("Gateway")),
						Name:        "valid-gateway",
						SectionName: (*gatewayv1.SectionName)(ptr.To("http")),
					},
				},
			},
			want: false,
		},
		{
			name: "Matching Port number",
			args: args{
				listener: httpListener,
				refs: []gatewayv1.ParentReference{
					{
						Kind: (*gatewayv1.Kind)(ptr.To("Gateway")),
						Name: "valid-gateway",
						Port: (*gatewayv1.PortNumber)(ptr.To[int32](80)),
					},
				},
			},
			want: true,
		},
		{
			name: "No matching Port number",
			args: args{
				listener: httpNoMatchListener,
				refs: []gatewayv1.ParentReference{
					{
						Kind: (*gatewayv1.Kind)(ptr.To("Gateway")),
						Name: "valid-gateway",
						Port: (*gatewayv1.PortNumber)(ptr.To[int32](80)),
					},
				},
			},
			want: false,
		},
		{
			name: "Matching both Section name and Port number",
			args: args{
				listener: httpListener,
				refs: []gatewayv1.ParentReference{
					{
						Kind:        (*gatewayv1.Kind)(ptr.To("Gateway")),
						Name:        "valid-gateway",
						SectionName: (*gatewayv1.SectionName)(ptr.To("http")),
						Port:        (*gatewayv1.PortNumber)(ptr.To[int32](80)),
					},
				},
			},
			want: true,
		},
		{
			name: "Matching any listener (httpListener)",
			args: args{
				listener: httpListener,
				refs: []gatewayv1.ParentReference{
					{
						Kind: (*gatewayv1.Kind)(ptr.To("Gateway")),
						Name: "valid-gateway",
					},
				},
			},
			want: true,
		},
		{
			name: "Matching any listener (httpNoMatchListener)",
			args: args{
				listener: httpNoMatchListener,
				refs: []gatewayv1.ParentReference{
					{
						Kind: (*gatewayv1.Kind)(ptr.To("Gateway")),
						Name: "valid-gateway",
					},
				},
			},
			want: true,
		},
		{
			name: "GAMMA Service with same name as Gateway should not match",
			args: args{
				listener: httpListener,
				refs: []gatewayv1.ParentReference{
					{
						Kind:  (*gatewayv1.Kind)(ptr.To("Service")),
						Group: (*gatewayv1.Group)(ptr.To("")),
						Name:  "valid-gateway",
					},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, parentRefMatched(gw, tt.args.listener, "default", tt.args.refs), "parentRefMatched(%v, %v, %v, %v)", gw, tt.args.listener, tt.args.routeNamespace, tt.args.refs)
		})
	}
}

// fakeIndexHTTPRouteByBackendService is a client.IndexerFunc that takes a single HTTPRoute and
// returns all referenced backend service full names (`namespace/name`) to add to the relevant index.
//
// The actual indexer does some dereferencing lookups in order to handle some ServiceImport
// behaviors correctly. This one is what that indexer used to look like before we added ServiceImport
// support.
func fakeIndexHTTPRouteByBackendService(rawObj client.Object) []string {
	route, ok := rawObj.(*gatewayv1.HTTPRoute)
	if !ok {
		return nil
	}
	var backendServices []string

	for _, rule := range route.Spec.Rules {
		for _, backend := range rule.BackendRefs {
			if !helpers.IsService(backend.BackendObjectReference) {
				continue
			}
			namespace := helpers.NamespaceDerefOr(backend.Namespace, route.Namespace)
			backendServices = append(backendServices,
				types.NamespacedName{
					Namespace: namespace,
					Name:      string(backend.Name),
				}.String(),
			)
		}
	}
	return backendServices
}

type gwDetails struct {
	FullName types.NamespacedName
	wantErr  bool
}

func runGatewayConformanceTest(t *testing.T, logger *slog.Logger, testName string, gateways []gwDetails, translatorCfg, reconcilerCfg translation.Config, disableServiceImport bool) {
	t.Helper()

	cecTranslator := translation.NewCECTranslator(translatorCfg)
	gatewayAPITranslator := gatewayApiTranslation.NewTranslator(cecTranslator, translatorCfg)
	c := newGatewayConformanceClient(t, testName, disableServiceImport)
	r := &gatewayReconciler{
		Client:     c,
		translator: gatewayAPITranslator,
		cfg:        reconcilerCfg,
		logger:     logger,
	}

	hrList := &gatewayv1.HTTPRouteList{}
	require.NoError(t, c.List(t.Context(), hrList))

	tlsrList := &gatewayv1alpha2.TLSRouteList{}
	require.NoError(t, c.List(t.Context(), tlsrList))

	grpcrList := &gatewayv1.GRPCRouteList{}
	require.NoError(t, c.List(t.Context(), grpcrList))

	btlspList := &gatewayv1.BackendTLSPolicyList{}
	require.NoError(t, c.List(t.Context(), btlspList))

	for _, gwDetail := range gateways {
		result, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: gwDetail.FullName})
		require.Equal(t, gwDetail.wantErr, err != nil, "Got an unexpected reconciliation error for Gateway %s. want: %t, got: %t", gwDetail.FullName.Name, gwDetail.wantErr, err != nil)
		require.Equal(t, ctrl.Result{}, result)

		assertGatewayOutput(t, c, testName, gwDetail)
		if !gwDetail.wantErr {
			assertCECOutput(t, c, testName, gwDetail)
		}
	}

	assertHTTPRoutesOutput(t, c, testName, hrList)
	assertTLSRoutesOutput(t, c, testName, tlsrList)
	assertGRPCRoutesOutput(t, c, testName, grpcrList)
	assertBackendTLSPoliciesOutput(t, c, testName, btlspList)
}

func newGatewayConformanceClient(t *testing.T, testName string, disableServiceImport bool) client.Client {
	t.Helper()

	base := readInputDir(t, "testdata/gateway/base")
	input := readInputDir(t, fmt.Sprintf("testdata/gateway/%s/input", testName))

	clientBuilder := fake.NewClientBuilder().
		WithObjects(append(base, input...)...).
		WithStatusSubresource(&corev1.Service{}).
		WithStatusSubresource(&corev1.Namespace{}).
		WithStatusSubresource(&gatewayv1.GRPCRoute{}).
		WithStatusSubresource(&gatewayv1.HTTPRoute{}).
		WithStatusSubresource(&gatewayv1alpha2.TLSRoute{}).
		WithStatusSubresource(&gatewayv1.Gateway{}).
		WithStatusSubresource(&gatewayv1.GatewayClass{}).
		WithStatusSubresource(&gatewayv1.BackendTLSPolicy{})

	if disableServiceImport {
		clientBuilder.WithScheme(testSchemeNoServiceImport())
	} else {
		clientBuilder.WithScheme(testScheme())
	}

	clientBuilder.WithIndex(&gatewayv1.HTTPRoute{}, indexers.GatewayHTTPRouteIndex, indexers.IndexHTTPRouteByGateway)
	clientBuilder.WithIndex(&gatewayv1.HTTPRoute{}, indexers.BackendServiceHTTPRouteIndex, fakeIndexHTTPRouteByBackendService)
	clientBuilder.WithIndex(&gatewayv1.GRPCRoute{}, indexers.GatewayGRPCRouteIndex, indexers.IndexGRPCRouteByGateway)
	clientBuilder.WithIndex(&gatewayv1alpha2.TLSRoute{}, indexers.GatewayTLSRouteIndex, indexers.IndexTLSRouteByGateway)

	return clientBuilder.Build()
}

func assertGatewayOutput(t *testing.T, c client.Client, testName string, gwDetail gwDetails) {
	t.Helper()

	actualGateway := &gatewayv1.Gateway{}
	err := c.Get(t.Context(), gwDetail.FullName, actualGateway)
	actualGateway.TypeMeta = gatewayTypeMeta
	require.NoError(t, err)

	expectedGateway := &gatewayv1.Gateway{}
	readOutput(t, fmt.Sprintf("testdata/gateway/%s/output/%s.yaml", testName, gwDetail.FullName.Name), expectedGateway)
	require.Empty(t, cmp.Diff(expectedGateway, actualGateway, cmpIgnoreFields...))
}

func assertCECOutput(t *testing.T, c client.Client, testName string, gwDetail gwDetails) {
	t.Helper()

	actualCEC := &ciliumv2.CiliumEnvoyConfig{}
	err := c.Get(t.Context(), client.ObjectKey{
		Namespace: gwDetail.FullName.Namespace,
		Name:      shortener.ShortenK8sResourceName(gatewayApiTranslation.CiliumGatewayPrefix + gwDetail.FullName.Name),
	}, actualCEC)
	require.NoError(t, err, "Could not get CiliumEnvoyConfig and wasn't expecting a reconciliation error")

	expectedCEC := &ciliumv2.CiliumEnvoyConfig{}
	readOutput(t, fmt.Sprintf("testdata/gateway/%s/output/cec-%s.yaml", testName, gwDetail.FullName.Name), expectedCEC)
	require.Empty(t, cmp.Diff(expectedCEC, actualCEC, protocmp.Transform()))
}

func assertHTTPRoutesOutput(t *testing.T, c client.Client, testName string, hrList *gatewayv1.HTTPRouteList) {
	t.Helper()

	for _, hr := range hrList.Items {
		actualHR := &gatewayv1.HTTPRoute{}
		err := c.Get(t.Context(), client.ObjectKeyFromObject(&hr), actualHR)
		actualHR.TypeMeta = httpRouteTypeMeta
		require.NoError(t, err, "error getting HTTPRoute %s/%s: %v", hr.Namespace, hr.Name, err)

		expectedHR := &gatewayv1.HTTPRoute{}
		readOutput(t, fmt.Sprintf("testdata/gateway/%s/output/httproute-%s.yaml", testName, hr.Name), expectedHR)
		require.Empty(t, cmp.Diff(expectedHR, actualHR, cmpIgnoreFields...))
	}
}

func assertTLSRoutesOutput(t *testing.T, c client.Client, testName string, tlsrList *gatewayv1alpha2.TLSRouteList) {
	t.Helper()

	for _, tlsr := range tlsrList.Items {
		actualTLSR := &gatewayv1alpha2.TLSRoute{}
		err := c.Get(t.Context(), client.ObjectKeyFromObject(&tlsr), actualTLSR)
		actualTLSR.TypeMeta = tlsRouteTypeMeta
		require.NoError(t, err, "error getting TLSRoute %s/%s: %v", tlsr.Namespace, tlsr.Name, err)

		expectedTLSR := &gatewayv1alpha2.TLSRoute{}
		readOutput(t, fmt.Sprintf("testdata/gateway/%s/output/tlsroute-%s.yaml", testName, tlsr.Name), expectedTLSR)
		require.Empty(t, cmp.Diff(expectedTLSR, actualTLSR, cmpIgnoreFields...))
	}
}

func assertGRPCRoutesOutput(t *testing.T, c client.Client, testName string, grpcrList *gatewayv1.GRPCRouteList) {
	t.Helper()

	for _, grpcr := range grpcrList.Items {
		actualGRPCR := &gatewayv1.GRPCRoute{}
		err := c.Get(t.Context(), client.ObjectKeyFromObject(&grpcr), actualGRPCR)
		actualGRPCR.TypeMeta = grpcRouteTypeMeta
		require.NoError(t, err, "error getting GRPCRoute %s/%s: %v", grpcr.Namespace, grpcr.Name, err)

		expectedGRPCR := &gatewayv1.GRPCRoute{}
		readOutput(t, fmt.Sprintf("testdata/gateway/%s/output/grpcroute-%s.yaml", testName, grpcr.Name), expectedGRPCR)
		require.Empty(t, cmp.Diff(expectedGRPCR, actualGRPCR, cmpIgnoreFields...))
	}
}

func assertBackendTLSPoliciesOutput(t *testing.T, c client.Client, testName string, btlspList *gatewayv1.BackendTLSPolicyList) {
	t.Helper()

	for _, btlsp := range btlspList.Items {
		actualBTLSP := &gatewayv1.BackendTLSPolicy{}
		err := c.Get(t.Context(), client.ObjectKeyFromObject(&btlsp), actualBTLSP)
		actualBTLSP.TypeMeta = backendTLSPolicyTypeMeta
		require.NoError(t, err, "error getting BackendTLSPolicy %s/%s: %v", btlsp.Namespace, btlsp.Name, err)

		expectedBTLSP := &gatewayv1.BackendTLSPolicy{}
		readOutput(t, fmt.Sprintf("testdata/gateway/%s/output/backendtlspolicy-%s.yaml", testName, btlsp.Name), expectedBTLSP)
		require.Empty(t, cmp.Diff(expectedBTLSP, actualBTLSP, cmpIgnoreFields...))
	}
}

func Test_HostNetwork_Conformance(t *testing.T) {
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

	hostNetworkCfg := translation.Config{
		RouteConfig: translation.RouteConfig{
			HostNameSuffixMatch: true,
		},
		ListenerConfig: translation.ListenerConfig{
			StreamIdleTimeoutSeconds: 300,
		},
		ClusterConfig: translation.ClusterConfig{
			IdleTimeoutSeconds: 60,
		},
		ServiceConfig: translation.ServiceConfig{
			ExternalTrafficPolicy: string(corev1.ServiceExternalTrafficPolicyCluster),
		},
		HostNetworkConfig: translation.HostNetworkConfig{
			Enabled: true,
		},
		IPConfig: translation.IPConfig{
			IPv4Enabled: true,
		},
	}

	reconcilerCfg := hostNetworkCfg

	tests := []struct {
		name    string
		gateway []gwDetails
	}{
		{name: "hostnetwork-node-addresses", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "same-namespace", Namespace: "gateway-conformance-infra"}}}},
		{name: "hostnetwork-all-nodes", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "same-namespace", Namespace: "gateway-conformance-infra"}}}},
		{name: "hostnetwork-internal-ip-fallback", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "same-namespace", Namespace: "gateway-conformance-infra"}}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runGatewayConformanceTest(t, logger, tt.name, tt.gateway, hostNetworkCfg, reconcilerCfg, false)
		})
	}
}

func Test_getNodeAddressesForGateway_HonorsNodeLabelSelectorExpressions(t *testing.T) {
	t.Parallel()

	c := fake.NewClientBuilder().
		WithScheme(testScheme()).
		WithObjects(
			&corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "worker-1",
					Labels: map[string]string{"role": "gateway", "zone": "a"},
				},
				Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeExternalIP, Address: "203.0.113.1"}}},
			},
			&corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "worker-2",
					Labels: map[string]string{"role": "gateway", "zone": "b"},
				},
				Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeExternalIP, Address: "203.0.113.2"}}},
			},
			&corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "worker-3",
					Labels: map[string]string{"role": "other", "zone": "a"},
				},
				Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeExternalIP, Address: "203.0.113.3"}}},
			},
		).
		Build()

	r := &gatewayReconciler{
		Client: c,
		cfg: translation.Config{
			HostNetworkConfig: translation.HostNetworkConfig{
				Enabled: true,
				NodeLabelSelector: &slim_metav1.LabelSelector{
					MatchExpressions: []slim_metav1.LabelSelectorRequirement{{
						Key:      "role",
						Operator: slim_metav1.LabelSelectorOpIn,
						Values:   []string{"gateway"},
					}},
				},
			},
			IPConfig: translation.IPConfig{IPv4Enabled: true},
		},
	}

	ips, err := r.getNodeAddressesForGateway(t.Context())
	require.NoError(t, err)
	assert.Equal(t, []string{"203.0.113.1", "203.0.113.2"}, ips)
}
