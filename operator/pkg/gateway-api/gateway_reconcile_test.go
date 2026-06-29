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
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
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
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/shortener"
)

var (
	gatewayv1APIVersion       = gatewayv1.GroupVersion.Group + "/" + gatewayv1.GroupVersion.Version
	gatewayv1alpha2APIVersion = gatewayv1alpha2.GroupVersion.Group + "/" + gatewayv1alpha2.GroupVersion.Version
	gatewayTypeMeta           = metav1.TypeMeta{
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
	tcpRouteTypeMeta = metav1.TypeMeta{
		Kind:       "TCPRoute",
		APIVersion: gatewayv1alpha2APIVersion,
	}
	udpRouteTypeMeta = metav1.TypeMeta{
		Kind:       "UDPRoute",
		APIVersion: gatewayv1alpha2APIVersion,
	}
	listenerSetTypeMeta = metav1.TypeMeta{
		Kind:       "ListenerSet",
		APIVersion: gatewayv1APIVersion,
	}
	endpointSliceTypeMeta = metav1.TypeMeta{
		Kind:       "EndpointSlice",
		APIVersion: discoveryv1.SchemeGroupVersion.String(),
	}
)

func Test_Conformance(t *testing.T) {
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
	cecTranslator := translation.NewCECTranslator(translation.Config{
		SecretsNamespace: "cilium-secrets",
		RouteConfig: translation.RouteConfig{
			HostNameSuffixMatch: true,
		},
		ListenerConfig: translation.ListenerConfig{
			StreamIdleTimeoutSeconds: 300,
		},
		ClusterConfig: translation.ClusterConfig{
			IdleTimeoutSeconds: 60,
		},
		OriginalIPDetectionConfig: translation.OriginalIPDetectionConfig{
			UseRemoteAddress: true,
		},
	})
	gatewayAPITranslator := gatewayApiTranslation.NewTranslator(cecTranslator, translation.Config{
		ServiceConfig: translation.ServiceConfig{
			ExternalTrafficPolicy: string(corev1.ServiceExternalTrafficPolicyCluster),
		},
		OriginalIPDetectionConfig: translation.OriginalIPDetectionConfig{
			UseRemoteAddress: true,
		},
	})

	type gwDetails struct {
		FullName types.NamespacedName
		wantErr  bool
		skipCEC  bool
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
		disableTCPRoute      bool
		disableUDPRoute      bool
		skipCEC              bool
		wantErr              bool
		hostNetwork          bool
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
		{name: "httproute-cors", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-cross-namespace", gateway: []gwDetails{gatewayBackendNamespace}},
		{
			name:    "httproute-allowed-kind-by-section-name",
			gateway: []gwDetails{{FullName: types.NamespacedName{Name: "kind-restricted-multi-listener", Namespace: "gateway-conformance-infra"}}},
		},
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
		{name: "gateway-multi-port-https", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "multi-port-https", Namespace: "gateway-conformance-infra"}}}},
		{name: "tcproute-invalid-reference-grant", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "gateway-tcproute-referencegrant", Namespace: "gateway-conformance-infra"}, skipCEC: true}}},
		{name: "tcproute-simple-same-namespace", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "gateway-tcproute", Namespace: "gateway-conformance-infra"}, skipCEC: true}}},
		{name: "udproute-invalid-reference-grant", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "gateway-udproute-referencegrant", Namespace: "gateway-conformance-infra"}, skipCEC: true}}},
		{name: "udproute-simple-same-namespace", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "gateway-udproute", Namespace: "gateway-conformance-infra"}, skipCEC: true}}},
		// A single Gateway mixing an L7 (HTTP) and an L4 (TCP) listener: the
		// L7 path produces a CiliumEnvoyConfig while the L4 path produces a
		// managed EndpointSlice for the TCP backend (no dummy slice is added
		// because a real L4 slice already exists).
		{name: "gateway-mixed-http-tcp", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "gateway-mixed", Namespace: "gateway-conformance-infra"}}}},
		{name: "tcproute-crd-not-installed", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "gateway-tcproute", Namespace: "gateway-conformance-infra"}, skipCEC: true}}, disableTCPRoute: true},
		{name: "udproute-crd-not-installed", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "gateway-udproute", Namespace: "gateway-conformance-infra"}, skipCEC: true}}, disableUDPRoute: true},
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
		{name: "tlsroute-mixed-protocol-listeners", gateway: []gwDetails{
			{FullName: types.NamespacedName{Name: "gateway-tlsroute-mixed", Namespace: "gateway-conformance-infra"}},
		}},
		{name: "gateway-multi-port-tls-passthrough", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "multi-port-tls-passthrough", Namespace: "gateway-conformance-infra"}}}},
		{name: "gateway-multi-port-https-with-multi-port-tls-passthrough", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "multi-port-https-with-multi-port-tls-passthrough", Namespace: "gateway-conformance-infra"}}}},
		{name: "gateway-cross-protocol-same-hostname", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "cross-protocol-same-hostname", Namespace: "gateway-conformance-infra"}}}},
		{name: "gateway-cross-protocol-same-port-same-hostname", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "cross-protocol-same-port-same-hostname", Namespace: "gateway-conformance-infra"}, wantErr: true}}},
		{name: "gateway-ns-restricted-same-hostname", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "ns-restricted-same-hostname", Namespace: "gateway-conformance-infra"}}}},
		{name: "hostNetwork-enabled-valid", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "hostnetwork-enabled", Namespace: "gateway-conformance-infra"}}}, hostNetwork: true},
		{name: "hostNetwork-enabled-exceed-max-address", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "hostnetwork-enabled", Namespace: "gateway-conformance-infra"}}}, hostNetwork: true},
		{name: "gatewayclassconfig-nodeport", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "nodeport-gateway", Namespace: "gateway-conformance-infra"}}}},
		// ListenerSet tests
		{name: "listenerset-default-not-allowed", gateway: []gwDetails{
			{FullName: types.NamespacedName{Name: "default-not-allowed", Namespace: "gateway-conformance-infra"}},
		}},
		{name: "listenerset-allowed-namespace-none", gateway: []gwDetails{
			{FullName: types.NamespacedName{Name: "allowed-namespace-none", Namespace: "gateway-conformance-infra"}},
		}},
		{name: "listenerset-allowed-namespace-same", skipCEC: true, gateway: []gwDetails{
			{FullName: types.NamespacedName{Name: "allowed-namespace-same", Namespace: "gateway-conformance-infra"}},
		}},
		{name: "listenerset-allowed-namespace-selector", skipCEC: true, gateway: []gwDetails{
			{FullName: types.NamespacedName{Name: "allowed-namespace-selector", Namespace: "gateway-conformance-infra"}},
		}},
		{name: "listenerset-protocol-conflict", skipCEC: true, gateway: []gwDetails{
			{FullName: types.NamespacedName{Name: "protocol-conflict", Namespace: "gateway-conformance-infra"}},
		}},
		{name: "listenerset-hostname-conflict", skipCEC: true, gateway: []gwDetails{
			{FullName: types.NamespacedName{Name: "hostname-conflict", Namespace: "gateway-conformance-infra"}},
		}},
		{name: "listenerset-cross-listenerset-hostname-conflict", skipCEC: true, gateway: []gwDetails{
			{FullName: types.NamespacedName{Name: "cross-listenerset-hostname-conflict", Namespace: "gateway-conformance-infra"}},
		}},
		{name: "listenerset-cross-listenerset-protocol-conflict", skipCEC: true, gateway: []gwDetails{
			{FullName: types.NamespacedName{Name: "cross-listenerset-protocol-conflict", Namespace: "gateway-conformance-infra"}},
		}},
		{name: "listenerset-allowed-routes-kinds", skipCEC: true, gateway: []gwDetails{
			{FullName: types.NamespacedName{Name: "allowed-route-kinds", Namespace: "gateway-conformance-infra"}},
		}},
		{name: "listenerset-route-hostname-independence", gateway: []gwDetails{
			{FullName: types.NamespacedName{Name: "route-hostname-independence", Namespace: "gateway-conformance-infra"}},
		}},
		{name: "listenerset-valid-with-invalid-gateway-listener", skipCEC: true, gateway: []gwDetails{
			{FullName: types.NamespacedName{Name: "valid-listenerset-only", Namespace: "gateway-conformance-infra"}, wantErr: true},
		}},
		// A Route that targets the Gateway must not leak into a ListenerSet's
		// L4 listeners, even when the Route lives in a namespace the ListenerSet
		// listener would otherwise allow.
		{name: "listenerset-l4-namespace-isolation", skipCEC: true, gateway: []gwDetails{
			{FullName: types.NamespacedName{Name: "l4-namespace-isolation", Namespace: "gateway-conformance-infra"}},
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := readInputDir(t, "testdata/gateway/base")
			input := readInputDir(t, fmt.Sprintf("testdata/gateway/%s/input", tt.name))
			clientBuilder := fake.NewClientBuilder().
				WithObjects(append(base, input...)...).
				WithStatusSubresource(&corev1.Service{}).
				WithStatusSubresource(&corev1.Namespace{}).
				WithStatusSubresource(&gatewayv1.GRPCRoute{}).
				WithStatusSubresource(&gatewayv1.HTTPRoute{}).
				WithStatusSubresource(&gatewayv1.TLSRoute{}).
				WithStatusSubresource(&gatewayv1.Gateway{}).
				WithStatusSubresource(&gatewayv1.GatewayClass{}).
				WithStatusSubresource(&gatewayv1.BackendTLSPolicy{}).
				WithStatusSubresource(&gatewayv1.ListenerSet{})

			disabledKinds := map[string]bool{
				helpers.ServiceImportKind: tt.disableServiceImport,
				helpers.TCPRouteKind:      tt.disableTCPRoute,
				helpers.UDPRouteKind:      tt.disableUDPRoute,
			}
			optionalKinds := make([]schema.GroupVersionKind, 0, len(helpers.AllOptionalKinds))
			for _, k := range helpers.AllOptionalKinds {
				if disabledKinds[k.Kind] {
					continue
				}
				optionalKinds = append(optionalKinds, k)
			}
			clientBuilder.WithScheme(helpers.TestScheme(optionalKinds))

			// Add any required indexes here
			clientBuilder.WithIndex(&gatewayv1.HTTPRoute{}, indexers.GatewayHTTPRouteIndex, indexers.IndexHTTPRouteByGateway)
			clientBuilder.WithIndex(&gatewayv1.HTTPRoute{}, indexers.BackendServiceHTTPRouteIndex, fakeIndexHTTPRouteByBackendService)
			clientBuilder.WithIndex(&gatewayv1.GRPCRoute{}, indexers.GatewayGRPCRouteIndex, indexers.IndexGRPCRouteByGateway)
			clientBuilder.WithIndex(&gatewayv1.TLSRoute{}, indexers.GatewayTLSRouteIndex, indexers.IndexTLSRouteByGateway)
			// TCPRoute/UDPRoute types are only registered in the scheme when their
			// CRDs are installed, so only set their status subresource and index then.
			if !tt.disableTCPRoute {
				clientBuilder.WithStatusSubresource(&gatewayv1alpha2.TCPRoute{})
				clientBuilder.WithIndex(&gatewayv1alpha2.TCPRoute{}, indexers.GatewayTCPRouteIndex, indexers.IndexTCPRouteByGateway)
				clientBuilder.WithIndex(&gatewayv1alpha2.TCPRoute{}, indexers.TCPRouteListenerSetIndex, indexers.IndexTCPRouteByListenerSet)
			}
			if !tt.disableUDPRoute {
				clientBuilder.WithStatusSubresource(&gatewayv1alpha2.UDPRoute{})
				clientBuilder.WithIndex(&gatewayv1alpha2.UDPRoute{}, indexers.GatewayUDPRouteIndex, indexers.IndexUDPRouteByGateway)
				clientBuilder.WithIndex(&gatewayv1alpha2.UDPRoute{}, indexers.UDPRouteListenerSetIndex, indexers.IndexUDPRouteByListenerSet)
			}
			clientBuilder.WithIndex(&gatewayv1.ListenerSet{}, indexers.ListenerSetGatewayIndex, indexers.IndexListenerSetByGateway)
			clientBuilder.WithIndex(&gatewayv1.HTTPRoute{}, indexers.HTTPRouteListenerSetIndex, indexers.IndexHTTPRouteByListenerSet)
			clientBuilder.WithIndex(&gatewayv1.GRPCRoute{}, indexers.GRPCRouteListenerSetIndex, indexers.IndexGRPCRouteByListenerSet)
			clientBuilder.WithIndex(&gatewayv1.TLSRoute{}, indexers.TLSRouteListenerSetIndex, indexers.IndexTLSRouteByListenerSet)

			c := clientBuilder.Build()
			if tt.hostNetwork {
				gatewayAPITranslator = gatewayApiTranslation.NewTranslator(cecTranslator, translation.Config{
					ServiceConfig: translation.ServiceConfig{
						ExternalTrafficPolicy: string(corev1.ServiceExternalTrafficPolicyCluster),
					},
					OriginalIPDetectionConfig: translation.OriginalIPDetectionConfig{
						UseRemoteAddress: true,
					},
					HostNetworkConfig: translation.HostNetworkConfig{
						Enabled: true,
					},
				})
			}
			r := &gatewayReconciler{
				Client:         c,
				translator:     gatewayAPITranslator,
				logger:         logger,
				controllerName: defaultControllerName,
			}

			// Reconcile all related HTTPRoute objects
			hrList := &gatewayv1.HTTPRouteList{}
			err := c.List(t.Context(), hrList)
			require.NoError(t, err)

			// Reconcile all related TLSRoute objects
			tlsrList := &gatewayv1.TLSRouteList{}
			err = c.List(t.Context(), tlsrList)
			require.NoError(t, err)

			// Reconcile all related GRPCRoute objects
			grpcrList := &gatewayv1.GRPCRouteList{}
			err = c.List(t.Context(), grpcrList)
			require.NoError(t, err)

			// Reconcile all BackendTLSPolicy objects
			btlspList := &gatewayv1.BackendTLSPolicyList{}
			err = c.List(t.Context(), btlspList)
			require.NoError(t, err)

			// Reconcile all TCPRoute objects
			tcprList := &gatewayv1alpha2.TCPRouteList{}
			if !tt.disableTCPRoute {
				err = c.List(t.Context(), tcprList)
				require.NoError(t, err)
			}

			// Reconcile all UDPRoute objects
			udprList := &gatewayv1alpha2.UDPRouteList{}
			if !tt.disableUDPRoute {
				err = c.List(t.Context(), udprList)
				require.NoError(t, err)
			}

			for _, gwDetail := range tt.gateway {
				// Reconcile the gateway under test
				result, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: gwDetail.FullName})
				require.Equal(t, gwDetail.wantErr, err != nil, "Got an unexpected reconciliation error for Gateway %s. want: %t, got: %t", gwDetail.FullName.Name, gwDetail.wantErr, err != nil)
				require.Equal(t, ctrl.Result{}, result)
				// Checking the output for Gateway
				actualGateway := &gatewayv1.Gateway{}
				err = c.Get(t.Context(), gwDetail.FullName, actualGateway)
				// TODO(youngnick): controller-runtime has broken something with the fake client
				// Bypass for now
				actualGateway.TypeMeta = gatewayTypeMeta
				require.NoError(t, err)
				expectedGateway := &gatewayv1.Gateway{}
				readOutput(t, fmt.Sprintf("testdata/gateway/%s/output/%s.yaml", tt.name, gwDetail.FullName.Name), expectedGateway)
				require.Empty(t, cmp.Diff(expectedGateway, actualGateway, cmpIgnoreFields...))
				if !gwDetail.wantErr && !gwDetail.skipCEC && !tt.skipCEC {
					// Checking the output for CiliumEnvoyConfig
					actualCEC := &ciliumv2.CiliumEnvoyConfig{}
					err = c.Get(t.Context(), client.ObjectKey{
						Namespace: gwDetail.FullName.Namespace,
						Name:      shortener.ShortenK8sResourceName(gatewayApiTranslation.CiliumGatewayPrefix + gwDetail.FullName.Name),
					}, actualCEC)
					require.NoError(t, err, "Could not get CiliumEnvoyConfig and wasn't expecting a reconciliation error")
					expectedCEC := &ciliumv2.CiliumEnvoyConfig{}
					readOutput(t, fmt.Sprintf("testdata/gateway/%s/output/cec-%s.yaml", tt.name, gwDetail.FullName.Name), expectedCEC)
					require.NoError(t, err)
					require.Empty(t, cmp.Diff(expectedCEC, actualCEC, protocmp.Transform()))
				}

			}

			// Checking the output for EndpointSlices
			epsList := &discoveryv1.EndpointSliceList{}
			err = c.List(t.Context(), epsList, client.MatchingLabels{
				gatewayApiTranslation.EndpointSliceManagedByLabel: gatewayApiTranslation.EndpointSliceManagedByValue,
			})
			require.NoError(t, err)
			for _, eps := range epsList.Items {
				actualEPS := &discoveryv1.EndpointSlice{}
				err = c.Get(t.Context(), client.ObjectKeyFromObject(&eps), actualEPS)
				actualEPS.TypeMeta = endpointSliceTypeMeta
				require.NoError(t, err, "error getting EndpointSlice %s/%s: %v", eps.Namespace, eps.Name, err)
				expectedEPS := &discoveryv1.EndpointSlice{}
				readOutput(t, fmt.Sprintf("testdata/gateway/%s/output/endpointslice-%s.yaml", tt.name, eps.Name), expectedEPS)
				require.Empty(t, cmp.Diff(expectedEPS, actualEPS, cmpIgnoreFields...))
			}

			// Checking the output for related HTTPRoute objects
			for _, hr := range hrList.Items {
				actualHR := &gatewayv1.HTTPRoute{}
				err = c.Get(t.Context(), client.ObjectKeyFromObject(&hr), actualHR)
				// TODO(youngnick): controller-runtime has broken something with the fake client
				// Bypass for now
				actualHR.TypeMeta = httpRouteTypeMeta
				require.NoError(t, err, "error getting HTTPRoute %s/%s: %v", hr.Namespace, hr.Name, err)
				expectedHR := &gatewayv1.HTTPRoute{}
				readOutput(t, fmt.Sprintf("testdata/gateway/%s/output/httproute-%s.yaml", tt.name, hr.Name), expectedHR)
				require.Empty(t, cmp.Diff(expectedHR, actualHR, cmpIgnoreFields...))
			}

			for _, tlsr := range tlsrList.Items {
				actualTLSR := &gatewayv1.TLSRoute{}
				err = c.Get(t.Context(), client.ObjectKeyFromObject(&tlsr), actualTLSR)
				actualTLSR.TypeMeta = tlsRouteTypeMeta
				require.NoError(t, err, "error getting TLSRoute %s/%s: %v", tlsr.Namespace, tlsr.Name, err)
				expectedTLSR := &gatewayv1.TLSRoute{}
				readOutput(t, fmt.Sprintf("testdata/gateway/%s/output/tlsroute-%s.yaml", tt.name, tlsr.Name), expectedTLSR)
				require.Empty(t, cmp.Diff(expectedTLSR, actualTLSR, cmpIgnoreFields...))
			}

			for _, grpcr := range grpcrList.Items {
				actualGRPCR := &gatewayv1.GRPCRoute{}
				err = c.Get(t.Context(), client.ObjectKeyFromObject(&grpcr), actualGRPCR)
				actualGRPCR.TypeMeta = grpcRouteTypeMeta
				require.NoError(t, err, "error getting GRPCRoute %s/%s: %v", grpcr.Namespace, grpcr.Name, err)
				expectedGRPCR := &gatewayv1.GRPCRoute{}
				readOutput(t, fmt.Sprintf("testdata/gateway/%s/output/grpcroute-%s.yaml", tt.name, grpcr.Name), expectedGRPCR)
				require.Empty(t, cmp.Diff(expectedGRPCR, actualGRPCR, cmpIgnoreFields...))
			}

			for _, btlsp := range btlspList.Items {
				actualBTLSP := &gatewayv1.BackendTLSPolicy{}
				err = c.Get(t.Context(), client.ObjectKeyFromObject(&btlsp), actualBTLSP)
				actualBTLSP.TypeMeta = backendTLSPolicyTypeMeta
				require.NoError(t, err, "error getting BackendTLSPolicy %s/%s: %v", btlsp.Namespace, btlsp.Name, err)
				expectedBTLSP := &gatewayv1.BackendTLSPolicy{}
				readOutput(t, fmt.Sprintf("testdata/gateway/%s/output/backendtlspolicy-%s.yaml", tt.name, btlsp.Name), expectedBTLSP)
				require.Empty(t, cmp.Diff(expectedBTLSP, actualBTLSP, cmpIgnoreFields...))
			}

			for _, tcpr := range tcprList.Items {
				actualTCPR := &gatewayv1alpha2.TCPRoute{}
				err = c.Get(t.Context(), client.ObjectKeyFromObject(&tcpr), actualTCPR)
				actualTCPR.TypeMeta = tcpRouteTypeMeta
				require.NoError(t, err, "error getting TCPRoute %s/%s: %v", tcpr.Namespace, tcpr.Name, err)
				expectedTCPR := &gatewayv1alpha2.TCPRoute{}
				readOutput(t, fmt.Sprintf("testdata/gateway/%s/output/tcproute-%s.yaml", tt.name, tcpr.Name), expectedTCPR)
				require.Empty(t, cmp.Diff(expectedTCPR, actualTCPR, cmpIgnoreFields...))
			}

			for _, udpr := range udprList.Items {
				actualUDPR := &gatewayv1alpha2.UDPRoute{}
				err = c.Get(t.Context(), client.ObjectKeyFromObject(&udpr), actualUDPR)
				actualUDPR.TypeMeta = udpRouteTypeMeta
				require.NoError(t, err, "error getting UDPRoute %s/%s: %v", udpr.Namespace, udpr.Name, err)
				expectedUDPR := &gatewayv1alpha2.UDPRoute{}
				readOutput(t, fmt.Sprintf("testdata/gateway/%s/output/udproute-%s.yaml", tt.name, udpr.Name), expectedUDPR)
				require.Empty(t, cmp.Diff(expectedUDPR, actualUDPR, cmpIgnoreFields...))
			}

			lsList := &gatewayv1.ListenerSetList{}
			err = c.List(t.Context(), lsList)
			require.NoError(t, err)
			for _, ls := range lsList.Items {
				actualLS := &gatewayv1.ListenerSet{}
				err = c.Get(t.Context(), client.ObjectKeyFromObject(&ls), actualLS)
				actualLS.TypeMeta = listenerSetTypeMeta
				require.NoError(t, err, "error getting ListenerSet %s/%s: %v", ls.Namespace, ls.Name, err)
				expectedLS := &gatewayv1.ListenerSet{}
				readOutput(t, fmt.Sprintf("testdata/gateway/%s/output/listenerset-%s.yaml", tt.name, ls.Name), expectedLS)
				require.Empty(t, cmp.Diff(expectedLS, actualLS, cmpIgnoreFields...))
			}
		})
	}
}

func Test_grpcWebTranslationEnabled(t *testing.T) {
	tests := []struct {
		name   string
		config *v2alpha1.CiliumGatewayClassConfig
		want   bool
	}{
		{
			name: "nil config",
			want: true,
		},
		{
			name:   "empty config",
			config: &v2alpha1.CiliumGatewayClassConfig{},
			want:   true,
		},
		{
			name: "nil enabled",
			config: &v2alpha1.CiliumGatewayClassConfig{
				Spec: v2alpha1.CiliumGatewayClassConfigSpec{
					HTTPOptions: &v2alpha1.HTTPOptions{
						GRPCWebTranslation: &v2alpha1.GRPCWebTranslationConfig{},
					},
				},
			},
			want: true,
		},
		{
			name: "explicitly enabled",
			config: &v2alpha1.CiliumGatewayClassConfig{
				Spec: v2alpha1.CiliumGatewayClassConfigSpec{
					HTTPOptions: &v2alpha1.HTTPOptions{
						GRPCWebTranslation: &v2alpha1.GRPCWebTranslationConfig{
							Enabled: ptr.To(true),
						},
					},
				},
			},
			want: true,
		},
		{
			name: "disabled",
			config: &v2alpha1.CiliumGatewayClassConfig{
				Spec: v2alpha1.CiliumGatewayClassConfigSpec{
					HTTPOptions: &v2alpha1.HTTPOptions{
						GRPCWebTranslation: &v2alpha1.GRPCWebTranslationConfig{
							Enabled: ptr.To(false),
						},
					},
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.config.GRPCWebTranslationEnabled())
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
				WithScheme(helpers.TestScheme(helpers.AllOptionalKinds)).
				WithObjects(objects...).
				Build()

			r := &gatewayReconciler{
				Client:         c,
				logger:         hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug)),
				controllerName: defaultControllerName,
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

// Test_gatewayReconciler_ensureEnvoyConfig_deletesStaleCEC verifies that a
// CiliumEnvoyConfig left over from a previous HTTP/TLS state is cleaned up when
// the Gateway no longer needs Envoy (e.g. it switches to pure L4 TCP/UDP
// Routes, so the translator returns a nil desired CEC).
func Test_gatewayReconciler_ensureEnvoyConfig_deletesStaleCEC(t *testing.T) {
	t.Parallel()

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "l4-gateway",
			Namespace: "default",
			UID:       types.UID("gateway-uid"),
		},
	}

	cecKey := types.NamespacedName{
		Namespace: gw.Namespace,
		Name:      shortener.ShortenK8sResourceName(gatewayApiTranslation.CiliumGatewayPrefix + gw.Name),
	}

	ownedCEC := func() *ciliumv2.CiliumEnvoyConfig {
		return &ciliumv2.CiliumEnvoyConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cecKey.Name,
				Namespace: cecKey.Namespace,
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
	}

	t.Run("deletes owned stale CEC when desired is nil", func(t *testing.T) {
		c := fake.NewClientBuilder().
			WithScheme(helpers.TestScheme(helpers.AllOptionalKinds)).
			WithObjects(gw, ownedCEC()).
			Build()
		r := &gatewayReconciler{
			Client: c,
			logger: hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug)),
		}

		require.NoError(t, r.ensureEnvoyConfig(t.Context(), gw, nil))

		err := c.Get(t.Context(), cecKey, &ciliumv2.CiliumEnvoyConfig{})
		require.ErrorContains(t, err, "not found")
	})

	t.Run("keeps CEC not owned by the Gateway", func(t *testing.T) {
		foreign := ownedCEC()
		foreign.OwnerReferences[0].UID = types.UID("other-uid")
		foreign.OwnerReferences[0].Name = "other-gateway"
		c := fake.NewClientBuilder().
			WithScheme(helpers.TestScheme(helpers.AllOptionalKinds)).
			WithObjects(gw, foreign).
			Build()
		r := &gatewayReconciler{
			Client: c,
			logger: hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug)),
		}

		require.NoError(t, r.ensureEnvoyConfig(t.Context(), gw, nil))

		require.NoError(t, c.Get(t.Context(), cecKey, &ciliumv2.CiliumEnvoyConfig{}))
	})

	t.Run("no error when no CEC exists", func(t *testing.T) {
		c := fake.NewClientBuilder().
			WithScheme(helpers.TestScheme(helpers.AllOptionalKinds)).
			WithObjects(gw).
			Build()
		r := &gatewayReconciler{
			Client: c,
			logger: hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug)),
		}

		require.NoError(t, r.ensureEnvoyConfig(t.Context(), gw, nil))
	})
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
			assert.Equalf(t, tt.want, parentRefMatched(gw, tt.args.listener, nil, "default", tt.args.refs), "parentRefMatched(%v, %v, %v, %v)", gw, tt.args.listener, tt.args.routeNamespace, tt.args.refs)
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
			backendServices = append(
				backendServices,
				types.NamespacedName{
					Namespace: namespace,
					Name:      string(backend.Name),
				}.String(),
			)
		}
	}
	return backendServices
}
