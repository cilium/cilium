// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
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
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/loading"
	"github.com/cilium/cilium/operator/pkg/model/translation"
	gatewayApiTranslation "github.com/cilium/cilium/operator/pkg/model/translation/gateway-api"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/shortener"
)

func typeMetaInterceptor(scheme *runtime.Scheme) interceptor.Funcs {
	setTypeMeta := func(obj runtime.Object) error {
		if _, isCEC := obj.(*ciliumv2.CiliumEnvoyConfig); isCEC {
			return nil
		}
		gvks, _, err := scheme.ObjectKinds(obj)
		if err != nil {
			return err
		}
		obj.GetObjectKind().SetGroupVersionKind(gvks[0])
		return nil
	}

	return interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if err := c.Get(ctx, key, obj, opts...); err != nil {
				return err
			}
			return setTypeMeta(obj)
		},
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if err := c.List(ctx, list, opts...); err != nil {
				return err
			}
			if err := setTypeMeta(list); err != nil {
				return err
			}
			return meta.EachListItem(list, setTypeMeta)
		},
	}
}

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
			name: "gateway-invalid-parameters-ref",
			gateway: []gwDetails{
				{FullName: types.NamespacedName{Name: "gateway-invalid-parameters-ref", Namespace: "gateway-conformance-infra"}, wantErr: true},
			},
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
		{name: "httproute-identical-rule-order", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-identical-rule-invalid-backend", gateway: []gwDetails{gatewaySameNamespace}},
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
		{name: "gatewayclassconfig-nodeport", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "nodeport-gateway", Namespace: "gateway-conformance-infra"}}}},
		{name: "hostNetwork-enabled-valid", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "hostnetwork-enabled", Namespace: "gateway-conformance-infra"}}}, hostNetwork: true},
		{name: "hostNetwork-enabled-exceed-max-address", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "hostnetwork-enabled", Namespace: "gateway-conformance-infra"}}}, hostNetwork: true},
		{name: "hostNetwork-enabled-no-l4-listeners", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "host-networking", Namespace: "gateway-conformance-infra"}}}, hostNetwork: true},
		{name: "hostNetwork-enabled-mixed-routes", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "host-networking", Namespace: "gateway-conformance-infra"}}}, hostNetwork: true},
		{name: "hostNetwork-enabled-tcp-route", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "host-networking", Namespace: "gateway-conformance-infra"}, wantErr: true, skipCEC: true}}, hostNetwork: true},
		{name: "hostNetwork-enabled-udp-route", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "host-networking", Namespace: "gateway-conformance-infra"}, wantErr: true, skipCEC: true}}, hostNetwork: true},
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
		{name: "listenerset-tls-protocol-conflict", gateway: []gwDetails{
			{FullName: types.NamespacedName{Name: "tls-protocol-conflict", Namespace: "gateway-conformance-infra"}},
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
			scheme := helpers.TestScheme(optionalKinds)
			clientBuilder := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(append(base, input...)...).
				WithStatusSubresource(&corev1.Service{}).
				WithStatusSubresource(&corev1.Namespace{}).
				WithStatusSubresource(&gatewayv1.GRPCRoute{}).
				WithStatusSubresource(&gatewayv1.HTTPRoute{}).
				WithStatusSubresource(&gatewayv1.TLSRoute{}).
				WithStatusSubresource(&gatewayv1.Gateway{}).
				WithStatusSubresource(&gatewayv1.GatewayClass{}).
				WithStatusSubresource(&gatewayv1.BackendTLSPolicy{}).
				WithStatusSubresource(&gatewayv1.ListenerSet{}).
				WithInterceptorFuncs(typeMetaInterceptor(scheme))

			// Add any required indexes here
			clientBuilder.WithIndex(&gatewayv1.HTTPRoute{}, indexers.GatewayHTTPRouteIndex, indexers.IndexHTTPRouteByGateway)
			clientBuilder.WithIndex(&gatewayv1.HTTPRoute{}, indexers.BackendServiceHTTPRouteIndex, fakeIndexHTTPRouteByBackendService)
			clientBuilder.WithIndex(&gatewayv1.GRPCRoute{}, indexers.GatewayGRPCRouteIndex, indexers.IndexGRPCRouteByGateway)
			clientBuilder.WithIndex(&gatewayv1.TLSRoute{}, indexers.GatewayTLSRouteIndex, indexers.IndexTLSRouteByGateway)
			// TCPRoute/UDPRoute types are only registered in the scheme when their
			// CRDs are installed, so only set their status subresource and index then.
			if !tt.disableTCPRoute {
				clientBuilder.WithStatusSubresource(&gatewayv1.TCPRoute{})
				clientBuilder.WithIndex(&gatewayv1.TCPRoute{}, indexers.GatewayTCPRouteIndex, indexers.IndexTCPRouteByGateway)
				clientBuilder.WithIndex(&gatewayv1.TCPRoute{}, indexers.TCPRouteListenerSetIndex, indexers.IndexTCPRouteByListenerSet)
			}
			if !tt.disableUDPRoute {
				clientBuilder.WithStatusSubresource(&gatewayv1.UDPRoute{})
				clientBuilder.WithIndex(&gatewayv1.UDPRoute{}, indexers.GatewayUDPRouteIndex, indexers.IndexUDPRouteByGateway)
				clientBuilder.WithIndex(&gatewayv1.UDPRoute{}, indexers.UDPRouteListenerSetIndex, indexers.IndexUDPRouteByListenerSet)
			}
			clientBuilder.WithIndex(&gatewayv1.ListenerSet{}, indexers.ListenerSetGatewayIndex, indexers.IndexListenerSetByGateway)
			clientBuilder.WithIndex(&gatewayv1.HTTPRoute{}, indexers.HTTPRouteListenerSetIndex, indexers.IndexHTTPRouteByListenerSet)
			clientBuilder.WithIndex(&gatewayv1.GRPCRoute{}, indexers.GRPCRouteListenerSetIndex, indexers.IndexGRPCRouteByListenerSet)
			clientBuilder.WithIndex(&gatewayv1.TLSRoute{}, indexers.TLSRouteListenerSetIndex, indexers.IndexTLSRouteByListenerSet)

			c := clientBuilder.Build()
			gatewayAPITranslator := gatewayApiTranslation.NewTranslator(cecTranslator, translation.Config{
				ServiceConfig: translation.ServiceConfig{
					ExternalTrafficPolicy: string(corev1.ServiceExternalTrafficPolicyCluster),
				},
				OriginalIPDetectionConfig: translation.OriginalIPDetectionConfig{
					UseRemoteAddress: true,
				},
				HostNetworkConfig: translation.HostNetworkConfig{
					Enabled: tt.hostNetwork,
				},
			})

			r := &gatewayReconciler{
				Client:     c,
				Scheme:     c.Scheme(),
				translator: gatewayAPITranslator,
				inputLoader: loading.NewTranslationInputLoader(c, logger, defaultControllerName, loading.TranslationInputLoaderConfig{
					IncludeTCPRoutes:      !tt.disableTCPRoute,
					IncludeUDPRoutes:      !tt.disableUDPRoute,
					IncludeServiceImports: helpers.HasServiceImportSupport(c.Scheme()),
					IncludeListenerSets:   helpers.HasListenerSetSupport(c.Scheme()),
				}),
				listenerStatusManager: NewListenerStatusManager(c, logger, ListenerStatusManagerConfig{
					TCPUDPRouteSupport:      !tt.hostNetwork,
					TCPUDPUnsupportedReason: hostNetworkTCPUDPRouteUnsupportedReason,
				}),
				routeStatusManager: NewRouteStatusManager(c, logger, defaultControllerName, RouteStatusManagerConfig{
					IncludeTCPRoutes:        !tt.disableTCPRoute,
					IncludeUDPRoutes:        !tt.disableUDPRoute,
					TCPUDPRouteSupport:      !tt.hostNetwork,
					TCPUDPUnsupportedReason: hostNetworkTCPUDPRouteUnsupportedReason,
				}),
				backendTLSPolicyStatusManager: NewBackendTLSPolicyStatusManager(c, defaultControllerName),
				logger:                        logger,
				controllerName:                defaultControllerName,
				tcpUDPRouteSupport:            !tt.hostNetwork,
				tcpUDPUnsupportedReason:       hostNetworkTCPUDPRouteUnsupportedReason,
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
			tcprList := &gatewayv1.TCPRouteList{}
			if !tt.disableTCPRoute {
				err = c.List(t.Context(), tcprList)
				require.NoError(t, err)
			}

			// Reconcile all UDPRoute objects
			udprList := &gatewayv1.UDPRouteList{}
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
				require.NoError(t, err, "error getting EndpointSlice %s/%s: %v", eps.Namespace, eps.Name, err)
				expectedEPS := &discoveryv1.EndpointSlice{}
				readOutput(t, fmt.Sprintf("testdata/gateway/%s/output/endpointslice-%s.yaml", tt.name, eps.Name), expectedEPS)
				require.Empty(t, cmp.Diff(expectedEPS, actualEPS, cmpIgnoreFields...))
			}

			// Checking the output for related HTTPRoute objects
			for _, hr := range hrList.Items {
				actualHR := &gatewayv1.HTTPRoute{}
				err = c.Get(t.Context(), client.ObjectKeyFromObject(&hr), actualHR)
				require.NoError(t, err, "error getting HTTPRoute %s/%s: %v", hr.Namespace, hr.Name, err)
				expectedHR := &gatewayv1.HTTPRoute{}
				readOutput(t, fmt.Sprintf("testdata/gateway/%s/output/httproute-%s.yaml", tt.name, hr.Name), expectedHR)
				require.Empty(t, cmp.Diff(expectedHR, actualHR, cmpIgnoreFields...))
			}

			for _, tlsr := range tlsrList.Items {
				actualTLSR := &gatewayv1.TLSRoute{}
				err = c.Get(t.Context(), client.ObjectKeyFromObject(&tlsr), actualTLSR)
				require.NoError(t, err, "error getting TLSRoute %s/%s: %v", tlsr.Namespace, tlsr.Name, err)
				expectedTLSR := &gatewayv1.TLSRoute{}
				readOutput(t, fmt.Sprintf("testdata/gateway/%s/output/tlsroute-%s.yaml", tt.name, tlsr.Name), expectedTLSR)
				require.Empty(t, cmp.Diff(expectedTLSR, actualTLSR, cmpIgnoreFields...))
			}

			for _, grpcr := range grpcrList.Items {
				actualGRPCR := &gatewayv1.GRPCRoute{}
				err = c.Get(t.Context(), client.ObjectKeyFromObject(&grpcr), actualGRPCR)
				require.NoError(t, err, "error getting GRPCRoute %s/%s: %v", grpcr.Namespace, grpcr.Name, err)
				expectedGRPCR := &gatewayv1.GRPCRoute{}
				readOutput(t, fmt.Sprintf("testdata/gateway/%s/output/grpcroute-%s.yaml", tt.name, grpcr.Name), expectedGRPCR)
				require.Empty(t, cmp.Diff(expectedGRPCR, actualGRPCR, cmpIgnoreFields...))
			}

			for _, btlsp := range btlspList.Items {
				actualBTLSP := &gatewayv1.BackendTLSPolicy{}
				err = c.Get(t.Context(), client.ObjectKeyFromObject(&btlsp), actualBTLSP)
				require.NoError(t, err, "error getting BackendTLSPolicy %s/%s: %v", btlsp.Namespace, btlsp.Name, err)
				expectedBTLSP := &gatewayv1.BackendTLSPolicy{}
				readOutput(t, fmt.Sprintf("testdata/gateway/%s/output/backendtlspolicy-%s.yaml", tt.name, btlsp.Name), expectedBTLSP)
				require.Empty(t, cmp.Diff(expectedBTLSP, actualBTLSP, cmpIgnoreFields...))
			}

			for _, tcpr := range tcprList.Items {
				actualTCPR := &gatewayv1.TCPRoute{}
				err = c.Get(t.Context(), client.ObjectKeyFromObject(&tcpr), actualTCPR)
				require.NoError(t, err, "error getting TCPRoute %s/%s: %v", tcpr.Namespace, tcpr.Name, err)
				expectedTCPR := &gatewayv1.TCPRoute{}
				readOutput(t, fmt.Sprintf("testdata/gateway/%s/output/tcproute-%s.yaml", tt.name, tcpr.Name), expectedTCPR)
				require.Empty(t, cmp.Diff(expectedTCPR, actualTCPR, cmpIgnoreFields...))
			}

			for _, udpr := range udprList.Items {
				actualUDPR := &gatewayv1.UDPRoute{}
				err = c.Get(t.Context(), client.ObjectKeyFromObject(&udpr), actualUDPR)
				require.NoError(t, err, "error getting UDPRoute %s/%s: %v", udpr.Namespace, udpr.Name, err)
				expectedUDPR := &gatewayv1.UDPRoute{}
				readOutput(t, fmt.Sprintf("testdata/gateway/%s/output/udproute-%s.yaml", tt.name, udpr.Name), expectedUDPR)
				require.Empty(t, cmp.Diff(expectedUDPR, actualUDPR, cmpIgnoreFields...))
			}

			lsList := &gatewayv1.ListenerSetList{}
			err = c.List(t.Context(), lsList)
			require.NoError(t, err)
			for _, ls := range lsList.Items {
				actualLS := &gatewayv1.ListenerSet{}
				err = c.Get(t.Context(), client.ObjectKeyFromObject(&ls), actualLS)
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

func Test_isAccessLogsConfigured(t *testing.T) {
	tests := []struct {
		name   string
		config *v2alpha1.Telemetry
		want   bool
	}{
		{
			name: "nil config",
			want: false,
		},
		{
			name:   "empty config",
			config: &v2alpha1.Telemetry{},
			want:   false,
		},
		{
			name:   "telemetry without access logs",
			config: &v2alpha1.Telemetry{},
			want:   false,
		},
		{
			name: "empty access logs",
			config: &v2alpha1.Telemetry{
				AccessLogs: []v2alpha1.AccessLogs{},
			},
			want: false,
		},
		{
			name: "access logs",
			config: &v2alpha1.Telemetry{
				AccessLogs: []v2alpha1.AccessLogs{
					{
						Format: v2alpha1.AccessLogsFormatText,
						Text:   "%REQ(:METHOD)%",
					},
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.config.IsAccessLogsConfigured())
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
					// Ensure handoff cleanup takes precedence over Gateway validation.
					Infrastructure: &gatewayv1.GatewayInfrastructure{
						ParametersRef: &gatewayv1.LocalParametersReference{
							Group: gatewayv1.Group("invalid.io"),
							Kind:  gatewayv1.Kind("InvalidParameters"),
							Name:  "invalid",
						},
					},
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
				Client: c,
				Scheme: c.Scheme(),
				inputLoader: loading.NewTranslationInputLoader(c, hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug)), defaultControllerName, loading.TranslationInputLoaderConfig{
					IncludeTCPRoutes:      helpers.HasTCPRouteSupport(c.Scheme()),
					IncludeUDPRoutes:      helpers.HasUDPRouteSupport(c.Scheme()),
					IncludeServiceImports: helpers.HasServiceImportSupport(c.Scheme()),
					IncludeListenerSets:   helpers.HasListenerSetSupport(c.Scheme()),
				}),
				listenerStatusManager: NewListenerStatusManager(c, hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug)), ListenerStatusManagerConfig{
					TCPUDPRouteSupport:      true,
					TCPUDPUnsupportedReason: hostNetworkTCPUDPRouteUnsupportedReason,
				}),
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

func Test_gatewayReconciler_setListenerStatus(t *testing.T) {
	tests := []struct {
		name          string
		listeners     []gatewayv1.Listener
		wantStatus    ListenersStatus
		wantListeners map[gatewayv1.SectionName]metav1.Condition
	}{
		{
			name: "all listeners valid",
			listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
				{
					Name:     "https",
					Port:     443,
					Protocol: gatewayv1.HTTPSProtocolType,
					TLS: &gatewayv1.ListenerTLSConfig{
						Mode: ptr.To(gatewayv1.TLSModeTerminate),
					},
				},
			},
			wantStatus: ListenersStatusAllValid,
			wantListeners: map[gatewayv1.SectionName]metav1.Condition{
				"http": {
					Type:   string(gatewayv1.ListenerConditionAccepted),
					Status: metav1.ConditionTrue,
					Reason: string(gatewayv1.ListenerReasonAccepted),
				},
				"https": {
					Type:   string(gatewayv1.ListenerConditionAccepted),
					Status: metav1.ConditionTrue,
					Reason: string(gatewayv1.ListenerReasonAccepted),
				},
			},
		},
		{
			name: "only unsupported protocol",
			listeners: []gatewayv1.Listener{{
				Name:     "invalid",
				Port:     1111,
				Protocol: gatewayv1.ProtocolType("INVALID"),
			}},
			wantStatus: ListenersStatusNoneValid,
			wantListeners: map[gatewayv1.SectionName]metav1.Condition{
				"invalid": {
					Type:   string(gatewayv1.ListenerConditionAccepted),
					Status: metav1.ConditionFalse,
					Reason: string(gatewayv1.ListenerReasonUnsupportedProtocol),
				},
			},
		},
		{
			name: "valid listener with unsupported protocol listener",
			listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
				{
					Name:     "invalid",
					Port:     1111,
					Protocol: gatewayv1.ProtocolType("INVALID"),
				},
			},
			wantStatus: ListenersStatusValidWithUnsupportedProtocol,
			wantListeners: map[gatewayv1.SectionName]metav1.Condition{
				"http": {
					Type:   string(gatewayv1.ListenerConditionAccepted),
					Status: metav1.ConditionTrue,
					Reason: string(gatewayv1.ListenerReasonAccepted),
				},
				"invalid": {
					Type:   string(gatewayv1.ListenerConditionAccepted),
					Status: metav1.ConditionFalse,
					Reason: string(gatewayv1.ListenerReasonUnsupportedProtocol),
				},
			},
		},
		{
			name: "valid listener with invalid route kind listener",
			listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
				{
					Name:     "invalid-route-kind",
					Port:     81,
					Protocol: gatewayv1.HTTPProtocolType,
					AllowedRoutes: &gatewayv1.AllowedRoutes{
						Kinds: []gatewayv1.RouteGroupKind{{
							Kind: "InvalidRouteKind",
						}},
					},
				},
			},
			wantStatus: ListenersStatusSomeInvalid,
			wantListeners: map[gatewayv1.SectionName]metav1.Condition{
				"http": {
					Type:   string(gatewayv1.ListenerConditionAccepted),
					Status: metav1.ConditionTrue,
					Reason: string(gatewayv1.ListenerReasonAccepted),
				},
				"invalid-route-kind": {
					Type:   string(gatewayv1.ListenerConditionAccepted),
					Status: metav1.ConditionFalse,
					Reason: string(gatewayv1.ListenerReasonInvalid),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "gateway",
					Namespace:  "gateway-conformance-infra",
					Generation: 1,
				},
				Spec: gatewayv1.GatewaySpec{
					GatewayClassName: "cilium",
					Listeners:        tt.listeners,
				},
			}

			r := &gatewayReconciler{
				Client: func() client.WithWatch {
					return fake.NewClientBuilder().
						WithScheme(helpers.TestScheme(helpers.AllOptionalKinds)).
						Build()
				}(),
			}
			r.listenerStatusManager = NewListenerStatusManager(r.Client, hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug)), ListenerStatusManagerConfig{
				TCPUDPRouteSupport:      true,
				TCPUDPUnsupportedReason: hostNetworkTCPUDPRouteUnsupportedReason,
			})
			gotStatus, err := r.listenerStatusManager.setGatewayListenerStatus(
				t.Context(),
				gw,
				nil,
				nil,
				nil,
				nil,
				nil,
				nil,
				nil,
				helpers.NewNamespaceLabelIndex(nil),
			)
			require.NoError(t, err)
			require.Equal(t, tt.wantStatus, gotStatus)

			for name, wantCond := range tt.wantListeners {
				gotCond := listenerStatusCondition(t, gw.Status.Listeners, name, string(gatewayv1.ListenerConditionAccepted))
				require.Equal(t, wantCond.Status, gotCond.Status)
				require.Equal(t, wantCond.Reason, gotCond.Reason)
			}
		})
	}
}

func Test_gatewayReconciler_setAddressStatus_updatesAcceptedListenerProgrammedCondition(t *testing.T) {
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "gateway",
			Namespace:  "gateway-conformance-infra",
			Generation: 7,
		},
		Status: gatewayv1.GatewayStatus{
			Listeners: []gatewayv1.ListenerStatus{
				{
					Name: "http",
					Conditions: []metav1.Condition{
						{
							Type:               string(gatewayv1.ListenerConditionAccepted),
							Status:             metav1.ConditionTrue,
							Reason:             string(gatewayv1.ListenerReasonAccepted),
							ObservedGeneration: 7,
						},
					},
				},
			},
		},
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gateway-service",
			Namespace: gw.Namespace,
			Labels: map[string]string{
				owningGatewayLabel: shortener.ShortenK8sResourceName(gw.Name),
			},
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeLoadBalancer,
		},
		Status: corev1.ServiceStatus{
			LoadBalancer: corev1.LoadBalancerStatus{
				Ingress: []corev1.LoadBalancerIngress{
					{IP: "192.0.2.10"},
				},
			},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(helpers.TestScheme(helpers.AllOptionalKinds)).
		WithObjects(svc).
		Build()

	r := &gatewayReconciler{
		Client: c,
		logger: hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug)),
	}

	require.NoError(t, r.setAddressStatus(t.Context(), gw))

	require.Len(t, gw.Status.Addresses, 1)
	require.Equal(t, "192.0.2.10", gw.Status.Addresses[0].Value)

	programmed := listenerStatusCondition(t, gw.Status.Listeners, "http", string(gatewayv1.ListenerConditionProgrammed))
	require.Equal(t, metav1.ConditionTrue, programmed.Status)
	require.Equal(t, string(gatewayv1.ListenerReasonProgrammed), programmed.Reason)
	require.Equal(t, int64(7), programmed.ObservedGeneration)
}

func listenerStatusCondition(t *testing.T, listeners []gatewayv1.ListenerStatus, name gatewayv1.SectionName, conditionType string) metav1.Condition {
	t.Helper()

	for _, listener := range listeners {
		if listener.Name != name {
			continue
		}
		for _, cond := range listener.Conditions {
			if cond.Type == conditionType {
				return cond
			}
		}
		require.Failf(t, "missing listener condition", "listener %q condition %q not found", name, conditionType)
	}

	require.Failf(t, "missing listener status", "listener %q not found", name)
	return metav1.Condition{}
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
		for _, f := range rule.Filters {
			if f.Type != gatewayv1.HTTPRouteFilterRequestMirror || f.RequestMirror == nil {
				continue
			}
			if !helpers.IsService(f.RequestMirror.BackendRef) {
				continue
			}
			namespace := helpers.NamespaceDerefOr(f.RequestMirror.BackendRef.Namespace, route.Namespace)
			backendServices = append(
				backendServices,
				types.NamespacedName{
					Namespace: namespace,
					Name:      string(f.RequestMirror.BackendRef.Name),
				}.String(),
			)
		}
	}
	return backendServices
}

func testReconciler(t *testing.T, obj ...client.Object) (*gatewayReconciler, client.WithWatch) {
	t.Helper()

	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

	fakeClient := fake.NewClientBuilder().
		WithScheme(helpers.TestScheme(helpers.AllOptionalKinds)).
		WithObjects(obj...).
		WithStatusSubresource(&gatewayv1.HTTPRoute{}, &gatewayv1.GRPCRoute{}).
		Build()

	reconciler := &gatewayReconciler{
		Client:                  fakeClient,
		logger:                  logger,
		controllerName:          defaultControllerName,
		tcpUDPRouteSupport:      true,
		tcpUDPUnsupportedReason: hostNetworkTCPUDPRouteUnsupportedReason,
		listenerStatusManager: NewListenerStatusManager(fakeClient, logger, ListenerStatusManagerConfig{
			TCPUDPRouteSupport:      true,
			TCPUDPUnsupportedReason: hostNetworkTCPUDPRouteUnsupportedReason,
		}),
		routeStatusManager: NewRouteStatusManager(fakeClient, logger, defaultControllerName, RouteStatusManagerConfig{
			IncludeTCPRoutes:        true,
			IncludeUDPRoutes:        true,
			TCPUDPRouteSupport:      true,
			TCPUDPUnsupportedReason: hostNetworkTCPUDPRouteUnsupportedReason,
		}),
		backendTLSPolicyStatusManager: NewBackendTLSPolicyStatusManager(fakeClient, defaultControllerName),
	}

	return reconciler, fakeClient
}

func findRouteAcceptedCondition(conds []metav1.Condition) *metav1.Condition {
	for _, cond := range conds {
		if cond.Type == string(gatewayv1.RouteConditionAccepted) {
			return &cond
		}
	}
	return nil
}

func TestGatewayReconciler_statuses(t *testing.T) {
	ciliumGWClass := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "cilium"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: gatewayv1.GatewayController(defaultControllerName)},
	}
	otherGWClass := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "other"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.com/other-controller"},
	}

	listener := gatewayv1.Listener{
		Name:     "http",
		Port:     80,
		Protocol: gatewayv1.HTTPProtocolType,
		AllowedRoutes: &gatewayv1.AllowedRoutes{
			Namespaces: &gatewayv1.RouteNamespaces{From: new(gatewayv1.NamespacesFromAll)},
		},
	}

	ciliumGW := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "cilium-gw", Namespace: "default"},
		Spec:       gatewayv1.GatewaySpec{GatewayClassName: "cilium", Listeners: []gatewayv1.Listener{listener}},
	}
	otherGW := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "other-gw", Namespace: "default"},
		Spec:       gatewayv1.GatewaySpec{GatewayClassName: "other", Listeners: []gatewayv1.Listener{listener}},
	}

	t.Run("setHTTPRouteStatuses sets related parent statuses", func(t *testing.T) {
		ctx := t.Context()

		validRoute := &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "route", Namespace: "default"},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{Name: gatewayv1.ObjectName(ciliumGW.Name)},
						{Name: gatewayv1.ObjectName(otherGW.Name)},
					},
				},
				Rules: []gatewayv1.HTTPRouteRule{{
					Matches: []gatewayv1.HTTPRouteMatch{{
						Path: &gatewayv1.HTTPPathMatch{
							Type:  new(gatewayv1.PathMatchRegularExpression),
							Value: new("^/api/v1$"),
						},
					}},
				}},
			},
		}

		invalidRoute := &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "invalid-route", Namespace: "default"},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{Name: gatewayv1.ObjectName(ciliumGW.Name)},
						{Name: gatewayv1.ObjectName(otherGW.Name)},
					},
				},
				Rules: []gatewayv1.HTTPRouteRule{{
					Matches: []gatewayv1.HTTPRouteMatch{{
						Path: &gatewayv1.HTTPPathMatch{
							Type:  new(gatewayv1.PathMatchRegularExpression),
							Value: new("[invalid"),
						},
					}},
				}},
			},
		}

		r, c := testReconciler(t, ciliumGWClass, ciliumGW, otherGWClass, otherGW, validRoute, invalidRoute)

		hrList := &gatewayv1.HTTPRouteList{}
		require.NoError(t, c.List(ctx, hrList))
		require.NoError(t, r.routeStatusManager.setHTTPRouteStatuses(ctx, r.logger, hrList.Items, nil))

		var updatedValidRoute, updatedInvalidRoute gatewayv1.HTTPRoute
		require.NoError(t, c.Get(ctx, types.NamespacedName{Name: validRoute.Name, Namespace: validRoute.Namespace}, &updatedValidRoute))
		require.NoError(t, c.Get(ctx, types.NamespacedName{Name: invalidRoute.Name, Namespace: invalidRoute.Namespace}, &updatedInvalidRoute))

		require.Len(t, updatedValidRoute.Status.Parents, 1, "Should not set status of unrelated parent")
		assert.EqualValues(t, defaultControllerName, updatedValidRoute.Status.Parents[0].ControllerName)

		validAcceptedCond := findRouteAcceptedCondition(updatedValidRoute.Status.Parents[0].Conditions)
		assert.NotNil(t, validAcceptedCond)
		assert.Equal(t, metav1.ConditionTrue, validAcceptedCond.Status)

		require.Len(t, updatedInvalidRoute.Status.Parents, 1, "Should not set status of unrelated parent")
		assert.EqualValues(t, defaultControllerName, updatedInvalidRoute.Status.Parents[0].ControllerName)

		invalidAcceptedCond := findRouteAcceptedCondition(updatedInvalidRoute.Status.Parents[0].Conditions)
		assert.NotNil(t, invalidAcceptedCond)
		assert.Equal(t, metav1.ConditionFalse, invalidAcceptedCond.Status)
	})

	t.Run("setGRPCRouteStatuses sets related parent statuses", func(t *testing.T) {
		ctx := t.Context()

		validRoute := &gatewayv1.GRPCRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "route", Namespace: "default"},
			Spec: gatewayv1.GRPCRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{Name: gatewayv1.ObjectName(ciliumGW.Name)},
						{Name: gatewayv1.ObjectName(otherGW.Name)},
					},
				},
				Rules: []gatewayv1.GRPCRouteRule{{
					Matches: []gatewayv1.GRPCRouteMatch{{
						Method: &gatewayv1.GRPCMethodMatch{
							Type:    new(gatewayv1.GRPCMethodMatchRegularExpression),
							Service: new("^ordersV[12]$"),
						},
					}},
				}},
			},
		}

		invalidRoute := &gatewayv1.GRPCRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "invalid-route", Namespace: "default"},
			Spec: gatewayv1.GRPCRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{Name: gatewayv1.ObjectName(ciliumGW.Name)},
						{Name: gatewayv1.ObjectName(otherGW.Name)},
					},
				},
				Rules: []gatewayv1.GRPCRouteRule{{
					Matches: []gatewayv1.GRPCRouteMatch{{
						Method: &gatewayv1.GRPCMethodMatch{
							Type:    new(gatewayv1.GRPCMethodMatchRegularExpression),
							Service: new("(unclosed"),
						},
					}},
				}},
			},
		}

		r, c := testReconciler(t, ciliumGWClass, ciliumGW, otherGWClass, otherGW, validRoute, invalidRoute)

		hrList := &gatewayv1.GRPCRouteList{}
		require.NoError(t, c.List(ctx, hrList))
		require.NoError(t, r.routeStatusManager.setGRPCRouteStatuses(ctx, r.logger, hrList.Items, nil))

		var updatedValidRoute, updatedInvalidRoute gatewayv1.GRPCRoute
		require.NoError(t, c.Get(ctx, types.NamespacedName{Name: validRoute.Name, Namespace: validRoute.Namespace}, &updatedValidRoute))
		require.NoError(t, c.Get(ctx, types.NamespacedName{Name: invalidRoute.Name, Namespace: invalidRoute.Namespace}, &updatedInvalidRoute))

		require.Len(t, updatedValidRoute.Status.Parents, 1, "Should not set status of unrelated parent")
		assert.EqualValues(t, defaultControllerName, updatedValidRoute.Status.Parents[0].ControllerName)

		validAcceptedCond := findRouteAcceptedCondition(updatedValidRoute.Status.Parents[0].Conditions)
		assert.NotNil(t, validAcceptedCond)
		assert.Equal(t, metav1.ConditionTrue, validAcceptedCond.Status)

		require.Len(t, updatedInvalidRoute.Status.Parents, 1, "Should not set status of unrelated parent")
		assert.EqualValues(t, defaultControllerName, updatedInvalidRoute.Status.Parents[0].ControllerName)

		invalidAcceptedCond := findRouteAcceptedCondition(updatedInvalidRoute.Status.Parents[0].Conditions)
		assert.NotNil(t, invalidAcceptedCond)
		assert.Equal(t, metav1.ConditionFalse, invalidAcceptedCond.Status)
	})
}

func Test_gatewayReconciler_setStaticAddressStatus(t *testing.T) {
	t.Parallel()

	gateway := func(addr string) *gatewayv1.Gateway {
		return &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "static-address-gateway",
				Namespace: "default",
			},
			Spec: gatewayv1.GatewaySpec{
				Addresses: []gatewayv1.GatewaySpecAddress{
					{
						Type:  ptr.To(gatewayv1.IPAddressType),
						Value: addr,
					},
				},
			},
		}
	}

	service := func(ingress ...corev1.LoadBalancerIngress) *corev1.Service {
		return &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "cilium-gateway-static-address-gateway",
				Namespace: "default",
				Labels: map[string]string{
					owningGatewayLabel: shortener.ShortenK8sResourceName("static-address-gateway"),
				},
			},
			Status: corev1.ServiceStatus{
				LoadBalancer: corev1.LoadBalancerStatus{
					Ingress: ingress,
				},
			},
		}
	}

	tests := []struct {
		name      string
		specAddr  string
		ingress   []corev1.LoadBalancerIngress
		wantError bool
	}{
		{
			name:     "IPv6 spelled with :: matches the canonical status address",
			specAddr: "2001:db8:1:2:3:4::6",
			ingress:  []corev1.LoadBalancerIngress{{IP: "2001:db8:1:2:3:4:0:6"}},
		},
		{
			name:     "IPv6 with leading zeroes matches the canonical status address",
			specAddr: "2001:0db8::0001",
			ingress:  []corev1.LoadBalancerIngress{{IP: "2001:db8::1"}},
		},
		{
			name:     "identical IPv4 addresses match",
			specAddr: "10.0.0.1",
			ingress:  []corev1.LoadBalancerIngress{{IP: "10.0.0.1"}},
		},
		{
			name:     "hostname entry is ignored when a matching IP is present",
			specAddr: "2001:db8::1",
			ingress: []corev1.LoadBalancerIngress{
				{Hostname: "gateway.example.com"},
				{IP: "2001:db8::1"},
			},
		},
		{
			name:      "a different address is still rejected",
			specAddr:  "2001:db8::1",
			ingress:   []corev1.LoadBalancerIngress{{IP: "2001:db8::2"}},
			wantError: true,
		},
		{
			name:      "hostname-only ingress is rejected",
			specAddr:  "2001:db8::1",
			ingress:   []corev1.LoadBalancerIngress{{Hostname: "gateway.example.com"}},
			wantError: true,
		},
		{
			name:      "invalid ingress IP is rejected",
			specAddr:  "2001:db8::1",
			ingress:   []corev1.LoadBalancerIngress{{IP: "not-an-ip"}},
			wantError: true,
		},
		{
			name:      "invalid Gateway spec address is rejected",
			specAddr:  "not-an-ip",
			ingress:   []corev1.LoadBalancerIngress{{IP: "2001:db8::1"}},
			wantError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gw := gateway(tc.specAddr)
			c := fake.NewClientBuilder().
				WithScheme(helpers.TestScheme(helpers.AllOptionalKinds)).
				WithObjects(gw, service(tc.ingress...)).
				Build()
			r := &gatewayReconciler{
				Client: c,
				logger: hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug)),
			}

			err := r.setStaticAddressStatus(t.Context(), gw)
			if tc.wantError {
				require.ErrorContains(t, err, "can't be used")
				return
			}
			require.NoError(t, err)
		})
	}
}
