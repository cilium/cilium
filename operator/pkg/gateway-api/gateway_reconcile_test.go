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
		APIVersion: gatewayv1alpha2APIVersion,
	}
	backendTLSPolicyTypeMeta = metav1.TypeMeta{
		Kind:       "BackendTLSPolicy",
		APIVersion: gatewayv1APIVersion,
	}
)

func Test_Conformance(t *testing.T) {
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
	cecTranslator := translation.NewCECTranslator(translation.Config{
		RouteConfig: translation.RouteConfig{
			HostNameSuffixMatch: true,
		},
		ListenerConfig: translation.ListenerConfig{
			StreamIdleTimeoutSeconds: 300,
		},
		ClusterConfig: translation.ClusterConfig{
			IdleTimeoutSeconds: 60,
		},
	})
	gatewayAPITranslator := gatewayApiTranslation.NewTranslator(cecTranslator, translation.Config{
		ServiceConfig: translation.ServiceConfig{
			ExternalTrafficPolicy: string(corev1.ServiceExternalTrafficPolicyCluster),
		},
	})

	type gwDetails struct {
		FullName types.NamespacedName
		wantErr  bool
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
				WithStatusSubresource(&gatewayv1alpha2.TLSRoute{}).
				WithStatusSubresource(&gatewayv1.Gateway{}).
				WithStatusSubresource(&gatewayv1.GatewayClass{}).
				WithStatusSubresource(&gatewayv1.BackendTLSPolicy{})

			switch tt.disableServiceImport {
			case true:
				clientBuilder.WithScheme(testSchemeNoServiceImport())
			case false:
				clientBuilder.WithScheme(testScheme())
			}

			// Add any required indexes here
			clientBuilder.WithIndex(&gatewayv1.HTTPRoute{}, indexers.GatewayHTTPRouteIndex, indexers.IndexHTTPRouteByGateway)
			clientBuilder.WithIndex(&gatewayv1.HTTPRoute{}, indexers.BackendServiceHTTPRouteIndex, fakeIndexHTTPRouteByBackendService)
			clientBuilder.WithIndex(&gatewayv1.GRPCRoute{}, indexers.GatewayGRPCRouteIndex, indexers.IndexGRPCRouteByGateway)
			clientBuilder.WithIndex(&gatewayv1alpha2.TLSRoute{}, indexers.GatewayTLSRouteIndex, indexers.IndexTLSRouteByGateway)

			c := clientBuilder.Build()

			r := &gatewayReconciler{
				Client:     c,
				translator: gatewayAPITranslator,
				logger:     logger,
			}

			// Reconcile all related HTTPRoute objects
			hrList := &gatewayv1.HTTPRouteList{}
			err := c.List(t.Context(), hrList)
			require.NoError(t, err)

			// Reconcile all related TLSRoute objects
			tlsrList := &gatewayv1alpha2.TLSRouteList{}
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

			for _, gwDetail := range tt.gateway {
				// Reconcile the gateway under test
				result, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: gwDetail.FullName})
				require.Equal(t, gwDetail.wantErr, err != nil, "Got an unexpected reconciliation error")
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
				if !gwDetail.wantErr {
					// Checking the output for CiliumEnvoyConfig
					actualCEC := &ciliumv2.CiliumEnvoyConfig{}
					err = c.Get(t.Context(), client.ObjectKey{Namespace: gwDetail.FullName.Namespace, Name: "cilium-gateway-" + gwDetail.FullName.Name}, actualCEC)
					require.NoError(t, err, "Could not get CiliumEnvoyConfig and wasn't expecting a reconciliation error")
					expectedCEC := &ciliumv2.CiliumEnvoyConfig{}
					readOutput(t, fmt.Sprintf("testdata/gateway/%s/output/cec-%s.yaml", tt.name, gwDetail.FullName.Name), expectedCEC)
					require.NoError(t, err)
					require.Empty(t, cmp.Diff(expectedCEC, actualCEC, protocmp.Transform()))
				}

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
				actualTLSR := &gatewayv1alpha2.TLSRoute{}
				err = c.Get(t.Context(), client.ObjectKeyFromObject(&tlsr), actualTLSR)
				actualTLSR.TypeMeta = tlsRouteTypeMeta
				require.NoError(t, err, "error getting TLSRoute %s/%s: %v", tlsr.Namespace, tlsr.Name, err)
				expectedTLSR := &gatewayv1alpha2.TLSRoute{}
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

func Test_isValidPemFormat(t *testing.T) {
	cert := []byte(`-----BEGIN CERTIFICATE-----
MIIENDCCApygAwIBAgIRAKD/BLFBfwKIZ0WGrHtTH6gwDQYJKoZIhvcNAQELBQAw
dzEeMBwGA1UEChMVbWtjZXJ0IGRldmVsb3BtZW50IENBMSYwJAYDVQQLDB10YW1t
YWNoQGZlZG9yYS5sYW4gKFRhbSBNYWNoKTEtMCsGA1UEAwwkbWtjZXJ0IHRhbW1h
Y2hAZmVkb3JhLmxhbiAoVGFtIE1hY2gpMB4XDTIzMDIyMTExMDg0M1oXDTI1MDUy
MTEyMDg0M1owUTEnMCUGA1UEChMebWtjZXJ0IGRldmVsb3BtZW50IGNlcnRpZmlj
YXRlMSYwJAYDVQQLDB10YW1tYWNoQGZlZG9yYS5sYW4gKFRhbSBNYWNoKTCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMIZy+0JRVjqpWgeq2dP+1oliO4A
CcZnMg4tSqPalhDQL6Mf68HYLfizyJIpRzMJ905rYd0AcmXmu/g0Eo8ykHxFDz5T
sePs2XQng8MN4azsRmm1l4f74ovawQzQcb822QP1CS6ILZ3VtwNjRh2nAwthYBMo
CkngDGeQ8Gl0tjHLFnBdTdSwQRmE2jtDBcAgyEGpq+6ReYt+/47nNn7dCftsVqhE
BYr9XH3itefHmsbfj7zWFbptdko7q9lMHwnBd+0hd40MmJIXMZrOGGFZjawJDBqS
sBq2Q3l6XQz8X7P/GA8Dn8h4w3rppmiaN7LOmGXeki3xX2wqnM+0s6aZYZsCAwEA
AaNhMF8wDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMB8GA1Ud
IwQYMBaAFGQ2DB06CdQFQBsYPye0NBwErUNEMBcGA1UdEQQQMA6CDHVuaXR0ZXN0
LmNvbTANBgkqhkiG9w0BAQsFAAOCAYEArtHdKWXR6aELpfal17biabCPvIF9j6nw
uDzcdMYQLrXm8M+NHe8x3dpI7u3lltO+dzLng+nVKQOR3alQACSmRD9c7ie8eT5d
7zKOTk6keY195I1wVV4jbNLbNWa9y4RJQRTvBLAvAP9NVtUw2Q/w/ErUTqSyz+ob
dwnt4gYCw6dGnluLxlfF34DB9KflvVNSnkyMB/gsB4A3r1GPOIo0Gyf74ig3FWrS
wHYKnBbtZfYO0JV0LCoPyHe8g0XajZe8DCbP/E6SmlTNAmJESVjigTTcIBAkFI+n
toBAdxfhjKUGaClOHS29cpaiynjSayGm4RkHkx7mcAua9lWPf7pSa3mCcFb+wFr3
ABkHDPJH2acfaUK1vgKTgOwcG/6KA820/PraoSihLaPK/A7eg77r1EeYpt0Neppb
XjvUp3YmVlIMZXPzrjOsastoDSrsygj5jdVtm4Pslv9nPhzDrBjlZpEJScW4Jlb+
6wtd7p03UDBSKfTbVROVAe5mvJvA0hoS
-----END CERTIFICATE-----
`)
	key := []byte(`-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDCGcvtCUVY6qVo
HqtnT/taJYjuAAnGZzIOLUqj2pYQ0C+jH+vB2C34s8iSKUczCfdOa2HdAHJl5rv4
NBKPMpB8RQ8+U7Hj7Nl0J4PDDeGs7EZptZeH++KL2sEM0HG/NtkD9QkuiC2d1bcD
Y0YdpwMLYWATKApJ4AxnkPBpdLYxyxZwXU3UsEEZhNo7QwXAIMhBqavukXmLfv+O
5zZ+3Qn7bFaoRAWK/Vx94rXnx5rG34+81hW6bXZKO6vZTB8JwXftIXeNDJiSFzGa
zhhhWY2sCQwakrAatkN5el0M/F+z/xgPA5/IeMN66aZomjeyzphl3pIt8V9sKpzP
tLOmmWGbAgMBAAECggEAEjASoMJ2og9Ssn/1NbgT6G2N+Cc+wz2WPifWT6ZC2452
eEWcdMyJ+jz2dWOyzUCI0OtU/z10esH1KRvQBWUKjup1tDRpfd8KvUyalyNs2yRE
sNEYQuDCaLJ11nqNvgooqatDUf3msFx/Sqz5u/uTWHSmaQUeea+p2eaF8IvEKsQf
6QNklkeHsv+GVPv+iibfbXXne6I5aV35Rc4Q08zRCgYX/BN1AYXV6ho4RC9dZVGP
JUkSLzRadegok/EONKkrqLZOFJVb2wtFq85gJ01lODM/gj7GqM59M/wk55CaQIRD
9x5H4X4rpM2rhmiNLkIN0tGLKO8X31up7hTx9bvJcQKBgQD51MLWYYUPz/umvSrN
QOT9UhEHI/bxtCbWQthW3L1qrVT7DB8Jko/6/xYlXhl7nwVwJz24jJf9vuxWbBpL
HZRf0QsDO2/O4rqhKDov/GMUCx2shzc+J7k+T93KNVANYa05guqMeB8n30HProkF
LgihVFF20k9Z6SibUvgTMpF1EwKBgQDG5MBgc8oFXmlr/7pHKizC4F3eDAXUxVHM
WCIbSwMyzOXKqDcdXNDz8cQrjhKa2rD1fKhE0oRR+QvHz8IPC+0MsT7Q6QsIHYj5
CXubHr0s5k8PJAp+Lk2EdHePZQM/I/vj/gSwxnJ9Qs64FWZ25K9zYnNNsiojQel7
WVmI9IVaWQKBgD3BYggsQwANoV8uE455JCGaT6s8MKa+qXr9Owz9s7TS89a6wFFV
cVHSDF9gS1xLisSWbqNX3ZpTv4f9YOKAhVTKD7bU0maJlSiREREbikJCHSuwoO80
Uo4cn+6EDy2/n1pACkp+xvTMMzBrLGOjZW67sQd2JTdMc0Ux1TCpp1sRAoGAaEVI
rchGYyYp8pqw19o+eTQTQfPforqHta+GwfRDiwBsgCBMNLKSQTHAfG0RR+na1/gw
Z1ROVoNQL8K1pBnGft71ZaSnSeviAV19Vcd5ue5MCE4GyjwQG57Lh3uXhiShS9fC
McL4Br9djJh7jV06ti0o8dSzzqQhea9QB0LaHpECgYApc8oBoiK69s0wXyI4+Phx
ScBJ0XqDBYFkxyXr8Y5pEarEaqCtl1OPPMOiQRDWoxRR+FwA/0laSfh5xw0U3b+q
iZ2XpkrbQp034rC0UR6p+Km1Sv9AVCACAjrcQ3NZaf8bDOWqvpla7Auq0oG8i6UX
hEKCKf/N3gE1oMrTxVzUDQ==
-----END PRIVATE KEY-----
`)
	keyAndCert := append(key, cert...)
	type args struct {
		b []byte
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "valid cert pem",
			args: args{
				b: cert,
			},
			want: true,
		},
		{
			name: "value key pem",
			args: args{
				b: key,
			},
			want: true,
		},
		{
			name: "multiple valid pem blocks",
			args: args{
				b: keyAndCert,
			},
			want: true,
		},
		{
			name: "invalid first block",
			args: args{
				b: append([]byte("invalid block"), key...),
			},
			want: false,
		},
		{
			name: "invalid pem",
			args: args{
				b: []byte("invalid pem"),
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, isValidPemFormat(tt.args.b), "isValidPemFormat(%v)", tt.args.b)
		})
	}
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
