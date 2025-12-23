// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"fmt"
	"log/slog"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
	"github.com/cilium/cilium/operator/pkg/model/translation"
	gatewayApiTranslation "github.com/cilium/cilium/operator/pkg/model/translation/gateway-api"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

var cmpIgnoreFields = []cmp.Option{
	cmpopts.IgnoreFields(metav1.Condition{}, "LastTransitionTime"),
	cmpopts.IgnoreFields(metav1.ObjectMeta{}, "ResourceVersion", "CreationTimestamp"),
}

var (
	serviceKeyEcho   = types.NamespacedName{Namespace: "gateway-conformance-mesh", Name: "echo"}
	serviceKeyEchoV1 = types.NamespacedName{Namespace: "gateway-conformance-mesh", Name: "echo-v1"}
	serviceKeyEchoV2 = types.NamespacedName{Namespace: "gateway-conformance-mesh", Name: "echo-v2"}
	serviceTypeMeta  = metav1.TypeMeta{
		Kind:       "Service",
		APIVersion: corev1.SchemeGroupVersion.Version,
	}
)

func Test_gammaReconciler_Reconcile(t *testing.T) {
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

	tests := []struct {
		name       string
		serviceKey []types.NamespacedName
		wantErr    bool
	}{
		{name: "mesh-basic", serviceKey: []types.NamespacedName{serviceKeyEcho}},
		{name: "mesh-split", serviceKey: []types.NamespacedName{serviceKeyEcho}},
		{name: "mesh-frontend", serviceKey: []types.NamespacedName{serviceKeyEchoV2}},
		{name: "mesh-matching", serviceKey: []types.NamespacedName{serviceKeyEcho}},
		{name: "mesh-ports", serviceKey: []types.NamespacedName{serviceKeyEchoV1, serviceKeyEchoV2}},
		{name: "mesh-query-param-matching", serviceKey: []types.NamespacedName{serviceKeyEcho}},
		{name: "mesh-redirect-host-and-status", serviceKey: []types.NamespacedName{serviceKeyEcho}},
		{name: "mesh-redirect-path", serviceKey: []types.NamespacedName{serviceKeyEcho}},
		{name: "mesh-redirect-port", serviceKey: []types.NamespacedName{serviceKeyEcho}},
		{name: "mesh-redirect-scheme", serviceKey: []types.NamespacedName{serviceKeyEcho}},
		{name: "mesh-request-header-modifier", serviceKey: []types.NamespacedName{serviceKeyEcho}},
		{name: "mesh-rewrite-path", serviceKey: []types.NamespacedName{serviceKeyEcho}},
		{name: "mesh-weighted-backends", serviceKey: []types.NamespacedName{serviceKeyEcho}},
		{name: "mesh-grpc-weight", serviceKey: []types.NamespacedName{serviceKeyEcho}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, serviceKey := range tt.serviceKey {
				t.Run(serviceKey.String(), func(t *testing.T) {
					base := readInputDir(t, "testdata/gamma/base")
					input := readInputDir(t, fmt.Sprintf("testdata/gamma/%s/input", tt.name))

					c := fake.NewClientBuilder().
						WithScheme(testScheme()).
						WithObjects(append(base, input...)...).
						WithIndex(&gatewayv1.HTTPRoute{}, indexers.GammaHTTPRouteParentRefsIndex, indexers.IndexHTTPRouteByGammaService).
						WithIndex(&gatewayv1.GRPCRoute{}, indexers.GammaGRPCRouteParentRefsIndex, indexers.IndexGRPCRouteByGammaService).
						WithStatusSubresource(&corev1.Service{}).
						WithStatusSubresource(&gatewayv1.HTTPRoute{}).
						WithStatusSubresource(&gatewayv1.GRPCRoute{}).
						Build()

					r := &gammaReconciler{
						Client:     c,
						translator: gatewayAPITranslator,
						logger:     logger,
					}

					// Reconcile all related HTTPRoute objects
					hrList := &gatewayv1.HTTPRouteList{}
					err := c.List(t.Context(), hrList)
					require.NoError(t, err)
					filterHTTPRouteList := filterHTTPRoute(hrList, serviceKey.Name, serviceKey.Namespace)

					// Reconcile all related GRPCRoute objects
					grpcrList := &gatewayv1.GRPCRouteList{}
					err = c.List(t.Context(), grpcrList)
					require.NoError(t, err)
					filterGRPCRouteList := filterGRPCRoute(grpcrList, serviceKey.Name, serviceKey.Namespace)

					t.Logf("Test %s, HTTPRoutes: %d, GRPCRoutes: %d", tt.name, len(filterHTTPRouteList), len(filterGRPCRouteList))
					result, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: serviceKey})
					require.Equal(t, tt.wantErr, err != nil, "Error mismatch")
					require.Equal(t, ctrl.Result{}, result)

					// Checking the output for Service
					expectedService := &corev1.Service{}
					readOutput(t, fmt.Sprintf("testdata/gamma/%s/output/service-%s.yaml", tt.name, serviceKey.Name), expectedService)
					actualService := &corev1.Service{}
					err = c.Get(t.Context(), serviceKey, actualService)
					actualService.TypeMeta = serviceTypeMeta
					require.NoError(t, err)

					for _, hr := range filterHTTPRouteList {
						actualHR := &gatewayv1.HTTPRoute{}
						err = c.Get(t.Context(), client.ObjectKeyFromObject(&hr), actualHR)
						actualHR.TypeMeta = httpRouteTypeMeta
						require.NoError(t, err, "error getting HTTPRoute %s/%s: %v", hr.Namespace, hr.Name, err)
						expectedHR := &gatewayv1.HTTPRoute{}
						readOutput(t, fmt.Sprintf("testdata/gamma/%s/output/httproute-%s.yaml", tt.name, hr.Name), expectedHR)
						require.Empty(t, cmp.Diff(expectedHR, actualHR, cmpIgnoreFields...))
					}

					for _, grpcr := range filterGRPCRouteList {
						actualGRPCR := &gatewayv1.GRPCRoute{}
						err = c.Get(t.Context(), client.ObjectKeyFromObject(&grpcr), actualGRPCR)
						actualGRPCR.TypeMeta = grpcRouteTypeMeta
						require.NoError(t, err, "error getting GRPCRoute %s/%s: %v", grpcr.Namespace, grpcr.Name, err)
						expectedGRPCR := &gatewayv1.GRPCRoute{}
						readOutput(t, fmt.Sprintf("testdata/gamma/%s/output/grpcroute-%s.yaml", tt.name, grpcr.Name), expectedGRPCR)
						require.Empty(t, cmp.Diff(expectedGRPCR, actualGRPCR, cmpIgnoreFields...))
					}

					if !tt.wantErr {
						// Checking the output for CiliumEnvoyConfig
						actualCEC := &ciliumv2.CiliumEnvoyConfig{}
						err = c.Get(t.Context(), serviceKey, actualCEC)
						require.NoError(t, err, "Could not get CiliumEnvoyConfig and wasn't expecting a reconciliation error")
						expectedCEC := &ciliumv2.CiliumEnvoyConfig{}
						readOutput(t, fmt.Sprintf("testdata/gamma/%s/output/cec-%s.yaml", tt.name, serviceKey.Name), expectedCEC)

						require.NoError(t, err)
						require.Empty(t, cmp.Diff(expectedCEC, actualCEC, protocmp.Transform()))
					}
				})
			}
		})
	}
}
