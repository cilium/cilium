// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"fmt"
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
)

func Test_gammaReconciler_Reconcile(t *testing.T) {
	logger := hivetest.Logger(t)
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
		{name: "mesh-split", serviceKey: []types.NamespacedName{serviceKeyEcho}},
		{name: "mesh-frontend", serviceKey: []types.NamespacedName{serviceKeyEchoV2}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, serviceKey := range tt.serviceKey {
				t.Run(serviceKey.String(), func(t *testing.T) {
					base := readInputDir(t, "testdata/gamma/base")
					hr := &gatewayv1.HTTPRoute{}
					readInput(t, fmt.Sprintf("testdata/gamma/%s/httproute-%s-input.yaml", tt.name, serviceKey.Name), hr)

					c := fake.NewClientBuilder().
						WithScheme(testScheme()).
						WithObjects(append(base, hr)...).
						WithIndex(&gatewayv1.HTTPRoute{}, gammaParentRefsIndex, getGammaHTTPRouteParentIndexFunc(logger)).
						WithStatusSubresource(&corev1.Service{}).
						WithStatusSubresource(&gatewayv1.HTTPRoute{}).
						Build()

					r := &gammaReconciler{
						Client:     c,
						translator: gatewayAPITranslator,
						logger:     logger,
					}

					result, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: serviceKey})
					require.Equal(t, tt.wantErr, err != nil, "Error mismatch")
					require.Equal(t, ctrl.Result{}, result)

					// Checking the output for HTTPRoute
					expectedHR := &gatewayv1.HTTPRoute{}
					readOutput(t, fmt.Sprintf("testdata/gamma/%s/httproute-%s-output.yaml", tt.name, serviceKey.Name), expectedHR)
					actualHR := &gatewayv1.HTTPRoute{}
					err = c.Get(t.Context(), client.ObjectKeyFromObject(hr), actualHR)
					require.NoError(t, err)
					require.Empty(t, cmp.Diff(expectedHR, actualHR, cmpIgnoreFields...))

					// Checking the output for Service
					expectedService := &corev1.Service{}
					readOutput(t, fmt.Sprintf("testdata/gamma/%s/service-%s-output.yaml", tt.name, serviceKey.Name), expectedService)
					actualService := &corev1.Service{}
					err = c.Get(t.Context(), serviceKey, actualService)

					require.NoError(t, err)
					require.Empty(t, cmp.Diff(expectedService, actualService, cmpIgnoreFields...))

					// Checking the output for CiliumEnvoyConfig
					expectedCEC := &ciliumv2.CiliumEnvoyConfig{}
					readOutput(t, fmt.Sprintf("testdata/gamma/%s/cec-%s-output.yaml", tt.name, serviceKey.Name), expectedCEC)
					actualCEC := &ciliumv2.CiliumEnvoyConfig{}
					err = c.Get(t.Context(), serviceKey, actualCEC)

					require.NoError(t, err)
					require.Empty(t, cmp.Diff(expectedCEC, actualCEC, protocmp.Transform()))
				})
			}
		})
	}
}
