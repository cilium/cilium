// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/model/translation"
	gatewayApiTranslation "github.com/cilium/cilium/operator/pkg/model/translation/gateway-api"
)

func Test_gammaReconciler_Reconcile(t *testing.T) {
	logger := hivetest.Logger(t)

	c := fake.NewClientBuilder().
		WithScheme(testScheme()).
		WithObjects(meshConformanceBaseFixture...).
		WithIndex(&gatewayv1.HTTPRoute{}, gammaParentRefsIndex, getGammaHTTPRouteParentIndexFunc(logger)).
		WithStatusSubresource(&corev1.Service{}).
		WithStatusSubresource(&gatewayv1.HTTPRoute{}).
		Build()

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
		HostNetworkConfig: translation.HostNetworkConfig{
			Enabled: false,
		},
		ServiceConfig: translation.ServiceConfig{
			ExternalTrafficPolicy: string(corev1.ServiceExternalTrafficPolicyCluster),
		},
	})

	r := &gammaReconciler{
		Client:     c,
		translator: gatewayAPITranslator,
		logger:     logger,
	}

	t.Run("non-existent GAMMA Service", func(t *testing.T) {
		result, err := r.Reconcile(t.Context(), ctrl.Request{
			NamespacedName: client.ObjectKey{
				Namespace: "gateway-conformance-mesh",
				Name:      "non-existent-service",
			},
		})

		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result)
	})

	t.Run("mesh-split", func(t *testing.T) {
		key := client.ObjectKey{
			Namespace: "gateway-conformance-mesh",
			Name:      "echo",
		}

		meshSplit := client.ObjectKey{
			Namespace: "gateway-conformance-mesh",
			Name:      "mesh-split",
		}

		result, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: key})

		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result)

		svc := &corev1.Service{}
		err = c.Get(t.Context(), key, svc)
		require.NoError(t, err)

		require.Len(t, svc.Status.Conditions, 2)
		require.Equal(t, CiliumGammaConditionAccepted, svc.Status.Conditions[0].Type)
		require.Equal(t, "True", string(svc.Status.Conditions[0].Status))
		require.Equal(t, "Gamma Service has HTTPRoutes attached", svc.Status.Conditions[0].Message)
		require.Equal(t, CiliumGammaConditionProgrammed, svc.Status.Conditions[1].Type)
		require.Equal(t, "True", string(svc.Status.Conditions[1].Status))
		require.Equal(t, "Gamma Service has been programmed", svc.Status.Conditions[1].Message)

		hr := &gatewayv1.HTTPRoute{}
		err = c.Get(t.Context(), meshSplit, hr)
		require.NoError(t, err)

		require.Len(t, hr.Status.RouteStatus.Parents, 1)
		require.Len(t, hr.Status.RouteStatus.Parents[0].Conditions, 2)
		require.Equal(t, "Accepted", hr.Status.RouteStatus.Parents[0].Conditions[0].Type)
		require.Equal(t, "True", string(hr.Status.RouteStatus.Parents[0].Conditions[0].Status))
		require.Equal(t, "ResolvedRefs", hr.Status.RouteStatus.Parents[0].Conditions[1].Type)
		require.Equal(t, "True", string(hr.Status.RouteStatus.Parents[0].Conditions[1].Status))
	})
}
