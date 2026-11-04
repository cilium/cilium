// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers/testhelpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
)

func TestBackendTLSPolicyStatusForGRPCRoute(t *testing.T) {
	policy := &gatewayv1.BackendTLSPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "backend-tls",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: gatewayv1.BackendTLSPolicySpec{
			TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
				{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
						Group: "",
						Kind:  "Service",
						Name:  "backend",
					},
				},
			},
			Validation: gatewayv1.BackendTLSPolicyValidation{
				Hostname:                "backend.example.com",
				WellKnownCACertificates: ptr.To[gatewayv1.WellKnownCACertificatesType]("System"),
			},
		},
	}
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "backend",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{{Port: 8443}},
		},
	}
	grpcRoute := &gatewayv1.GRPCRoute{
		TypeMeta: metav1.TypeMeta{
			APIVersion: gatewayv1.GroupVersion.String(),
			Kind:       "GRPCRoute",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "grpc",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: gatewayv1.GRPCRouteSpec{
			Rules: []gatewayv1.GRPCRouteRule{
				{
					BackendRefs: []gatewayv1.GRPCBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: "backend",
									Port: ptr.To(gatewayv1.PortNumber(8443)),
								},
							},
						},
					},
				},
			},
		},
	}
	scheme := testhelpers.TestScheme(nil, helpers.RegisterGatewayAPITypesToScheme)
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy, service, grpcRoute).
		WithStatusSubresource(&gatewayv1.BackendTLSPolicy{}).
		WithIndex(&gatewayv1.HTTPRoute{}, indexers.BackendServiceHTTPRouteIndex, func(client.Object) []string { return nil }).
		WithIndex(&gatewayv1.GRPCRoute{}, indexers.BackendServiceGRPCRouteIndex, fakeIndexGRPCRouteByBackendService).
		WithInterceptorFuncs(typeMetaInterceptor(scheme)).
		Build()

	manager := NewBackendTLSPolicyStatusManager(c, defaultControllerName)
	btlspMap, err := manager.SetBackendTLSPolicyStatuses(
		t.Context(),
		hivetest.Logger(t),
		types.NamespacedName{Namespace: "default", Name: "gateway"},
		[]gatewayv1.BackendTLSPolicy{*policy},
		nil,
		[]gatewayv1.GRPCRoute{*grpcRoute},
	)
	require.NoError(t, err)
	collection := btlspMap[types.NamespacedName{Namespace: "default", Name: "backend"}]
	require.NotNil(t, collection)
	require.Equal(t, "backend-tls", collection.Valid[""].Name)

	actual := &gatewayv1.BackendTLSPolicy{}
	require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(policy), actual))
	require.Len(t, actual.Status.Ancestors, 1)
	require.Equal(t, metav1.ConditionTrue, actual.Status.Ancestors[0].Conditions[0].Status)
}
