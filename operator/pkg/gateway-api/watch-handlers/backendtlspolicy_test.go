// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchhandlers

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers/testhelpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
)

func TestBackendTLSPolicyEnqueuesGRPCRouteGateway(t *testing.T) {
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gateway",
			Namespace: "default",
		},
	}
	grpcRoute := &gatewayv1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grpc",
			Namespace: "default",
		},
		Spec: gatewayv1.GRPCRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{Name: "gateway"}},
			},
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
	policy := &gatewayv1.BackendTLSPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "backend-tls",
			Namespace: "default",
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
		},
	}
	scheme := testhelpers.TestScheme(nil, helpers.RegisterGatewayAPITypesToScheme)
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gateway, grpcRoute).
		WithIndex(&gatewayv1.HTTPRoute{}, indexers.BackendServiceHTTPRouteIndex, func(client.Object) []string { return nil }).
		WithIndex(&gatewayv1.GRPCRoute{}, indexers.BackendServiceGRPCRouteIndex, func(rawObj client.Object) []string {
			route := rawObj.(*gatewayv1.GRPCRoute)
			return []string{types.NamespacedName{
				Namespace: route.Namespace,
				Name:      string(route.Spec.Rules[0].BackendRefs[0].Name),
			}.String()}
		}).
		Build()
	rrSet := map[reconcile.Request]struct{}{}

	updateReconcileRequestsForBackendTLSPolicy(
		t.Context(),
		c,
		hivetest.Logger(t),
		map[string]struct{}{types.NamespacedName{Namespace: "default", Name: "gateway"}.String(): {}},
		rrSet,
		policy,
		"default",
	)

	require.Contains(t, rrSet, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "gateway"}})
}
