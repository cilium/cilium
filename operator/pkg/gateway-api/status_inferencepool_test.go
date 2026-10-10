// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gateway_inf_ext "sigs.k8s.io/gateway-api-inference-extension/api/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers/testhelpers"
)

func TestSetInferencePoolStatuses(t *testing.T) {
	const controllerName = "io.cilium/gateway-controller"
	gwName := types.NamespacedName{Namespace: "default", Name: "my-gw"}

	eppRef := &gateway_inf_ext.EndpointPickerRef{
		Name: "pool-epp",
		Port: &gateway_inf_ext.Port{Number: 9002},
	}
	pool := func(ref *gateway_inf_ext.EndpointPickerRef) *gateway_inf_ext.InferencePool {
		return &gateway_inf_ext.InferencePool{
			ObjectMeta: metav1.ObjectMeta{Name: "pool", Namespace: "default"},
			Spec:       gateway_inf_ext.InferencePoolSpec{EndpointPickerRef: ref},
		}
	}

	route := gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "r", Namespace: "default"},
		Spec: gatewayv1.HTTPRouteSpec{Rules: []gatewayv1.HTTPRouteRule{{
			BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{
				BackendObjectReference: gatewayv1.BackendObjectReference{
					Group: ptr.To[gatewayv1.Group]("inference.networking.k8s.io"),
					Kind:  ptr.To[gatewayv1.Kind]("InferencePool"),
					Name:  "pool",
				},
			}}},
		}}},
	}
	eppSvc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "pool-epp", Namespace: "default"}}

	tests := []struct {
		name        string
		pool        *gateway_inf_ext.InferencePool
		routes      []gatewayv1.HTTPRoute
		extraObjs   []client.Object
		wantParents int
		assert      func(t *testing.T, ps gateway_inf_ext.ParentStatus)
	}{
		{
			name:        "referenced with valid EPP",
			pool:        pool(eppRef),
			routes:      []gatewayv1.HTTPRoute{route},
			extraObjs:   []client.Object{eppSvc},
			wantParents: 1,
			assert: func(t *testing.T, ps gateway_inf_ext.ParentStatus) {
				requireCond(t, ps, "Accepted", metav1.ConditionTrue, "Accepted")
				requireCond(t, ps, "ResolvedRefs", metav1.ConditionTrue, "ResolvedRefs")
			},
		},
		{
			name:        "referenced, EPP Service missing",
			pool:        pool(eppRef),
			routes:      []gatewayv1.HTTPRoute{route},
			wantParents: 1,
			assert: func(t *testing.T, ps gateway_inf_ext.ParentStatus) {
				requireCond(t, ps, "Accepted", metav1.ConditionTrue, "Accepted")
				requireCond(t, ps, "ResolvedRefs", metav1.ConditionFalse, "InvalidExtensionRef")
			},
		},
		{
			name:        "referenced, no endpointPickerRef",
			pool:        pool(nil),
			routes:      []gatewayv1.HTTPRoute{route},
			wantParents: 1,
			assert: func(t *testing.T, ps gateway_inf_ext.ParentStatus) {
				requireCond(t, ps, "Accepted", metav1.ConditionFalse, "EndpointPickerRefMissing")
			},
		},
		{
			name:        "not referenced by this gateway",
			pool:        pool(eppRef),
			routes:      nil,
			wantParents: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			objs := append([]client.Object{tc.pool}, tc.extraObjs...)
			c := fake.NewClientBuilder().
				WithScheme(testhelpers.TestScheme(helpers.AllOptionalKinds, helpers.RegisterGatewayAPITypesToScheme)).
				WithStatusSubresource(&gateway_inf_ext.InferencePool{}).
				WithObjects(objs...).
				Build()

			// Pull the stored pool so it carries the resourceVersion Status().Update needs.
			stored := &gateway_inf_ext.InferencePool{}
			require.NoError(t, c.Get(ctx, types.NamespacedName{Namespace: "default", Name: "pool"}, stored))

			m := NewInferencePoolStatusManager(c, controllerName)
			require.NoError(t, m.SetInferencePoolStatuses(ctx, hivetest.Logger(t), gwName,
				[]gateway_inf_ext.InferencePool{*stored}, tc.routes))

			got := &gateway_inf_ext.InferencePool{}
			require.NoError(t, c.Get(ctx, types.NamespacedName{Namespace: "default", Name: "pool"}, got))
			require.Len(t, got.Status.Parents, tc.wantParents)
			if tc.wantParents == 1 {
				require.Equal(t, controllerName, string(got.Status.Parents[0].ControllerName))
				tc.assert(t, got.Status.Parents[0])
			}
		})
	}
}

func requireCond(t *testing.T, ps gateway_inf_ext.ParentStatus, condType string, status metav1.ConditionStatus, reason string) {
	cond := meta.FindStatusCondition(ps.Conditions, condType)
	require.NotNil(t, cond, "condition %q not found", condType)
	require.Equal(t, status, cond.Status)
	require.Equal(t, reason, cond.Reason)
}
