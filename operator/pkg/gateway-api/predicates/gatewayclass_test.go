// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package predicates

import (
	"testing"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/event"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
)

func Test_gatewayClassReconcilePredicate(t *testing.T) {
	predicate := GatewayClassOwnedByController(helpers.CiliumDefaultControllerName)

	t.Run("update keeps handoff reconcile when old gatewayclass matched", func(t *testing.T) {
		require.True(t, predicate.Update(event.UpdateEvent{
			ObjectOld: &gatewayv1.GatewayClass{
				Spec: gatewayv1.GatewayClassSpec{ControllerName: helpers.CiliumDefaultControllerName},
			},
			ObjectNew: &gatewayv1.GatewayClass{
				Spec: gatewayv1.GatewayClassSpec{ControllerName: "example.com/other-controller"},
			},
		}))
	})

	t.Run("create ignores unrelated gatewayclass", func(t *testing.T) {
		require.False(t, predicate.Create(event.CreateEvent{
			Object: &gatewayv1.GatewayClass{
				Spec: gatewayv1.GatewayClassSpec{ControllerName: "example.com/other-controller"},
			},
		}))
	})
}
