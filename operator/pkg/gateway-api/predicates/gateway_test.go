// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package predicates

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers/testhelpers"
)

func Test_gatewayReconcilePredicate(t *testing.T) {
	logger := hivetest.Logger(t)
	c := fake.NewClientBuilder().WithScheme(helpers.TestScheme(helpers.AllOptionalKinds)).WithObjects(testhelpers.ControllerTestFixture...).Build()
	predicate := GatewayOwnedByController(helpers.GatewayHasMatchingControllerFn(t.Context(), c, helpers.CiliumDefaultControllerName, logger))

	t.Run("update keeps handoff reconcile when old gateway matched", func(t *testing.T) {
		require.True(t, predicate.Update(event.UpdateEvent{
			ObjectOld: &gatewayv1.Gateway{
				Spec: gatewayv1.GatewaySpec{GatewayClassName: "cilium"},
			},
			ObjectNew: &gatewayv1.Gateway{
				Spec: gatewayv1.GatewaySpec{GatewayClassName: "non-existent"},
			},
		}))
	})

	t.Run("create ignores gateway that never matched", func(t *testing.T) {
		require.False(t, predicate.Create(event.CreateEvent{
			Object: &gatewayv1.Gateway{
				Spec: gatewayv1.GatewaySpec{GatewayClassName: "non-existent"},
			},
		}))
	})
}
