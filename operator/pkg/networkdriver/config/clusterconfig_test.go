// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"context"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb/reconciler"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"

	cilium_v2alpha1_api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sTestClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/option"
)

// TestDriverClusterConfigOps_Update verifies the Update operation's idempotency
// and error handling: it must surface unexpected API errors, and must skip
// UpdateStatus when the conflict condition on the K8s object already reflects
// the desired state (both for conflicting and non-conflicting cases).
func TestDriverClusterConfigOps_Update(t *testing.T) {
	t.Run("propagates non-NotFound Get error", func(t *testing.T) {
		fcs, cs := k8sTestClient.NewFakeClientset(hivetest.Logger(t))
		fcs.CiliumFakeClientset.Fake.PrependReactor("get", "ciliumnetworkdriverclusterconfigs",
			func(action k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, errPropagated
			})

		ops := &driverClusterConfigOps{client: cs.CiliumV2alpha1().CiliumNetworkDriverClusterConfigs()}
		err := ops.Update(context.Background(), nil, 0, &driverClusterConfig{Name: "cfg", IsConflicting: false})
		require.Error(t, err)
		require.ErrorIs(t, err, errPropagated)
	})

	t.Run("skips UpdateStatus when conflict condition is absent and IsConflicting is false", func(t *testing.T) {
		fcs, cs := k8sTestClient.NewFakeClientset(hivetest.Logger(t))
		_, err := cs.CiliumV2alpha1().CiliumNetworkDriverClusterConfigs().Create(
			context.Background(),
			&cilium_v2alpha1_api.CiliumNetworkDriverClusterConfig{
				ObjectMeta: metav1.ObjectMeta{Name: "cfg"},
			},
			metav1.CreateOptions{},
		)

		require.NoError(t, err)

		updateStatusCalled := false
		fcs.CiliumFakeClientset.Fake.PrependReactor("update", "ciliumnetworkdriverclusterconfigs",
			func(action k8stesting.Action) (bool, runtime.Object, error) {
				updateStatusCalled = true
				return false, nil, nil
			})

		ops := &driverClusterConfigOps{client: cs.CiliumV2alpha1().CiliumNetworkDriverClusterConfigs()}
		err = ops.Update(context.Background(), nil, 0, &driverClusterConfig{Name: "cfg", IsConflicting: false})
		require.NoError(t, err)
		require.False(t, updateStatusCalled, "UpdateStatus should not be called when status already reflects desired state")
	})

	t.Run("skips UpdateStatus when conflict condition is already set and IsConflicting is true", func(t *testing.T) {
		fcs, cs := k8sTestClient.NewFakeClientset(hivetest.Logger(t))
		cfg := &cilium_v2alpha1_api.CiliumNetworkDriverClusterConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "cfg"},
			Status: cilium_v2alpha1_api.CiliumNetworkDriverClusterConfigStatus{
				Conditions: []metav1.Condition{{
					Type:   cilium_v2alpha1_api.NetworkDriverClusterConfigConditionConflict,
					Status: metav1.ConditionTrue,
					Reason: cilium_v2alpha1_api.NetworkDriverClusterConfigReasonConflict,
				}},
			},
		}

		_, err := cs.CiliumV2alpha1().CiliumNetworkDriverClusterConfigs().Create(
			context.Background(), cfg, metav1.CreateOptions{})
		require.NoError(t, err)

		updateStatusCalled := false
		fcs.CiliumFakeClientset.Fake.PrependReactor("update", "ciliumnetworkdriverclusterconfigs",
			func(action k8stesting.Action) (bool, runtime.Object, error) {
				updateStatusCalled = true
				return false, nil, nil
			})

		ops := &driverClusterConfigOps{client: cs.CiliumV2alpha1().CiliumNetworkDriverClusterConfigs()}
		err = ops.Update(context.Background(), nil, 0, &driverClusterConfig{Name: "cfg", IsConflicting: true})
		require.NoError(t, err)
		require.False(t, updateStatusCalled, "UpdateStatus should not be called when conflict condition already set")
	})
}

// TestRegisterDriverClusterConfigReconciler verifies that the reconciler
// registration is a no-op when either the Kubernetes client is disabled
// or the NetworkDriver feature flag is turned off.
func TestRegisterDriverClusterConfigReconciler(t *testing.T) {
	t.Run("no-op when client is disabled", func(t *testing.T) {
		fcs, cs := k8sTestClient.NewFakeClientset(hivetest.Logger(t))
		fcs.Disable()
		err := registerDriverClusterConfigReconciler(
			reconciler.Params{}, nil, nil,
			&option.DaemonConfig{EnableCiliumNetworkDriver: true},
			cs,
		)

		require.NoError(t, err)
	})

	t.Run("no-op when feature is disabled", func(t *testing.T) {
		_, cs := k8sTestClient.NewFakeClientset(hivetest.Logger(t))
		err := registerDriverClusterConfigReconciler(
			reconciler.Params{}, nil, nil,
			&option.DaemonConfig{EnableCiliumNetworkDriver: false},
			cs,
		)

		require.NoError(t, err)
	})
}
