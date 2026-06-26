// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"errors"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stesting "k8s.io/client-go/testing"

	k8sTestClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/option"
)

func disabledDaemonCfg(featureEnabled bool) *option.DaemonConfig {
	return &option.DaemonConfig{EnableCiliumNetworkDriver: featureEnabled}
}

// TestRegisterAllocator verifies that registerAllocator is a no-op when
// either the Kubernetes client is disabled or the NetworkDriver feature flag
// is turned off.
func TestRegisterAllocator(t *testing.T) {
	t.Run("no-op when client is disabled", func(t *testing.T) {
		fcs, cs := k8sTestClient.NewFakeClientset(hivetest.Logger(t))
		fcs.Disable()
		// Should return without panicking or registering anything.
		registerAllocator(AllocatorParams{
			Clientset: cs,
			DaemonCfg: disabledDaemonCfg(true),
		})
	})

	t.Run("no-op when feature is disabled", func(t *testing.T) {
		_, cs := k8sTestClient.NewFakeClientset(hivetest.Logger(t))
		registerAllocator(AllocatorParams{
			Clientset: cs,
			DaemonCfg: disabledDaemonCfg(false),
		})
	})
}

// TestAutoCreatePools verifies autoCreatePools error handling:
// all pool specs are validated first; if any are invalid the function returns
// an error immediately without creating anything. AlreadyExists and other
// create errors on valid pools are logged but do not cause a return error.
func TestAutoCreatePools(t *testing.T) {
	const validSpec = "ipv4-cidrs:10.0.0.0/8;ipv4-mask-size:24"

	t.Run("does not create any pool when at least one spec is invalid", func(t *testing.T) {
		fcs, cs := k8sTestClient.NewFakeClientset(hivetest.Logger(t))

		createCalled := false
		fcs.CiliumFakeClientset.Fake.PrependReactor("create", "ciliumresourceippools",
			func(action k8stesting.Action) (bool, runtime.Object, error) {
				createCalled = true
				return false, nil, nil
			})

		err := autoCreatePools(
			context.Background(),
			cs.CiliumV2alpha1().CiliumResourceIPPools(),
			map[string]string{
				"good-pool": validSpec,
				"bad-pool":  "not-a-valid-spec",
			},

			hivetest.Logger(t),
		)

		require.Error(t, err)
		require.False(t, createCalled, "no pool should be created when any spec is invalid")
	})

	t.Run("silently skips AlreadyExists on create", func(t *testing.T) {
		fcs, cs := k8sTestClient.NewFakeClientset(hivetest.Logger(t))
		fcs.CiliumFakeClientset.Fake.PrependReactor("create", "ciliumresourceippools",
			func(action k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, k8sErrors.NewAlreadyExists(
					schema.GroupResource{Resource: "ciliumresourceippools"}, "test-pool")
			})

		require.NoError(t, autoCreatePools(
			context.Background(),
			cs.CiliumV2alpha1().CiliumResourceIPPools(),
			map[string]string{"test-pool": validSpec},
			hivetest.Logger(t),
		))
	})

	t.Run("sets first and last IP flags from pool spec", func(t *testing.T) {
		_, cs := k8sTestClient.NewFakeClientset(hivetest.Logger(t))

		require.NoError(t, autoCreatePools(
			t.Context(),
			cs.CiliumV2alpha1().CiliumResourceIPPools(),
			map[string]string{
				"test-pool": validSpec + ";allow-first-ip:true;allow-last-ip:true",
			},
			hivetest.Logger(t),
		))

		pool, err := cs.CiliumV2alpha1().CiliumResourceIPPools().Get(
			context.Background(),
			"test-pool",
			metav1.GetOptions{},
		)
		require.NoError(t, err)
		require.True(t, pool.Spec.AllowFirstIP)
		require.True(t, pool.Spec.AllowLastIP)
	})

	t.Run("silently skips other create errors", func(t *testing.T) {
		fcs, cs := k8sTestClient.NewFakeClientset(hivetest.Logger(t))
		fcs.CiliumFakeClientset.Fake.PrependReactor("create", "ciliumresourceippools",
			func(action k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, errors.New("internal server error")
			})

		require.NoError(t, autoCreatePools(
			context.Background(),
			cs.CiliumV2alpha1().CiliumResourceIPPools(),
			map[string]string{"test-pool": validSpec},
			hivetest.Logger(t),
		))
	})
}

// TestCiliumResourceIPPool verifies that ciliumResourceIPPool returns nil
// when the Kubernetes client is disabled.
func TestCiliumResourceIPPool(t *testing.T) {
	t.Run("returns nil when client is disabled", func(t *testing.T) {
		fcs, cs := k8sTestClient.NewFakeClientset(hivetest.Logger(t))
		fcs.Disable()

		r, err := ciliumResourceIPPool(nil, cs, nil)
		require.NoError(t, err)
		require.Nil(t, r)
	})
}
