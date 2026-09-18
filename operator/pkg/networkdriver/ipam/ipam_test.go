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
)

func TestAutoCreatePools(t *testing.T) {
	const validSpec = "ipv4-cidrs:10.0.0.0/8;ipv4-mask-size:24"

	t.Run("validates all pools before creating any", func(t *testing.T) {
		fakeClientset, clientset := k8sTestClient.NewFakeClientset(hivetest.Logger(t))
		createCalled := false
		fakeClientset.CiliumFakeClientset.Fake.PrependReactor(
			"create",
			"ciliumresourceippools",
			func(k8stesting.Action) (bool, runtime.Object, error) {
				createCalled = true
				return false, nil, nil
			},
		)

		err := autoCreatePools(
			t.Context(),
			clientset.CiliumV2alpha1().CiliumResourceIPPools(),
			map[string]string{
				"valid":   validSpec,
				"invalid": "not-a-valid-spec",
			},
			hivetest.Logger(t),
		)
		require.Error(t, err)
		require.False(t, createCalled)
	})

	t.Run("creates dual-stack pool allowing first and last IP", func(t *testing.T) {
		_, clientset := k8sTestClient.NewFakeClientset(hivetest.Logger(t))

		err := autoCreatePools(
			t.Context(),
			clientset.CiliumV2alpha1().CiliumResourceIPPools(),
			map[string]string{
				"blue": validSpec + ";ipv6-cidrs:fd00::/64;ipv6-mask-size:80;allow-first-ip:true;allow-last-ip:true",
			},
			hivetest.Logger(t),
		)
		require.NoError(t, err)

		pool, err := clientset.CiliumV2alpha1().CiliumResourceIPPools().Get(
			context.Background(),
			"blue",
			metav1.GetOptions{},
		)
		require.NoError(t, err)
		require.Equal(t, uint8(24), pool.Spec.IPv4.MaskSize)
		require.Equal(t, uint8(80), pool.Spec.IPv6.MaskSize)
		require.True(t, pool.Spec.AllowFirstIP)
		require.True(t, pool.Spec.AllowLastIP)
	})

	t.Run("ignores an existing pool", func(t *testing.T) {
		fakeClientset, clientset := k8sTestClient.NewFakeClientset(hivetest.Logger(t))
		fakeClientset.CiliumFakeClientset.Fake.PrependReactor(
			"create",
			"ciliumresourceippools",
			func(k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, k8sErrors.NewAlreadyExists(
					schema.GroupResource{Resource: "ciliumresourceippools"},
					"blue",
				)
			},
		)

		require.NoError(t, autoCreatePools(
			t.Context(),
			clientset.CiliumV2alpha1().CiliumResourceIPPools(),
			map[string]string{"blue": validSpec},
			hivetest.Logger(t),
		))
	})

	t.Run("does not fail startup on a create error", func(t *testing.T) {
		fakeClientset, clientset := k8sTestClient.NewFakeClientset(hivetest.Logger(t))
		fakeClientset.CiliumFakeClientset.Fake.PrependReactor(
			"create",
			"ciliumresourceippools",
			func(k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, errors.New("injected create error")
			},
		)

		require.NoError(t, autoCreatePools(
			t.Context(),
			clientset.CiliumV2alpha1().CiliumResourceIPPools(),
			map[string]string{"blue": validSpec},
			hivetest.Logger(t),
		))
	})
}
