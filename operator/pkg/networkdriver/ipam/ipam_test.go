// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stesting "k8s.io/client-go/testing"

	"github.com/cilium/cilium/operator/pkg/ipam/allocator/multipool"
	iputil "github.com/cilium/cilium/pkg/ip"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sTestClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
)

func TestUpsertPoolPreservesReservedRanges(t *testing.T) {
	const poolName = "blue"

	poolCIDR := iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.0/24"))
	pool := &ciliumv2alpha1.CiliumResourceIPPool{
		ObjectMeta: metav1.ObjectMeta{Name: poolName},
		Spec: ciliumv2alpha1.ResourceIPPoolSpec{
			IPv4: &ciliumv2.IPv4PoolSpec{
				CIDRs:    []iputil.Prefix{poolCIDR},
				MaskSize: 28,
				Pool: []ciliumv2.PoolCIDRConfig{
					{
						CIDR: poolCIDR,
						ReservedRanges: []ciliumv2.ReservedRange{
							{Start: "10.0.0.1", End: "10.0.0.10"},
						},
					},
				},
			},
		},
	}

	allocator := multipool.NewPoolAllocator(hivetest.Logger(t), true, false)
	require.NoError(t, upsertPool(allocator, pool))
	allocator.RestoreFinished()

	require.NoError(t, allocator.AllocateToNode("node", ipamTypes.IPAMPoolSpec{
		Requested: []ipamTypes.IPAMPoolRequest{
			{
				Pool: poolName,
				Needed: ipamTypes.IPAMPoolDemand{
					IPv4Addrs: 1,
				},
			},
		},
	}))
	require.Equal(t, []ipamTypes.IPAMPoolAllocation{
		{
			Pool: poolName,
			CIDRs: []iputil.Prefix{
				iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.16/28")),
			},
		},
	}, allocator.AllocatedPools("node"))
}

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
		require.Equal(t, []iputil.Prefix{iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.0/8"))}, pool.Spec.IPv4.CIDRs)
		require.Equal(t, uint8(24), pool.Spec.IPv4.MaskSize)
		require.Equal(t, []iputil.Prefix{iputil.PrefixFrom(netip.MustParsePrefix("fd00::/64"))}, pool.Spec.IPv6.CIDRs)
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
