// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

func pool(name string, ifNames []string, pciAddrs []string, parentIfNames []string) v2alpha1.CiliumNetworkDriverDevicePoolConfig {
	return v2alpha1.CiliumNetworkDriverDevicePoolConfig{
		PoolName: name,
		Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{
			IfNames:       ifNames,
			PCIAddrs:      pciAddrs,
			ParentIfNames: parentIfNames,
		},
	}
}

func TestValidateFilters(t *testing.T) {
	t.Run("no conflict", func(t *testing.T) {
		err := validateFilters(
			pool("pool-a", []string{"eth0"}, []string{"0000:01:00.0"}, []string{"ens1f0"}),
			pool("pool-b", []string{"eth1"}, []string{"0000:02:00.0"}, []string{"ens2f0"}),
		)

		require.NoError(t, err)
	})

	t.Run("duplicate ifname across pools returns error", func(t *testing.T) {
		err := validateFilters(
			pool("pool-a", []string{"eth0"}, nil, nil),
			pool("pool-b", []string{"eth0"}, nil, nil),
		)

		require.ErrorIs(t, err, errIfNameInMultiplePools)
	})

	t.Run("duplicate PCI address across pools returns error", func(t *testing.T) {
		err := validateFilters(
			pool("pool-a", nil, []string{"0000:01:00.0"}, nil),
			pool("pool-b", nil, []string{"0000:01:00.0"}, nil),
		)

		require.ErrorIs(t, err, errPCIAddrInMultiplePools)
	})

	t.Run("duplicate parentIfName across pools returns error", func(t *testing.T) {
		err := validateFilters(
			pool("pool-a", nil, nil, []string{"ens1f0"}),
			pool("pool-b", nil, nil, []string{"ens1f0"}),
		)

		require.ErrorIs(t, err, errParentIfNameInMultiplePools)
	})
}

func TestValidatePools(t *testing.T) {
	t.Run("unique pool names and non-overlapping filters returns nil", func(t *testing.T) {
		err := validatePools(
			pool("pool-a", []string{"eth0"}, nil, nil),
			pool("pool-b", []string{"eth1"}, nil, nil),
		)

		require.NoError(t, err)
	})

	t.Run("duplicate pool name returns error", func(t *testing.T) {
		err := validatePools(
			pool("pool-a", nil, nil, nil),
			pool("pool-a", nil, nil, nil),
		)

		require.ErrorIs(t, err, errDuplicatedPoolName)
	})

	t.Run("overlapping ifname across distinct pool names returns error", func(t *testing.T) {
		err := validatePools(
			pool("pool-a", []string{"eth0"}, nil, nil),
			pool("pool-b", []string{"eth0"}, nil, nil),
		)

		require.ErrorIs(t, err, errIfNameInMultiplePools)
	})
}

func TestValidateConfig(t *testing.T) {
	t.Run("nil config is valid", func(t *testing.T) {
		require.NoError(t, validateConfig(nil))
	})

	t.Run("single pool is valid", func(t *testing.T) {
		require.NoError(t, validateConfig(&v2alpha1.CiliumNetworkDriverNodeConfigSpec{
			Pools: []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
				pool("pool-a", []string{"eth0"}, nil, nil),
			},
		}))
	})

	t.Run("two pools with non-overlapping filters are valid", func(t *testing.T) {
		require.NoError(t, validateConfig(&v2alpha1.CiliumNetworkDriverNodeConfigSpec{
			Pools: []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
				pool("pool-a", []string{"eth0"}, nil, nil),
				pool("pool-b", []string{"eth1"}, nil, nil),
			},
		}))
	})

	t.Run("two pools with duplicate name returns errBadConfig", func(t *testing.T) {
		err := validateConfig(&v2alpha1.CiliumNetworkDriverNodeConfigSpec{
			Pools: []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
				pool("pool-a", nil, nil, nil),
				pool("pool-a", nil, nil, nil),
			},
		})

		require.ErrorIs(t, err, errBadConfig)
		require.ErrorIs(t, err, errDuplicatedPoolName)
	})

	t.Run("two pools with overlapping ifname returns errBadConfig", func(t *testing.T) {
		err := validateConfig(&v2alpha1.CiliumNetworkDriverNodeConfigSpec{
			Pools: []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
				pool("pool-a", []string{"eth0"}, nil, nil),
				pool("pool-b", []string{"eth0"}, nil, nil),
			},
		})

		require.ErrorIs(t, err, errBadConfig)
		require.ErrorIs(t, err, errIfNameInMultiplePools)
	})

	t.Run("two pools with overlapping PCI address returns errBadConfig", func(t *testing.T) {
		err := validateConfig(&v2alpha1.CiliumNetworkDriverNodeConfigSpec{
			Pools: []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
				pool("pool-a", nil, []string{"0000:01:00.0"}, nil),
				pool("pool-b", nil, []string{"0000:01:00.0"}, nil),
			},
		})

		require.ErrorIs(t, err, errBadConfig)
		require.ErrorIs(t, err, errPCIAddrInMultiplePools)
	})

	t.Run("two pools with overlapping parentIfName returns errBadConfig", func(t *testing.T) {
		err := validateConfig(&v2alpha1.CiliumNetworkDriverNodeConfigSpec{
			Pools: []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
				pool("pool-a", nil, nil, []string{"ens1f0"}),
				pool("pool-b", nil, nil, []string{"ens1f0"}),
			},
		})

		require.ErrorIs(t, err, errBadConfig)
		require.ErrorIs(t, err, errParentIfNameInMultiplePools)
	})
}
