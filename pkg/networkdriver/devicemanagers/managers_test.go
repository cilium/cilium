// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package devicemanagers

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

func TestInitManagers(t *testing.T) {
	t.Run("nil config returns nil", func(t *testing.T) {
		mgrs, err := InitManagers(hivetest.Logger(t), nil)
		require.NoError(t, err)
		assert.Nil(t, mgrs)
	})

	t.Run("dummy disabled does not show up in the map", func(t *testing.T) {
		cfg := &v2alpha1.CiliumNetworkDriverDeviceManagerConfig{
			Dummy: &v2alpha1.DummyDeviceManagerConfig{Enabled: false, Count: 2},
		}
		mgrs, err := InitManagers(hivetest.Logger(t), cfg)
		require.NoError(t, err)
		assert.NotContains(t, mgrs, types.DeviceManagerTypeDummy)
	})

	t.Run("dummy enabled shows up in the map", func(t *testing.T) {
		cfg := &v2alpha1.CiliumNetworkDriverDeviceManagerConfig{
			Dummy: &v2alpha1.DummyDeviceManagerConfig{Enabled: true, Count: 2},
		}
		mgrs, err := InitManagers(hivetest.Logger(t), cfg)
		require.NoError(t, err)
		require.Contains(t, mgrs, types.DeviceManagerTypeDummy)
		assert.Equal(t, types.DeviceManagerTypeDummy, mgrs[types.DeviceManagerTypeDummy].Type())
	})

	t.Run("dummy config nil, not in map", func(t *testing.T) {
		cfg := &v2alpha1.CiliumNetworkDriverDeviceManagerConfig{
			Dummy: nil,
		}
		mgrs, err := InitManagers(hivetest.Logger(t), cfg)
		require.NoError(t, err)
		assert.NotContains(t, mgrs, types.DeviceManagerTypeDummy)
	})

	t.Run("dummy negative count return error", func(t *testing.T) {
		cfg := &v2alpha1.CiliumNetworkDriverDeviceManagerConfig{
			Dummy: &v2alpha1.DummyDeviceManagerConfig{Enabled: true, Count: -1},
		}
		mgrs, err := InitManagers(hivetest.Logger(t), cfg)
		require.Error(t, err)
		assert.NotContains(t, mgrs, types.DeviceManagerTypeDummy)

	})
}
