// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"testing"

	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	config "github.com/cilium/cilium/pkg/envoy/config"
)

func TestGetListenerFilterADSMode(t *testing.T) {
	t.Run("ADS disabled: UseNphds not set", func(t *testing.T) {
		SetXDSMode(config.EnvoyXDSModeSplit)
		defer SetXDSMode("")

		lf := GetListenerFilter(true, false, 1234, -1)
		require.NotNil(t, lf)
		msg, err := lf.GetTypedConfig().UnmarshalNew()
		require.NoError(t, err)
		meta, ok := msg.(*cilium.BpfMetadata)
		require.True(t, ok)
		assert.False(t, meta.UseNphds)
		assert.Nil(t, meta.CiliumConfigSource) // not set for the legacy SotW mode
	})

	t.Run("ADS enabled: CiliumConfigSource set to ADS without NPHDS", func(t *testing.T) {
		SetXDSMode(config.EnvoyXDSModeADS)
		defer SetXDSMode("")

		lf := GetListenerFilter(true, false, 1234, -1)
		require.NotNil(t, lf)
		msg, err := lf.GetTypedConfig().UnmarshalNew()
		require.NoError(t, err)
		meta, ok := msg.(*cilium.BpfMetadata)
		require.True(t, ok)
		assert.False(t, meta.UseNphds)
		require.NotNil(t, meta.CiliumConfigSource)
		assert.NotNil(t, meta.CiliumConfigSource.GetAds(), "CiliumConfigSource should use ADS aggregated source")
		assert.Equal(t, envoy_config_core.ApiVersion_V3, meta.CiliumConfigSource.ResourceApiVersion)
	})
}
