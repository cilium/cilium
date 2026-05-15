// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"testing"

	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/option"
)

func TestGetListenerFilterADSMode(t *testing.T) {
	t.Run("ADS disabled: UseNphds not set", func(t *testing.T) {
		option.Config.EnvoyXDSMode = ""
		lf := GetListenerFilter(true, false, 1234, -1)
		require.NotNil(t, lf)
		msg, err := lf.GetTypedConfig().UnmarshalNew()
		require.NoError(t, err)
		meta, ok := msg.(*cilium.BpfMetadata)
		require.True(t, ok)
		assert.False(t, meta.UseNphds)
		assert.Nil(t, meta.NpdsConfig)
	})

	t.Run("ADS enabled: UseNphds and NpdsConfig set to ADS", func(t *testing.T) {
		option.Config.EnvoyXDSMode = option.EnvoyXDSModeADS
		defer func() { option.Config.EnvoyXDSMode = "" }()

		lf := GetListenerFilter(true, false, 1234, -1)
		require.NotNil(t, lf)
		msg, err := lf.GetTypedConfig().UnmarshalNew()
		require.NoError(t, err)
		meta, ok := msg.(*cilium.BpfMetadata)
		require.True(t, ok)
		assert.True(t, meta.UseNphds)
		require.NotNil(t, meta.NpdsConfig)
		assert.NotNil(t, meta.NpdsConfig.GetAds(), "NpdsConfig should use ADS aggregated source")
		assert.Equal(t, envoy_config_core.ApiVersion_V3, meta.NpdsConfig.ResourceApiVersion)
	})
}
