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
	t.Run("split leaves NpdsConfig unset", func(t *testing.T) {
		SetXDSMode(config.EnvoyXDSModeSplit)
		defer SetXDSMode("")

		lf := GetListenerFilter(true, false, 1234, -1)
		require.NotNil(t, lf)
		msg, err := lf.GetTypedConfig().UnmarshalNew()
		require.NoError(t, err)
		meta, ok := msg.(*cilium.BpfMetadata)
		require.True(t, ok)
		assert.Nil(t, meta.NpdsConfig)
	})

	t.Run("ADS sets NpdsConfig to ADS", func(t *testing.T) {
		SetXDSMode(config.EnvoyXDSModeADS)
		defer SetXDSMode("")

		lf := GetListenerFilter(true, false, 1234, -1)
		require.NotNil(t, lf)
		msg, err := lf.GetTypedConfig().UnmarshalNew()
		require.NoError(t, err)
		meta, ok := msg.(*cilium.BpfMetadata)
		require.True(t, ok)
		require.NotNil(t, meta.NpdsConfig)
		assert.NotNil(t, meta.NpdsConfig.GetAds(), "NpdsConfig should use ADS aggregated source")
		assert.Equal(t, envoy_config_core.ApiVersion_V3, meta.NpdsConfig.ResourceApiVersion)
	})
}
