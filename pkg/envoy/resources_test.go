// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	envoyAPI "github.com/cilium/proxy/go/cilium/api"
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/envoy/config"
)

func TestCiliumConfigSource(t *testing.T) {
	tests := []struct {
		mode    config.XDSMode
		apiType envoy_config_core.ApiConfigSource_ApiType
		ads     bool
	}{
		{mode: config.EnvoyXDSModeSplit, apiType: envoy_config_core.ApiConfigSource_GRPC},
		{mode: config.EnvoyXDSModeDeltaSplit, apiType: envoy_config_core.ApiConfigSource_DELTA_GRPC},
		{mode: config.EnvoyXDSModeADS, ads: true},
		{mode: config.EnvoyXDSModeDeltaADS, ads: true},
		{mode: config.EnvoyXDSModeStrictADS, ads: true},
		{mode: config.EnvoyXDSModeStrictDeltaADS, ads: true},
	}

	for _, tt := range tests {
		t.Run(tt.mode.String(), func(t *testing.T) {
			source := CiliumConfigSource(tt.mode)
			require.NotNil(t, source)
			if tt.ads {
				require.NotNil(t, source.GetAds())
				require.Nil(t, source.GetApiConfigSource())
				return
			}
			require.Nil(t, source.GetAds())
			require.Equal(t, tt.apiType, source.GetApiConfigSource().GetApiType())
		})
	}
}

func TestCiliumADSConfigSource(t *testing.T) {
	tests := []struct {
		mode    config.XDSMode
		apiType envoy_config_core.ApiConfigSource_ApiType
	}{
		{mode: config.EnvoyXDSModeADS, apiType: envoy_config_core.ApiConfigSource_GRPC},
		{mode: config.EnvoyXDSModeDeltaADS, apiType: envoy_config_core.ApiConfigSource_DELTA_GRPC},
		{mode: config.EnvoyXDSModeStrictADS, apiType: envoy_config_core.ApiConfigSource_GRPC},
		{mode: config.EnvoyXDSModeStrictDeltaADS, apiType: envoy_config_core.ApiConfigSource_DELTA_GRPC},
	}

	for _, tt := range tests {
		t.Run(tt.mode.String(), func(t *testing.T) {
			source := CiliumADSConfigSource(tt.mode)
			require.Equal(t, tt.apiType, source.GetApiType())
			require.Equal(t, envoy_config_core.ApiVersion_V3, source.GetTransportApiVersion())
			require.True(t, source.GetSetNodeOnFirstMessageOnly())
			require.Equal(t, CiliumXDSClusterName, source.GetGrpcServices()[0].GetEnvoyGrpc().GetClusterName())
		})
	}
}

func TestHandleIPUpsert(t *testing.T) {
	cache := newNPHDSCache(hivetest.Logger(t), nil)

	msg := cache.Lookup(NetworkPolicyHostsTypeURL, "123")
	require.Nil(t, msg)

	err := cache.handleIPUpsert(nil, "123", "1.2.3.0/32", 123)
	require.NoError(t, err)

	msg = cache.Lookup(NetworkPolicyHostsTypeURL, "123")
	require.NotNil(t, msg)
	npHost := msg.(*envoyAPI.NetworkPolicyHosts)
	require.NotNil(t, npHost)
	require.Equal(t, uint64(123), npHost.Policy)
	require.Len(t, npHost.HostAddresses, 1)
	require.Equal(t, "1.2.3.0/32", npHost.HostAddresses[0])

	// Another address
	err = cache.handleIPUpsert(npHost, "123", "::1/128", 123)
	require.NoError(t, err)

	msg = cache.Lookup(NetworkPolicyHostsTypeURL, "123")
	require.NotNil(t, msg)
	npHost = msg.(*envoyAPI.NetworkPolicyHosts)
	require.NotNil(t, npHost)
	require.Equal(t, uint64(123), npHost.Policy)
	require.Len(t, npHost.HostAddresses, 2)
	require.Equal(t, "1.2.3.0/32", npHost.HostAddresses[0])
	require.Equal(t, "::1/128", npHost.HostAddresses[1])

	// Check that duplicates are not added, and not erroring out
	err = cache.handleIPUpsert(npHost, "123", "1.2.3.0/32", 123)
	require.NoError(t, err)

	msg = cache.Lookup(NetworkPolicyHostsTypeURL, "123")
	require.NotNil(t, msg)
	npHost = msg.(*envoyAPI.NetworkPolicyHosts)
	require.NotNil(t, npHost)
	require.Equal(t, uint64(123), npHost.Policy)
	require.Len(t, npHost.HostAddresses, 2)
	require.Equal(t, "1.2.3.0/32", npHost.HostAddresses[0])
	require.Equal(t, "::1/128", npHost.HostAddresses[1])
}
