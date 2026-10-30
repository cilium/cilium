// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	envoyAPI "github.com/cilium/proxy/go/cilium/api"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/envoy/config"
)

func TestCiliumADSConfigSource(t *testing.T) {
	for _, test := range []struct {
		mode    config.XDSMode
		apiType core.ApiConfigSource_ApiType
	}{
		{config.EnvoyXDSModeADS, core.ApiConfigSource_GRPC},
		{config.EnvoyXDSModeDeltaADS, core.ApiConfigSource_DELTA_GRPC},
	} {
		t.Run(string(test.mode), func(t *testing.T) {
			require.Equal(t, test.apiType, CiliumADSConfigSource(test.mode).GetApiType())
			require.NotNil(t, CiliumConfigSource(test.mode).GetAds())
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
