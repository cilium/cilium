// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	envoyAPI "github.com/cilium/proxy/go/cilium/api"
	"github.com/stretchr/testify/require"
)

func TestHandleIPUpsert(t *testing.T) {
	cache := newNPHDSCache(hivetest.Logger(t), nil)

	msg, err := cache.Lookup(NetworkPolicyHostsTypeURL, "123")
	require.NoError(t, err)
	require.Nil(t, msg)

	err = cache.handleIPUpsert(nil, "123", "1.2.3.0/32", 123)
	require.NoError(t, err)

	msg, err = cache.Lookup(NetworkPolicyHostsTypeURL, "123")
	require.NoError(t, err)
	require.NotNil(t, msg)
	npHost := msg.(*envoyAPI.NetworkPolicyHosts)
	require.NotNil(t, npHost)
	require.Equal(t, uint64(123), npHost.Policy)
	require.Len(t, npHost.HostAddresses, 1)
	require.Equal(t, "1.2.3.0/32", npHost.HostAddresses[0])

	// Another address
	err = cache.handleIPUpsert(npHost, "123", "::1/128", 123)
	require.NoError(t, err)

	msg, err = cache.Lookup(NetworkPolicyHostsTypeURL, "123")
	require.NoError(t, err)
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

	msg, err = cache.Lookup(NetworkPolicyHostsTypeURL, "123")
	require.NoError(t, err)
	require.NotNil(t, msg)
	npHost = msg.(*envoyAPI.NetworkPolicyHosts)
	require.NotNil(t, npHost)
	require.Equal(t, uint64(123), npHost.Policy)
	require.Len(t, npHost.HostAddresses, 2)
	require.Equal(t, "1.2.3.0/32", npHost.HostAddresses[0])
	require.Equal(t, "::1/128", npHost.HostAddresses[1])
}
