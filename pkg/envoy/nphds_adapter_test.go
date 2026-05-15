// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"log/slog"
	"os"
	"testing"

	envoyAPI "github.com/cilium/proxy/go/cilium/api"
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	stream "github.com/envoyproxy/go-control-plane/pkg/server/stream/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/envoy/xdsnew"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
)

func newTestNPHDSAdapter(t *testing.T) *nphdsCacheAdapter {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	server := newADSServerWithCache(xdsnew.NewCache(logger), logger, nil, nil, xdsServerConfig{}, nil, nil)
	return newNPHDSCacheAdapter(logger, server)
}

func lookupNPHDS(t *testing.T, adapter *nphdsCacheAdapter, identityStr string) *envoyAPI.NetworkPolicyHosts {
	t.Helper()
	resources := adapter.store.networkPolicyHosts()
	res, ok := resources[identityStr]
	if !ok {
		return nil
	}
	return res
}

func testADSNPHDSCache(t *testing.T, adapter *nphdsCacheAdapter) xdsnew.Cache {
	t.Helper()
	server, ok := adapter.store.(*adsServer)
	require.True(t, ok)
	return server.cache
}

func TestNPHDSAdapterHandleIPUpsert(t *testing.T) {
	adapter := newTestNPHDSAdapter(t)

	// Initially empty
	require.Nil(t, lookupNPHDS(t, adapter, "123"))

	// Upsert first address
	err := adapter.handleIPUpsert("123", "1.2.3.0/32", 123)
	require.NoError(t, err)

	npHost := lookupNPHDS(t, adapter, "123")
	require.NotNil(t, npHost)
	assert.Equal(t, uint64(123), npHost.Policy)
	assert.Equal(t, []string{"1.2.3.0/32"}, npHost.HostAddresses)

	// Upsert second address — should be sorted
	err = adapter.handleIPUpsert("123", "::1/128", 123)
	require.NoError(t, err)

	npHost = lookupNPHDS(t, adapter, "123")
	require.NotNil(t, npHost)
	assert.Equal(t, uint64(123), npHost.Policy)
	assert.Len(t, npHost.HostAddresses, 2)
	assert.Equal(t, "1.2.3.0/32", npHost.HostAddresses[0])
	assert.Equal(t, "::1/128", npHost.HostAddresses[1])

	// Duplicate is a no-op
	err = adapter.handleIPUpsert("123", "1.2.3.0/32", 123)
	require.NoError(t, err)

	npHost = lookupNPHDS(t, adapter, "123")
	require.NotNil(t, npHost)
	assert.Len(t, npHost.HostAddresses, 2)
}

func TestNPHDSAdapterHandleIPDelete(t *testing.T) {
	adapter := newTestNPHDSAdapter(t)

	// Delete from nil is a no-op
	err := adapter.handleIPDelete("123", "1.2.3.0/32")
	require.NoError(t, err)

	// Seed two addresses
	require.NoError(t, adapter.handleIPUpsert("123", "1.2.3.0/32", 123))
	require.NoError(t, adapter.handleIPUpsert("123", "::1/128", 123))
	npHost := lookupNPHDS(t, adapter, "123")
	require.Len(t, npHost.HostAddresses, 2)

	// Delete one address
	err = adapter.handleIPDelete("123", "1.2.3.0/32")
	require.NoError(t, err)

	npHost = lookupNPHDS(t, adapter, "123")
	require.NotNil(t, npHost)
	assert.Equal(t, []string{"::1/128"}, npHost.HostAddresses)

	// Delete last address — resource should be removed
	err = adapter.handleIPDelete("123", "::1/128")
	require.NoError(t, err)

	require.Nil(t, lookupNPHDS(t, adapter, "123"))

	// Delete non-existent IP returns error
	require.NoError(t, adapter.handleIPUpsert("456", "10.0.0.1/32", 456))
	err = adapter.handleIPDelete("456", "10.0.0.2/32")
	require.Error(t, err)
}

func TestNPHDSAdapterOnIPIdentityCacheChange(t *testing.T) {
	adapter := newTestNPHDSAdapter(t)

	// Upsert via the full callback
	adapter.OnIPIdentityCacheChange(
		ipcache.Upsert,
		cmtypes.MustParsePrefixCluster("10.0.0.1/32"),
		nil, nil,
		nil,
		ipcache.Identity{ID: identity.NumericIdentity(100)},
		0, nil, 0,
	)

	npHost := lookupNPHDS(t, adapter, "100")
	require.NotNil(t, npHost)
	assert.Equal(t, uint64(100), npHost.Policy)
	assert.Equal(t, []string{"10.0.0.1/32"}, npHost.HostAddresses)

	// Upsert second CIDR to the same identity
	adapter.OnIPIdentityCacheChange(
		ipcache.Upsert,
		cmtypes.MustParsePrefixCluster("10.0.0.2/32"),
		nil, nil,
		nil,
		ipcache.Identity{ID: identity.NumericIdentity(100)},
		0, nil, 0,
	)

	npHost = lookupNPHDS(t, adapter, "100")
	require.NotNil(t, npHost)
	assert.Len(t, npHost.HostAddresses, 2)

	// Identity change: move 10.0.0.1/32 from identity 100 to 200.
	// This should delete it from 100 and add it to 200.
	oldID := &ipcache.Identity{ID: identity.NumericIdentity(100)}
	adapter.OnIPIdentityCacheChange(
		ipcache.Upsert,
		cmtypes.MustParsePrefixCluster("10.0.0.1/32"),
		nil, nil,
		oldID,
		ipcache.Identity{ID: identity.NumericIdentity(200)},
		0, nil, 0,
	)

	// Identity 100 should now only have 10.0.0.2/32
	npHost100 := lookupNPHDS(t, adapter, "100")
	require.NotNil(t, npHost100)
	assert.Equal(t, []string{"10.0.0.2/32"}, npHost100.HostAddresses)

	// Identity 200 should have 10.0.0.1/32
	npHost200 := lookupNPHDS(t, adapter, "200")
	require.NotNil(t, npHost200)
	assert.Equal(t, uint64(200), npHost200.Policy)
	assert.Equal(t, []string{"10.0.0.1/32"}, npHost200.HostAddresses)

	// Delete via the full callback
	adapter.OnIPIdentityCacheChange(
		ipcache.Delete,
		cmtypes.MustParsePrefixCluster("10.0.0.2/32"),
		nil, nil,
		nil,
		ipcache.Identity{ID: identity.NumericIdentity(100)},
		0, nil, 0,
	)

	// Identity 100 should be gone (last address deleted)
	require.Nil(t, lookupNPHDS(t, adapter, "100"))
}

func TestNPHDSAdapterPublishesFullStateResponses(t *testing.T) {
	adapter := newTestNPHDSAdapter(t)
	req := &cache.Request{
		TypeUrl:       NetworkPolicyHostsTypeURL,
		ResourceNames: []string{"*"},
		Node:          &envoy_config_core.Node{Id: localNodeID},
	}
	subscription := stream.NewSotwSubscription(req.GetResourceNames(), false)

	require.NoError(t, adapter.handleIPUpsert("100", "10.0.0.1/32", 100))

	respChan := make(chan cache.Response, 1)
	cancel, err := testADSNPHDSCache(t, adapter).CreateWatch(req, subscription, respChan)
	require.NoError(t, err)
	require.NotNil(t, cancel)
	defer cancel()

	firstResponse := <-respChan
	firstDiscoveryResponse, err := firstResponse.GetDiscoveryResponse()
	require.NoError(t, err)
	require.Len(t, firstDiscoveryResponse.Resources, 1)
	subscription.SetReturnedResources(firstResponse.GetReturnedResources())
	req.VersionInfo, err = firstResponse.GetVersion()
	require.NoError(t, err)

	require.NoError(t, adapter.handleIPUpsert("200", "10.0.0.2/32", 200))

	respChan = make(chan cache.Response, 1)
	cancel, err = testADSNPHDSCache(t, adapter).CreateWatch(req, subscription, respChan)
	require.NoError(t, err)
	require.NotNil(t, cancel)
	defer cancel()

	secondResponse := <-respChan
	secondDiscoveryResponse, err := secondResponse.GetDiscoveryResponse()
	require.NoError(t, err)
	require.Len(t, secondDiscoveryResponse.Resources, 2)
	assert.Contains(t, secondResponse.GetReturnedResources(), "100")
	assert.Contains(t, secondResponse.GetReturnedResources(), "200")
}

func TestStartNPHDSIPCacheListener(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	adsCache := xdsnew.NewCache(logger)
	server := newADSServerWithCache(adsCache, logger, nil, nil, xdsServerConfig{}, nil, nil)

	// nil ipCache should be a no-op
	startNPHDSIPCacheListener(logger, nil, server)

	// With a mock ipCache, the adapter should be registered
	mock := &mockIPCacheEventSource{}
	startNPHDSIPCacheListener(logger, mock, server)
	assert.Equal(t, 1, mock.listenerCount)
}

type mockIPCacheEventSource struct {
	listenerCount int
}

func (m *mockIPCacheEventSource) AddListener(listener ipcache.IPIdentityMappingListener) {
	m.listenerCount++
}
