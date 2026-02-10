// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/time"
)

// TestNewADSServer verifies that a new ADS server is created correctly
func TestNewADSServer(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := adsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
		metrics:              nil,
	}

	server := newADSServer(logger, nil, nil, config, nil)

	require.NotNil(t, server)
	require.NotNil(t, server.logger)
	require.NotNil(t, &server.cache)
	assert.Equal(t, "proxy", server.socketPath)
}

// TestAddListener verifies that a listener can be added
func TestAddListener(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := adsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}

	server := newADSServer(logger, nil, nil, config, nil)
	ctx := context.Background()
	wg := completion.NewWaitGroup(ctx)

	err := server.AddListener(ctx, "test-listener", policy.ParserTypeHTTP, 8080, false, false, wg, func(err error) {
		if err != nil {
			t.Logf("callback received error: %v", err)
		}
	})

	assert.NoError(t, err)
}

// TestAddAdminListener verifies that an admin listener can be added
func TestAddAdminListener(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := adsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}

	server := newADSServer(logger, nil, nil, config, nil)
	ctx := context.Background()
	wg := completion.NewWaitGroup(ctx)

	// Should not panic and should handle port 0 gracefully
	server.AddAdminListener(ctx, 0, wg)

	// Test with valid port
	server.AddAdminListener(ctx, 9000, wg)
}

// TestAddMetricsListener verifies that a metrics listener can be added
func TestAddMetricsListener(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := adsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}

	server := newADSServer(logger, nil, nil, config, nil)
	ctx := context.Background()
	wg := completion.NewWaitGroup(ctx)

	// Should not panic and should handle port 0 gracefully
	server.AddMetricsListener(ctx, 0, wg)

	// Test with valid port
	server.AddMetricsListener(ctx, 9001, wg)
}

// TestRemoveListener verifies that a listener can be removed
func TestRemoveListener(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := adsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}

	server := newADSServer(logger, nil, nil, config, nil)
	ctx := context.Background()
	wg := completion.NewWaitGroup(ctx)

	// Add a listener first
	err := server.AddListener(ctx, "test-listener", policy.ParserTypeHTTP, 8080, false, false, wg, func(err error) {})
	require.NoError(t, err)

	// Remove the listener
	revertFunc := server.RemoveListener(ctx, "test-listener", wg)
	assert.NotNil(t, revertFunc)
}

// TestUpsertEnvoyResources verifies that Envoy resources can be upserted
func TestUpsertEnvoyResources(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := adsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}

	server := newADSServer(logger, nil, nil, config, nil)
	ctx := context.Background()

	resources := xds.Resources{
		Listeners:       make(map[string]*envoy_config_listener.Listener),
		Clusters:        make(map[string]*envoy_config_cluster.Cluster),
		Routes:          make(map[string]*envoy_config_route.RouteConfiguration),
		Endpoints:       make(map[string]*envoy_config_endpoint.ClusterLoadAssignment),
		Secrets:         make(map[string]*tlsv3.Secret),
		NetworkPolicies: make(map[string]*cilium.NetworkPolicy),
	}

	err := server.UpsertEnvoyResources(ctx, resources)
	assert.NoError(t, err)
}

// TestUpdateEnvoyResources verifies that Envoy resources can be updated
func TestUpdateEnvoyResources(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := adsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}

	server := newADSServer(logger, nil, nil, config, nil)
	ctx := context.Background()

	oldResources := xds.Resources{
		Listeners:       make(map[string]*envoy_config_listener.Listener),
		Clusters:        make(map[string]*envoy_config_cluster.Cluster),
		Routes:          make(map[string]*envoy_config_route.RouteConfiguration),
		Endpoints:       make(map[string]*envoy_config_endpoint.ClusterLoadAssignment),
		Secrets:         make(map[string]*tlsv3.Secret),
		NetworkPolicies: make(map[string]*cilium.NetworkPolicy),
	}

	newResources := xds.Resources{
		Listeners:       make(map[string]*envoy_config_listener.Listener),
		Clusters:        make(map[string]*envoy_config_cluster.Cluster),
		Routes:          make(map[string]*envoy_config_route.RouteConfiguration),
		Endpoints:       make(map[string]*envoy_config_endpoint.ClusterLoadAssignment),
		Secrets:         make(map[string]*tlsv3.Secret),
		NetworkPolicies: make(map[string]*cilium.NetworkPolicy),
	}

	err := server.UpdateEnvoyResources(ctx, oldResources, newResources)
	assert.NoError(t, err)
}

// TestDeleteEnvoyResources verifies that Envoy resources can be deleted
func TestDeleteEnvoyResources(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := adsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}

	server := newADSServer(logger, nil, nil, config, nil)
	ctx := context.Background()

	resources := xds.Resources{
		Listeners:       make(map[string]*envoy_config_listener.Listener),
		Clusters:        make(map[string]*envoy_config_cluster.Cluster),
		Routes:          make(map[string]*envoy_config_route.RouteConfiguration),
		Endpoints:       make(map[string]*envoy_config_endpoint.ClusterLoadAssignment),
		Secrets:         make(map[string]*tlsv3.Secret),
		NetworkPolicies: make(map[string]*cilium.NetworkPolicy),
	}

	err := server.DeleteEnvoyResources(ctx, resources)
	assert.NoError(t, err)
}

// TestGetNetworkPolicies verifies that network policies can be retrieved
func TestGetNetworkPolicies(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := adsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}

	server := newADSServer(logger, nil, nil, config, nil)

	// Get all network policies
	policies, err := server.GetNetworkPolicies(nil)
	assert.NoError(t, err)
	assert.NotNil(t, policies)

	// Get specific network policies
	policies, err = server.GetNetworkPolicies([]string{"policy1", "policy2"})
	assert.NoError(t, err)
	assert.NotNil(t, policies)
}

// TestUseCurrentNetworkPolicy verifies that current network policy can be used
// func TestUseCurrentNetworkPolicy(t *testing.T) {
// 	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
// 	config := adsServerConfig{
// 		envoySocketDir:       t.TempDir(),
// 		policyRestoreTimeout: 30 * time.Second,
// 	}

// 	server := newADSServer(logger, nil, nil, config, nil)
// 	ctx := context.Background()
// 	wg := completion.NewWaitGroup(ctx)

// 	// Create a mock endpoint updater
// 	mockEp := &mockEndpointUpdater{}

// 	// Create a mock policy
// 	mockPolicy := &policy.EndpointPolicy{}

// 	// Should not panic
// 	server.UseCurrentNetworkPolicy(mockEp, mockPolicy, wg)
// }

// TestUpdateNetworkPolicy verifies that network policy can be updated
// func TestUpdateNetworkPolicy(t *testing.T) {
// 	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
// 	config := adsServerConfig{
// 		envoySocketDir:       t.TempDir(),
// 		policyRestoreTimeout: 30 * time.Second,
// 	}

// 	server := newADSServer(logger, nil, nil, config, nil)
// 	ctx := context.Background()
// 	wg := completion.NewWaitGroup(ctx)

// 	// Create a mock endpoint updater
// 	mockEp := &mockEndpointUpdater{}

// 	// Create a mock policy
// 	mockPolicy := &policy.EndpointPolicy{}

// 	err, revertFunc := server.UpdateNetworkPolicy(ctx, mockEp, mockPolicy, wg)
// 	// This may return an error if policy is nil or invalid
// 	if err != nil {
// 		assert.Error(t, err)
// 	} else {
// 		assert.NotNil(t, revertFunc)
// 	}
// }

// // TestRemoveNetworkPolicy verifies that network policy can be removed
// func TestRemoveNetworkPolicy(t *testing.T) {
// 	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
// 	config := adsServerConfig{
// 		envoySocketDir:       t.TempDir(),
// 		policyRestoreTimeout: 30 * time.Second,
// 	}

// 	server := newADSServer(logger, nil, nil, config, nil)

// 	// Create a mock endpoint info source
// 	mockEp := &mockEndpointInfoSource{}

// 	// Should not panic
// 	server.RemoveNetworkPolicy(mockEp)
// }

// TestRemoveAllNetworkPolicies verifies that all network policies can be removed
func TestRemoveAllNetworkPolicies(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := adsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}

	server := newADSServer(logger, nil, nil, config, nil)

	// Should not panic
	server.RemoveAllNetworkPolicies()
}

// Mock types for testing

type mockEndpointUpdater struct{}

func (m *mockEndpointUpdater) GetID() uint64 {
	return 1
}

func (m *mockEndpointUpdater) GetPolicyNames() []string {
	return []string{"127.0.0.1"}
}

// func (m *mockEndpointUpdater) GetPolicySelectors() policy.SelectorSnapshot {
// 	return policy.MockSelectorSnapshot()
// }

func (m *mockEndpointUpdater) OnProxyPolicyUpdate(revision uint64) {
}

func (m *mockEndpointUpdater) UpdateProxyStatistics(proxyType, l4Protocol string, port, proxyPort uint16, ingress, request bool, verdict interface{}) {
}

func (m *mockEndpointUpdater) GetListenerProxyPort(listener string) uint16 {
	return 0
}

func (m *mockEndpointUpdater) GetNamedPort(ingress bool, name string, proto interface{}) uint16 {
	return 0
}

type mockEndpointInfoSource struct{}

func (m *mockEndpointInfoSource) GetID() uint64 {
	return 1
}

func (m *mockEndpointInfoSource) GetIPv4Address() string {
	return "127.0.0.1"
}

func (m *mockEndpointInfoSource) GetIPv6Address() string {
	return ""
}

func (m *mockEndpointInfoSource) GetPolicyNames() []string {
	return []string{"127.0.0.1"}
}

func (m *mockEndpointInfoSource) GetNamedPort(ingress bool, name string, proto interface{}) uint16 {
	return 0
}
