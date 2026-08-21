// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_tcp "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/crypto/certificatemanager"
	"github.com/cilium/cilium/pkg/envoy/config"
	util "github.com/cilium/cilium/pkg/envoy/util"
	"github.com/cilium/cilium/pkg/envoy/xds"
	testipcache "github.com/cilium/cilium/pkg/testutils/ipcache"
)

const (
	deltaScenarioClusterName  = "xds-scenario-cluster"
	deltaScenarioListenerName = "xds-scenario-listener"
	deltaScenarioAddressA     = "10.0.0.1"
	deltaScenarioAddressB     = "10.0.0.2"
)

type realEnvoyScenarioCheck struct {
	configType string
	needle     string
	present    bool
	activeOnly bool
}

type realEnvoyScenarioStep struct {
	name   string
	apply  func(*realEnvoyScenarioRunner) error
	checks []realEnvoyScenarioCheck
}

type realEnvoyScenario struct {
	name  string
	steps []realEnvoyScenarioStep
}

type realEnvoyScenarioRunner struct {
	t      *testing.T
	mode   config.XDSMode
	logger *slog.Logger
	ctx    context.Context
	cancel context.CancelFunc
	runDir string

	server       runnableXDSServer
	serverErrors chan error
	envoy        *StandaloneEnvoy
	baseID       uint64
}

func newRealEnvoyScenarioRunner(t *testing.T, mode config.XDSMode, baseID uint64) *realEnvoyScenarioRunner {
	t.Helper()

	runDir, err := os.MkdirTemp("", "cilium-xds-scenario-")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	serverConfig := xdsServerConfig{
		envoySocketDir: util.GetSocketDir(runDir),
		proxyGID:       1337,
		envoyXDSMode:   mode,
		metrics:        xds.NewXDSMetric(),
	}
	localEndpointStore := newLocalEndpointStore()
	secretManager := certificatemanager.NewMockSecretManagerSDS()
	ipCache := testipcache.NewMockIPCache()

	var server runnableXDSServer
	if mode.IsADS() {
		server = newADSServer(logger, ipCache, localEndpointStore, serverConfig, secretManager, nil)
	} else {
		server = newXDSServer(logger, nil, ipCache, localEndpointStore, serverConfig, secretManager)
	}

	runner := &realEnvoyScenarioRunner{
		t: t, mode: mode, logger: logger, ctx: ctx, cancel: cancel, runDir: runDir,
		server: server, serverErrors: make(chan error, 1), baseID: baseID,
	}
	go func() {
		runner.serverErrors <- server.run(ctx)
	}()
	require.NoError(t, runner.startEnvoy())
	t.Cleanup(runner.close)
	return runner
}

func (r *realEnvoyScenarioRunner) startEnvoy() error {
	starter := &onDemandXdsStarter{logger: r.logger}
	envoy, err := starter.startStandaloneEnvoyInternal(standaloneEnvoyConfig{
		runDir:                         r.runDir,
		logPath:                        filepath.Join(r.runDir, "cilium-envoy.log"),
		baseID:                         r.baseID,
		connectTimeout:                 1,
		maxActiveDownstreamConnections: 100,
		idleTimeout:                    60 * time.Second,
		maxConcurrentRetries:           16,
		maxConnections:                 128,
		maxRequests:                    128,
		maxPendingRequests:             128,
		xdsMode:                        r.mode,
	})
	if err != nil {
		return err
	}
	r.envoy = envoy
	return nil
}

func (r *realEnvoyScenarioRunner) stopEnvoy() error {
	if r.envoy == nil {
		return nil
	}
	err := r.envoy.Stop()
	r.envoy = nil
	return err
}

func (r *realEnvoyScenarioRunner) restartEnvoy() error {
	if err := r.stopEnvoy(); err != nil {
		return err
	}
	return r.startEnvoy()
}

func (r *realEnvoyScenarioRunner) close() {
	require.NoError(r.t, r.stopEnvoy())
	r.cancel()
	select {
	case err := <-r.serverErrors:
		require.True(r.t, err == nil || errors.Is(err, context.Canceled), "xDS server stopped with %v", err)
	case <-time.After(5 * time.Second):
		r.t.Error("timed out waiting for xDS server to stop")
	}
	require.NoError(r.t, os.RemoveAll(r.runDir))
}

func (r *realEnvoyScenarioRunner) applyResourceUpdate(update func(context.Context, *completion.WaitGroup) error) error {
	ctx, cancel := context.WithTimeout(r.ctx, 10*time.Second)
	defer cancel()
	wg := completion.NewWaitGroup(ctx)
	if err := update(ctx, wg); err != nil {
		return err
	}
	return wg.Wait()
}

func (r *realEnvoyScenarioRunner) waitForConfig(check realEnvoyScenarioCheck) error {
	deadline := time.Now().Add(10 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		body, err := r.envoy.GetAdminClient().Get("config_dump?include_eds")
		contains := configDumpContains(body, check.configType, check.needle)
		if check.activeOnly {
			contains = activeConfigDumpContains(body, check.configType, check.needle)
		}
		if err == nil && contains == check.present {
			return nil
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("Envoy config %q presence for %q did not become %t: %v", check.configType, check.needle, check.present, lastErr)
}

func activeConfigDumpContains(body, configType, needle string) bool {
	var dump struct {
		Configs []map[string]any `json:"configs"`
	}
	if err := json.Unmarshal([]byte(body), &dump); err != nil {
		return false
	}

	for _, config := range dump.Configs {
		typeURL, _ := config["@type"].(string)
		if !strings.Contains(typeURL, configType) {
			continue
		}

		var activeEntries any
		switch configType {
		case "ListenersConfigDump":
			listeners, _ := config["dynamic_listeners"].([]any)
			active := make([]any, 0, len(listeners))
			for _, listener := range listeners {
				entry, _ := listener.(map[string]any)
				if state, exists := entry["active_state"]; exists {
					active = append(active, state)
				}
			}
			activeEntries = active
		case "ClustersConfigDump":
			activeEntries = config["dynamic_active_clusters"]
		case "EndpointsConfigDump":
			activeEntries = config["dynamic_endpoint_configs"]
		default:
			activeEntries = config
		}

		encoded, err := json.Marshal(activeEntries)
		if err == nil && strings.Contains(string(encoded), needle) {
			return true
		}
	}
	return false
}

func (r *realEnvoyScenarioRunner) run(scenario realEnvoyScenario) {
	r.t.Helper()
	for _, step := range scenario.steps {
		started := time.Now()
		require.NoErrorf(r.t, step.apply(r), "scenario %q step %q failed", scenario.name, step.name)
		for _, check := range step.checks {
			require.NoErrorf(r.t, r.waitForConfig(check), "scenario %q step %q failed", scenario.name, step.name)
		}
		r.t.Logf("xDS scenario %q step %q completed in %s", scenario.name, step.name, time.Since(started))
	}
}

func deltaScenarioEndpoint(address string) *envoy_config_endpoint.ClusterLoadAssignment {
	return &envoy_config_endpoint.ClusterLoadAssignment{
		ClusterName: deltaScenarioClusterName,
		Endpoints: []*envoy_config_endpoint.LocalityLbEndpoints{{
			LbEndpoints: []*envoy_config_endpoint.LbEndpoint{{
				HostIdentifier: &envoy_config_endpoint.LbEndpoint_Endpoint{
					Endpoint: &envoy_config_endpoint.Endpoint{
						Address: &envoy_config_core.Address{
							Address: &envoy_config_core.Address_SocketAddress{
								SocketAddress: &envoy_config_core.SocketAddress{
									Protocol: envoy_config_core.SocketAddress_TCP,
									Address:  address,
									PortSpecifier: &envoy_config_core.SocketAddress_PortValue{
										PortValue: 8080,
									},
								},
							},
						},
					},
				},
			}},
		}},
	}
}

func deltaScenarioResources(mode config.XDSMode, endpointAddress string, listenerPort uint32) xds.Resources {
	resources := xds.NewResources()
	resources.Clusters[deltaScenarioClusterName] = &envoy_config_cluster.Cluster{
		Name:           deltaScenarioClusterName,
		ConnectTimeout: durationpb.New(time.Second),
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{
			Type: envoy_config_cluster.Cluster_EDS,
		},
		EdsClusterConfig: &envoy_config_cluster.Cluster_EdsClusterConfig{
			EdsConfig:   CiliumConfigSource(mode),
			ServiceName: deltaScenarioClusterName,
		},
		LbPolicy: envoy_config_cluster.Cluster_ROUND_ROBIN,
	}
	resources.Endpoints[deltaScenarioClusterName] = deltaScenarioEndpoint(endpointAddress)
	resources.Listeners[deltaScenarioListenerName] = &envoy_config_listener.Listener{
		Name: deltaScenarioListenerName,
		Address: &envoy_config_core.Address{
			Address: &envoy_config_core.Address_SocketAddress{
				SocketAddress: &envoy_config_core.SocketAddress{
					Protocol: envoy_config_core.SocketAddress_TCP,
					Address:  "127.0.0.1",
					PortSpecifier: &envoy_config_core.SocketAddress_PortValue{
						PortValue: listenerPort,
					},
				},
			},
		},
		FilterChains: []*envoy_config_listener.FilterChain{{
			Filters: []*envoy_config_listener.Filter{{
				Name: "envoy.filters.network.tcp_proxy",
				ConfigType: &envoy_config_listener.Filter_TypedConfig{
					TypedConfig: ToAny(&envoy_config_tcp.TcpProxy{
						StatPrefix: "xds_scenario",
						ClusterSpecifier: &envoy_config_tcp.TcpProxy_Cluster{
							Cluster: deltaScenarioClusterName,
						},
					}),
				},
			}},
		}},
	}
	return resources
}

func deltaEndpointScenario(mode config.XDSMode, listenerPort uint32) realEnvoyScenario {
	initial := deltaScenarioResources(mode, deltaScenarioAddressA, listenerPort)
	updated := deltaScenarioResources(mode, deltaScenarioAddressB, listenerPort)
	oldEndpoint := xds.NewResources()
	oldEndpoint.Endpoints[deltaScenarioClusterName] = initial.Endpoints[deltaScenarioClusterName]
	newEndpoint := xds.NewResources()
	newEndpoint.Endpoints[deltaScenarioClusterName] = updated.Endpoints[deltaScenarioClusterName]

	return realEnvoyScenario{
		name: "sparse endpoint update and reconnect",
		steps: []realEnvoyScenarioStep{
			{
				name: "initial publish",
				apply: func(runner *realEnvoyScenarioRunner) error {
					return runner.applyResourceUpdate(func(ctx context.Context, wg *completion.WaitGroup) error {
						return runner.server.UpsertEnvoyResources(ctx, initial, wg)
					})
				},
				checks: []realEnvoyScenarioCheck{{configType: "EndpointsConfigDump", needle: deltaScenarioAddressA, present: true, activeOnly: true}},
			},
			{
				name: "sparse endpoint update",
				apply: func(runner *realEnvoyScenarioRunner) error {
					return runner.applyResourceUpdate(func(ctx context.Context, wg *completion.WaitGroup) error {
						return runner.server.UpdateEnvoyResources(ctx, oldEndpoint, newEndpoint, wg)
					})
				},
				checks: []realEnvoyScenarioCheck{
					{configType: "EndpointsConfigDump", needle: deltaScenarioAddressA, present: false, activeOnly: true},
					{configType: "EndpointsConfigDump", needle: deltaScenarioAddressB, present: true, activeOnly: true},
				},
			},
			{
				name:  "Envoy reconnect",
				apply: func(runner *realEnvoyScenarioRunner) error { return runner.restartEnvoy() },
				checks: []realEnvoyScenarioCheck{
					{configType: "EndpointsConfigDump", needle: deltaScenarioAddressA, present: false, activeOnly: true},
					{configType: "EndpointsConfigDump", needle: deltaScenarioAddressB, present: true, activeOnly: true},
				},
			},
			{
				name: "delete resource graph",
				apply: func(runner *realEnvoyScenarioRunner) error {
					return runner.applyResourceUpdate(func(ctx context.Context, wg *completion.WaitGroup) error {
						return runner.server.DeleteEnvoyResources(ctx, updated, wg)
					})
				},
				checks: []realEnvoyScenarioCheck{
					{configType: "ListenersConfigDump", needle: deltaScenarioListenerName, present: false, activeOnly: true},
					{configType: "ClustersConfigDump", needle: deltaScenarioClusterName, present: false, activeOnly: true},
					{configType: "EndpointsConfigDump", needle: deltaScenarioClusterName, present: false, activeOnly: true},
				},
			},
		},
	}
}

func TestEnvoyDeltaResourceScenario(t *testing.T) {
	if os.Getenv("CILIUM_ENABLE_ENVOY_UNIT_TEST") == "" {
		t.Skip("skipping Envoy scenario test; CILIUM_ENABLE_ENVOY_UNIT_TEST not set")
	}

	for index, mode := range []config.XDSMode{
		config.EnvoyXDSModeDeltaSplit,
		config.EnvoyXDSModeDeltaADS,
	} {
		t.Run(mode.String(), func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			require.NoError(t, err)
			listenerPort := uint32(listener.Addr().(*net.TCPAddr).Port)
			require.NoError(t, listener.Close())

			runner := newRealEnvoyScenarioRunner(t, mode, uint64(40+index))
			runner.run(deltaEndpointScenario(mode, listenerPort))
		})
	}
}
