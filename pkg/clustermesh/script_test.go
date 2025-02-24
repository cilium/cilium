// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh_test

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path"
	"testing"

	uhive "github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	"github.com/cilium/statedb"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/cilium/cilium/daemon/cmd/cni"
	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/clustermesh"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	cmutils "github.com/cilium/cilium/pkg/clustermesh/utils"
	"github.com/cilium/cilium/pkg/datapath/iptables/ipset"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/dial"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/testutils"
	"github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/loadbalancer"
	lbcell "github.com/cilium/cilium/pkg/loadbalancer/cell"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	nodemanager "github.com/cilium/cilium/pkg/node/manager"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

var debug = flag.Bool("debug", false, "Enable debug logging")

func TestScript(t *testing.T) {
	// Catch any leaked goroutines. Ignoring goroutines possibly left by other tests.
	leakOpts := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, leakOpts) })

	version.Force(testutils.DefaultVersion)

	var opts []hivetest.LogOption
	if *debug {
		opts = append(opts, hivetest.LogLevel(slog.LevelDebug))
		logging.SetLogLevelToDebug()
	}
	log := hivetest.Logger(t, opts...)

	// Due to the kvstore global variables we cannot run these tests in parallel
	// (scripttest calls t.Parallel()). Use a mutex to serialize the test execution.
	// Remove this once kvstore globals are removed.
	var serializeMu lock.Mutex

	setup := func(t testing.TB, args []string) *script.Engine {
		serializeMu.Lock()
		t.Cleanup(serializeMu.Unlock)

		storeFactory := store.NewFactory(hivetest.Logger(t), store.MetricsProvider())
		configDir := t.TempDir()

		h := hive.New(
			client.FakeClientCell,
			daemonk8s.ResourcesCell,
			daemonk8s.TablesCell,
			lbcell.Cell,

			maglev.Cell,
			node.LocalNodeStoreCell,
			cni.Cell,
			ipset.Cell,
			dial.ServiceResolverCell,
			metrics.Cell,

			cell.Config(cmtypes.DefaultClusterInfo),
			cell.Invoke(cmtypes.ClusterInfo.InitClusterIDMax, cmtypes.ClusterInfo.Validate),

			cell.Provide(
				tables.NewNodeAddressTable,
				statedb.RWTable[tables.NodeAddress].ToTable,
				source.NewSources,
				func() *option.DaemonConfig {
					// The LB control-plane still derives its configuration from DaemonConfig.
					return &option.DaemonConfig{
						EnableIPv4:           true,
						EnableIPv6:           true,
						EnableNodePort:       true,
						KubeProxyReplacement: option.KubeProxyReplacementTrue,
					}
				},
				func() store.Factory {
					return storeFactory
				},
				func() *loadbalancer.TestConfig {
					return &loadbalancer.TestConfig{}
				},
				clustermesh.NewClusterMeshMetricsNoop,
				func() clustermesh.RemoteIdentityWatcher {
					return dummyRemoteIdentityWatcher{}
				},
				func() k8s.ServiceCache {
					return nil
				},
				func(log *slog.Logger) nodemanager.NodeManager {
					return dummyNodeManager{log}
				},
				func() *ipcache.IPCache {
					return nil
				},
			),
			cell.Invoke(statedb.RegisterTable[tables.NodeAddress]),

			cell.Provide(func(db *statedb.DB) (kvstore.BackendOperations, uhive.ScriptCmdsOut) {
				kvstore.SetupInMemory(db)
				client := kvstore.SetupDummy(t, "in-memory")
				return client, uhive.NewScriptCmds(kvstoreCommands{client}.cmds())
			}),

			cell.Invoke(func(client kvstore.BackendOperations) {
				clusterConfig := []byte("endpoints:\n- in-memory\n")
				config1 := path.Join(configDir, "cluster1")
				require.NoError(t, os.WriteFile(config1, clusterConfig, 0644), "Failed to write config file for cluster1")
				config2 := path.Join(configDir, "cluster2")
				require.NoError(t, os.WriteFile(config2, clusterConfig, 0644), "Failed to write config file for cluster2")
				config3 := path.Join(configDir, "cluster3")
				require.NoError(t, os.WriteFile(config3, clusterConfig, 0644), "Failed to write config file for cluster3")

				for i, name := range []string{"cluster1", "cluster2", "cluster3"} {
					config := cmtypes.CiliumClusterConfig{
						ID: uint32(i + 1),
						Capabilities: cmtypes.CiliumClusterConfigCapabilities{
							MaxConnectedClusters: 255,
						},
					}
					err := cmutils.SetClusterConfig(context.TODO(), name, config, client)
					require.NoErrorf(t, err, "Failed to set cluster config for %s", name)
				}
			}),
			clustermesh.Cell,
		)

		flags := pflag.NewFlagSet("", pflag.ContinueOnError)
		h.RegisterFlags(flags)
		flags.Set("enable-experimental-lb", "true")
		flags.Set("clustermesh-config", configDir)

		// Parse the shebang arguments in the script.
		require.NoError(t, flags.Parse(args), "flags.Parse")

		t.Cleanup(func() {
			assert.NoError(t, h.Stop(log, context.TODO()))
		})
		cmds, err := h.ScriptCommands(log)
		require.NoError(t, err, "ScriptCommands")
		maps.Insert(cmds, maps.All(script.DefaultCmds()))

		return &script.Engine{
			Cmds:             cmds,
			RetryInterval:    100 * time.Millisecond,
			MaxRetryInterval: time.Second,
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	scripttest.Test(t,
		ctx,
		setup,
		[]string{},
		"testdata/*.txtar")
}

type dummyNodeManager struct {
	log *slog.Logger
}

// ClusterSizeDependantInterval implements manager.NodeManager.
func (d dummyNodeManager) ClusterSizeDependantInterval(baseInterval time.Duration) time.Duration {
	return time.Second
}

// Enqueue implements manager.NodeManager.
func (d dummyNodeManager) Enqueue(*nodeTypes.Node) {
	panic("unimplemented")
}

// GetNodeIdentities implements manager.NodeManager.
func (d dummyNodeManager) GetNodeIdentities() []nodeTypes.Identity {
	panic("unimplemented")
}

// GetNodes implements manager.NodeManager.
func (d dummyNodeManager) GetNodes() map[nodeTypes.Identity]nodeTypes.Node {
	panic("unimplemented")
}

// MeshNodeSync implements manager.NodeManager.
func (d dummyNodeManager) MeshNodeSync() {
	d.log.Debug("NodeManager.MeshNodeSync()")
}

// NodeDeleted implements manager.NodeManager.
func (d dummyNodeManager) NodeDeleted(n nodeTypes.Node) {
	panic("unimplemented")
}

// NodeSync implements manager.NodeManager.
func (d dummyNodeManager) NodeSync() {
	panic("unimplemented")
}

// NodeUpdated implements manager.NodeManager.
func (d dummyNodeManager) NodeUpdated(n nodeTypes.Node) {
	panic("unimplemented")
}

// StartNeighborRefresh implements manager.NodeManager.
func (d dummyNodeManager) StartNeighborRefresh(nh types.NodeNeighbors) {
	panic("unimplemented")
}

// StartNodeNeighborLinkUpdater implements manager.NodeManager.
func (d dummyNodeManager) StartNodeNeighborLinkUpdater(nh types.NodeNeighbors) {
	panic("unimplemented")
}

// Subscribe implements manager.NodeManager.
func (d dummyNodeManager) Subscribe(types.NodeHandler) {
	panic("unimplemented")
}

// Unsubscribe implements manager.NodeManager.
func (d dummyNodeManager) Unsubscribe(types.NodeHandler) {
	panic("unimplemented")
}

// SetPrefixClusterMutatorFn implements manager.NodeManager
func (d dummyNodeManager) SetPrefixClusterMutatorFn(mutator func(*nodeTypes.Node) []cmtypes.PrefixClusterOpts) {
	panic("unimplemented")
}

var _ nodemanager.NodeManager = dummyNodeManager{}

type dummyRemoteIdentityWatcher struct{}

// RemoveRemoteIdentities implements clustermesh.RemoteIdentityWatcher.
func (d dummyRemoteIdentityWatcher) RemoveRemoteIdentities(name string) {
}

// WatchRemoteIdentities implements clustermesh.RemoteIdentityWatcher.
func (d dummyRemoteIdentityWatcher) WatchRemoteIdentities(remoteName string, remoteID uint32, backend kvstore.BackendOperations, cachedPrefix bool) (allocator.RemoteIDCache, error) {
	return &cache.NoopRemoteIDCache{}, nil
}

var _ clustermesh.RemoteIdentityWatcher = dummyRemoteIdentityWatcher{}

type kvstoreCommands struct {
	client kvstore.BackendOperations
}

func (e kvstoreCommands) cmds() map[string]script.Cmd {
	return map[string]script.Cmd{
		"kvstore/update": e.update(),
		"kvstore/delete": e.delete(),
		"kvstore/list":   e.list(),
	}
}

func (e kvstoreCommands) update() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "update kvstore key-value",
			Args:    "key value-file",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 2 {
				return nil, fmt.Errorf("%w: expected key and value file", script.ErrUsage)
			}
			b, err := os.ReadFile(s.Path(args[1]))
			if err != nil {
				return nil, err
			}

			return nil, e.client.Update(s.Context(), args[0], b, false)
		},
	)
}

func (e kvstoreCommands) delete() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "delete kvstore key-value",
			Args:    "key",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 1 {
				return nil, fmt.Errorf("%w: expected key", script.ErrUsage)
			}
			return nil, e.client.Delete(s.Context(), args[0])
		},
	)
}

func (e kvstoreCommands) list() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "list kvstore key-value pairs",
			Args:    "(prefix)",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			prefix := ""
			if len(args) > 0 {
				prefix = args[0]
			}
			kvs, err := e.client.ListPrefix(s.Context(), prefix)
			if err != nil {
				return nil, err
			}
			for k, v := range kvs {
				s.Logf("%s: %s\n", k, v.Data)
			}
			return nil, nil
		},
	)
}
