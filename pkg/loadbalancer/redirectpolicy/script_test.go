// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy_test

import (
	"context"
	"flag"
	"log/slog"
	"maps"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	"github.com/cilium/statedb"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/tables"
	envoyCfg "github.com/cilium/cilium/pkg/envoy/config"
	"github.com/cilium/cilium/pkg/hive"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	k8sTables "github.com/cilium/cilium/pkg/k8s/tables"
	k8sTestutils "github.com/cilium/cilium/pkg/k8s/testutils"
	"github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/lbipamconfig"
	"github.com/cilium/cilium/pkg/loadbalancer"
	lbcell "github.com/cilium/cilium/pkg/loadbalancer/cell"
	lbmaps "github.com/cilium/cilium/pkg/loadbalancer/maps"
	"github.com/cilium/cilium/pkg/loadbalancer/redirectpolicy"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/nodeipamconfig"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/time"
)

var debug = flag.Bool("debug", false, "Enable debug logging")

func TestScript(t *testing.T) {
	version.Force(k8sTestutils.DefaultVersion)
	nodeTypes.SetName("testnode")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	var opts []hivetest.LogOption
	if *debug {
		opts = append(opts, hivetest.LogLevel(slog.LevelDebug))
		logging.SetLogLevel(slog.LevelDebug)
	}

	scripttest.Test(t,
		ctx,
		func(t testing.TB, args []string) *script.Engine {
			log := hivetest.Logger(t, opts...)
			h := hive.New(
				k8sClient.FakeClientCell(),
				daemonk8s.ResourcesCell,
				cell.Config(envoyCfg.SecretSyncConfig{}),
				k8sTables.TablesCell,
				metrics.Cell,

				lbipamconfig.Cell,
				nodeipamconfig.Cell,
				lbcell.Cell,

				node.LocalNodeStoreTestCell,
				maglev.Cell,
				cell.Provide(
					func() cmtypes.ClusterInfo { return cmtypes.ClusterInfo{} },
					source.NewSources,
					func() *loadbalancer.TestConfig { return &loadbalancer.TestConfig{} },
					tables.NewNodeAddressTable,
					statedb.RWTable[tables.NodeAddress].ToTable,
					func() *option.DaemonConfig {
						return &option.DaemonConfig{
							EnableIPv4: true,
							EnableIPv6: true,
						}
					},
					func() kpr.KPRConfig {
						return kpr.KPRConfig{
							KubeProxyReplacement: true,
						}
					},
					func() redirectpolicy.TestSkipLBMap {
						// Only use fake SkipLBMap if we're running unprivileged tests.
						if testutils.IsPrivileged() {
							return nil
						}
						return &lbmaps.FakeSkipLBMap{}
					},
				),
			)

			flags := pflag.NewFlagSet("", pflag.ContinueOnError)
			h.RegisterFlags(flags)

			// Forcibly enable LRP.
			require.NoError(t, flags.Set(redirectpolicy.EnableLocalRedirectPolicyName, "true"))

			// Set some defaults
			require.NoError(t, flags.Parse(args), "flags.Parse")

			t.Cleanup(func() {
				assert.NoError(t, h.Stop(log, context.TODO()))
			})
			cmds, err := h.ScriptCommands(log)
			require.NoError(t, err, "ScriptCommands")
			maps.Insert(cmds, maps.All(script.DefaultCmds()))
			return &script.Engine{
				Cmds:          cmds,
				RetryInterval: 10 * time.Millisecond,
			}
		}, []string{}, "testdata/*.txtar")
}
