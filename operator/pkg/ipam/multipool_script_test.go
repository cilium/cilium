// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"encoding/json"
	"flag"
	"log/slog"
	"maps"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/operator/k8s"
	"github.com/cilium/cilium/operator/pkg/ipam/allocator/multipool"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/hive"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

// Register the multi-pool IPAM allocator directly to test it without the specific build tag.
func init() {
	allocators = append(allocators, cell.Module(
		"multipool-ipam-allocator",
		"Multi Pool IP Allocator",

		cell.Config(multipool.DefaultConfig),
		cell.Provide(func(logger *slog.Logger, daemonCfg *option.DaemonConfig) *multipool.PoolAllocator {
			return multipool.NewPoolAllocator(logger, daemonCfg.EnableIPv4, daemonCfg.EnableIPv6)
		}),
		cell.Invoke(multipool.StartAllocator),
	))
}

var debug = flag.Bool("debug", false, "Enable debug logging")

func TestScriptMultiPool(t *testing.T) {
	t.Cleanup(func() { testutils.GoleakVerifyNone(t) })

	setup := func(t testing.TB, args []string) *script.Engine {
		var allocator *multipool.PoolAllocator

		h := hive.New(
			k8sClient.FakeClientCell(),
			k8s.ResourcesCell,
			cell.Provide(func() *option.DaemonConfig {
				return &option.DaemonConfig{
					EnableIPv4:        true,
					EnableIPv6:        true,
					IPAM:              ipamOption.IPAMMultiPool,
					IPAMDefaultIPPool: defaults.IPAMDefaultIPPool,
				}
			}),

			Cell(),

			cell.Invoke(func(allocator_ *multipool.PoolAllocator) {
				allocator = allocator_
			}),
		)

		flags := pflag.NewFlagSet("", pflag.ContinueOnError)
		h.RegisterFlags(flags)

		// Parse the shebang arguments in the script.
		require.NoError(t, flags.Parse(args), "flags.Parse")

		var opts []hivetest.LogOption
		if *debug {
			opts = append(opts, hivetest.LogLevel(slog.LevelDebug))
			logging.SetLogLevel(slog.LevelDebug)
		}
		log := hivetest.Logger(t, opts...)

		t.Cleanup(func() {
			assert.NoError(t, h.Stop(log, context.TODO()))
		})

		cmds, err := h.ScriptCommands(log)
		require.NoError(t, err, "ScriptCommands")
		maps.Insert(cmds, maps.All(script.DefaultCmds()))
		maps.Insert(cmds, maps.All(commands(allocator)))

		return &script.Engine{Cmds: cmds}
	}

	scripttest.Test(t,
		t.Context(),
		setup,
		[]string{},
		"testdata/multipool/*.txtar",
	)
}

func commands(allocator *multipool.PoolAllocator) map[string]script.Cmd {
	return map[string]script.Cmd{
		"allocator/allocated-pools": script.Command(
			script.CmdUsage{
				Summary: "Dump PoolAllocator.AllocatedPools for a node",
				Args:    "node-name",
			},
			func(_ *script.State, args ...string) (script.WaitFunc, error) {
				if len(args) != 1 {
					return nil, script.ErrUsage
				}

				return func(_ *script.State) (stdout string, stderr string, err error) {
					data, err := json.MarshalIndent(allocator.AllocatedPools(args[0]), "", "  ")
					if err != nil {
						return "", "", err
					}
					return string(data) + "\n", "", nil
				}, nil
			},
		),
	}
}
