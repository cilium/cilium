//go:build unparallel

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package test

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	"github.com/spf13/afero"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/datapath/linux"
	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/neighbor"
	"github.com/cilium/cilium/pkg/datapath/xdp"
	ciliumhive "github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/scriptnet"

	"github.com/cilium/cilium/pkg/logging"
)

var debug = flag.Bool("debug", false, "Enable debug logging")

func TestPrivilegedScript(t *testing.T) {
	testutils.PrivilegedTest(t)

	defer goleak.VerifyNone(t)

	var opts []hivetest.LogOption
	if *debug {
		opts = append(opts, hivetest.LogLevel(slog.LevelDebug))
		logging.SetLogLevelToDebug()
	}

	// When certain kernel modules are loaded, the kernel will by default try
	// to create fallback devices in newly created network namespaces.
	// Setting net.core.fb_tunnels_only_for_init=2 will prevent the kernel from
	// creating fallback devices so we have a more predictable test environment.
	sc := sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc")
	val, _ := sc.ReadInt([]string{"net", "core", "fb_tunnels_only_for_init_net"})
	t.Log("sysctl net.core.fb_tunnels_only_for_init_net was set to ", val)
	if val != 2 {
		t.Log("Setting sysctl net.core.fb_tunnels_only_for_init_net to 2")
		sc.WriteInt([]string{"net", "core", "fb_tunnels_only_for_init_net"}, 2)

		// Lets be a good citizen and clean up after ourselves.
		t.Cleanup(func() {
			t.Log("Resetting sysctl net.core.fb_tunnels_only_for_init_net to previous value")
			sc.WriteInt([]string{"net", "core", "fb_tunnels_only_for_init_net"}, val)
		})
	}

	scripttest.Test(t,
		t.Context(),
		func(t testing.TB, args []string) *script.Engine {
			nsManager, err := scriptnet.NewNSManager(t)
			require.NoError(t, err, "NewNSManager")

			err = nsManager.LockThreadAndInitialize(t, true)
			require.NoError(t, err, "LockThreadAndInitialize")

			log := hivetest.Logger(t, opts...)
			cells := []cell.Cell{
				linux.DevicesControllerCell,
				neighbor.Cell,
				metrics.Cell,
				xdp.Cell,
				cell.Provide(func() *option.DaemonConfig { return &option.DaemonConfig{} }),
				cell.Config(UseKernelManagedARPPing{}),
				cell.DecorateAll(func(testConfig UseKernelManagedARPPing) *neighbor.CommonConfig {
					return neighbor.NewCommonTestConfig(true, testConfig.ARPPingKernelManaged)()
				}),
				cell.Provide(forwardableIPInitializers),
			}
			h := ciliumhive.New(cells...)

			flags := pflag.NewFlagSet("", pflag.ContinueOnError)
			h.RegisterFlags(flags)

			// Set some defaults
			require.NoError(t, flags.Parse(args), "flags.Parse")

			t.Cleanup(func() {
				assert.NoError(t, h.Stop(log, context.TODO()))
			})

			cmds, err := h.ScriptCommands(log)
			require.NoError(t, err, "ScriptCommands")

			maps.Insert(cmds, maps.All(nsManager.Commands()))
			maps.Insert(cmds, maps.All(script.DefaultCmds()))

			e := &script.Engine{
				Conds: map[string]script.Cond{
					"kernel-can-manage-arp-ping": script.BoolCondition(
						"True if a probe detects the current kernel can manage ARP pings",
						probes.HaveManagedNeighbors() == nil,
					),
				},
				RetryInterval: 10 * time.Millisecond,
			}

			cmds["hive/recreate"] = script.Command(
				script.CmdUsage{
					Summary: "Restart the hive",
				},
				func(s1 *script.State, s2 ...string) (script.WaitFunc, error) {
					newHive := ciliumhive.New(cells...)

					flags := pflag.NewFlagSet("", pflag.ContinueOnError)
					newHive.RegisterFlags(flags)

					// Set some defaults
					require.NoError(t, flags.Parse(args), "flags.Parse")

					newHiveCmds, err := newHive.ScriptCommands(log)
					if err != nil {
						return nil, err
					}

					for name, newCmd := range newHiveCmds {
						cmds[name] = newCmd
					}

					return nil, nil
				},
			)
			e.Cmds = cmds
			return e
		}, []string{"PATH=" + os.Getenv("PATH")}, "testdata/*.txtar")
}

var _ cell.Flagger = UseKernelManagedARPPing{}

type UseKernelManagedARPPing struct {
	ARPPingKernelManaged bool `mapstructure:"use-kernel-managed-arp-ping"`
}

func (c UseKernelManagedARPPing) Flags(flags *pflag.FlagSet) {
	flags.BoolVar(&c.ARPPingKernelManaged, "use-kernel-managed-arp-ping", false, "Use kernel managed ARP ping")
}

func forwardableIPInitializers(fim *neighbor.ForwardableIPManager) hive.ScriptCmdsOut {
	initializers := make(map[string]neighbor.ForwardableIPInitializer)

	return hive.NewScriptCmds(map[string]script.Cmd{
		"forwardable-ip/register-initializer": script.Command(
			script.CmdUsage{
				Summary: "Register a forwardable IP initializer",
				Args:    "initializer-name",
			},
			func(state *script.State, args ...string) (script.WaitFunc, error) {
				if len(args) != 1 {
					return nil, script.ErrUsage
				}

				initializers[args[0]] = fim.RegisterInitializer(args[0])

				return nil, nil
			},
		),
		"forwardable-ip/finish-initializer": script.Command(
			script.CmdUsage{
				Summary: "Initialize forwardable IPs",
				Args:    "initializer-name",
			},
			func(state *script.State, args ...string) (script.WaitFunc, error) {
				if len(args) != 1 {
					return nil, script.ErrUsage
				}

				name := args[0]
				init, ok := initializers[name]
				if !ok {
					return nil, fmt.Errorf("no forwardable IP initializer registered with name %q", name)
				}

				fim.FinishInitializer(init)

				return nil, nil
			},
		),
	})
}
