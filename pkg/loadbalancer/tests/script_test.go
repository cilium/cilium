// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"path/filepath"
	"strconv"
	"strings"
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

	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/tables"
	envoyCfg "github.com/cilium/cilium/pkg/envoy/config"
	"github.com/cilium/cilium/pkg/hive"
	k8sclient "github.com/cilium/cilium/pkg/k8s/client"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	k8sTables "github.com/cilium/cilium/pkg/k8s/tables"
	k8sTestutils "github.com/cilium/cilium/pkg/k8s/testutils"
	"github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/lbipamconfig"
	"github.com/cilium/cilium/pkg/loadbalancer"
	lbcell "github.com/cilium/cilium/pkg/loadbalancer/cell"
	lbmaps "github.com/cilium/cilium/pkg/loadbalancer/maps"
	lbreconciler "github.com/cilium/cilium/pkg/loadbalancer/reconciler"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/nodeipamconfig"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/time"
)

var debug = flag.Bool("debug", false, "Enable debug logging")

// TestPrivilegedScript runs script tests when privileged.
// This exists solely to satisfy 'tests-privileged-only' make target and to not
// run the tests twice when privileged.
func TestPrivilegedScript(t *testing.T) {
	testutils.PrivilegedTest(t)
	testScript(t)
}

// TestScript runs script tests when non-privileged.
func TestScript(t *testing.T) {
	if testutils.IsPrivileged() {
		t.Skip("Skipping in favour of TestPrivilegedScript")
	} else {
		testScript(t)
	}
}

func testScript(t *testing.T) {
	// version/capabilities are unfortunately a global variable, so we're forcing it here.
	// This makes it difficult to have different k8s version/capabilities (e.g. use Endpoints
	// not EndpointSlice) in the tests here, which is why we're currently only testing against
	// the default.
	// Issue for fixing this: https://github.com/cilium/cilium/issues/35537
	version.Force(k8sTestutils.DefaultVersion)

	// Set the node name
	nodeTypes.SetName("testnode")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	scripttest.Test(t,
		ctx,
		func(t testing.TB, args []string) *script.Engine {
			var opts []hivetest.LogOption
			if *debug {
				opts = append(opts, hivetest.LogLevel(slog.LevelDebug))
				logging.SetLogLevel(slog.LevelDebug)
			}
			log := hivetest.Logger(t, opts...)
			conds := map[string]script.Cond{
				"privileged": script.BoolCondition("testutils.IsPrivileged", testutils.IsPrivileged()),
			}
			rt := &scriptRuntime{
				t:        t,
				log:      log,
				baseArgs: append([]string(nil), args...),
				workDir:  filepath.Join(filepath.Dir(t.TempDir()), "001"),
			}
			rt.engine = &script.Engine{
				Conds:            conds,
				RetryInterval:    20 * time.Millisecond,
				MaxRetryInterval: 500 * time.Millisecond,
			}
			require.NoError(t, rt.recreate(), "create initial hive")
			return rt.engine
		},
		[]string{
			/* empty environment */
		}, "testdata/*.txtar")
}

// scriptRuntime owns the application instance used by a single script. Recreating
// the Hive models restarting the Cilium agent: its in-memory StateDB is rebuilt,
// while the Kubernetes API and pinned BPF maps continue to exist outside the
// process. The fake client and fake LB maps model those two persistent stores.
type scriptRuntime struct {
	t        testing.TB
	log      *slog.Logger
	engine   *script.Engine
	baseArgs []string
	workDir  string

	client *k8sClient.FakeClientset
	lbMaps lbmaps.LBMaps
}

func (rt *scriptRuntime) newHive(extraArgs []string) (*hive.Hive, map[string]script.Cmd, error) {
	var (
		client *k8sClient.FakeClientset
		lbMaps lbmaps.LBMaps
	)

	app := cell.Group(
		k8sClient.FakeClientCell(),
		daemonk8s.ResourcesCell,
		k8sTables.TablesCell,
		cell.Config(envoyCfg.SecretSyncConfig{}),
		kpr.Cell,

		cell.Config(loadbalancer.TestConfig{
			// By default 10% of the time the LBMap operations fail.
			TestFaultProbability: 0.1,
		}),
		metrics.Cell,
		maglev.Cell,
		lbipamconfig.Cell,
		nodeipamconfig.Cell,
		node.LocalNodeStoreTestCell,
		cell.Provide(
			func() cmtypes.ClusterInfo { return cmtypes.ClusterInfo{} },
			func(cfg loadbalancer.TestConfig) *loadbalancer.TestConfig { return &cfg },
			tables.NewNodeAddressTable,
			statedb.RWTable[tables.NodeAddress].ToTable,
			source.NewSources,
			func(cfg loadbalancer.TestConfig) *option.DaemonConfig {
				return &option.DaemonConfig{
					EnableIPv4: true,
					EnableIPv6: true,
				}
			},
			func(ops *lbreconciler.BPFOps, lns *node.LocalNodeStore, w *writer.Writer, waitFn loadbalancer.InitWaitFunc) uhive.ScriptCmdsOut {
				return uhive.NewScriptCmds(testCommands{w, lns, ops, waitFn}.cmds())
			},
		),
		cell.Invoke(func(c *k8sClient.FakeClientset, m lbmaps.LBMaps) {
			client = c
			lbMaps = m
		}),

		lbcell.Cell,
	)

	// A new FakeClientCell and LB maps implementation would normally be constructed
	// with every Hive. Decorate them on recreation so Kubernetes objects created by
	// the script and datapath state programmed by the previous agent remain visible
	// to the new agent. StateDB is not decorated and is therefore always fresh.
	if rt.client != nil {
		app = cell.Decorate(
			func(k8sclient.Clientset) k8sclient.Clientset { return rt.client },
			app,
		)
	}
	if rt.lbMaps != nil {
		app = cell.Decorate(
			func(lbmaps.LBMaps) lbmaps.LBMaps { return rt.lbMaps },
			app,
		)
	}

	h := hive.New(app)
	flags := pflag.NewFlagSet("", pflag.ContinueOnError)
	h.RegisterFlags(flags)

	// Preserve the defaults used by the existing script suite. The shebang and
	// hive/recreate arguments may override these values.
	for name, value := range map[string]string{
		"kube-proxy-replacement":   "true",
		"lb-retry-backoff-min":     "10ms",
		"lb-retry-backoff-max":     "10ms",
		"bpf-lb-maglev-table-size": "1021",
	} {
		if err := flags.Set(name, value); err != nil {
			return nil, nil, fmt.Errorf("setting default --%s: %w", name, err)
		}
	}

	// Treat the shebang as the base agent configuration and flags passed to
	// hive/recreate as overrides for the replacement agent.
	args := append([]string(nil), rt.baseArgs...)
	args = append(args, extraArgs...)
	for i := range args {
		args[i] = strings.ReplaceAll(args[i], "$WORK", rt.workDir)
	}
	if err := flags.Parse(args); err != nil {
		return nil, nil, fmt.Errorf("parsing hive arguments: %w", err)
	}

	rt.t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		assert.NoError(rt.t, h.Stop(rt.log, ctx))
	})
	cmds, err := h.ScriptCommands(rt.log)
	if err != nil {
		return nil, nil, fmt.Errorf("getting script commands: %w", err)
	}

	if rt.client == nil {
		rt.client = client
	}
	if rt.lbMaps == nil {
		rt.lbMaps = lbMaps
	}

	// Always direct Kubernetes commands to the client retained across Hive
	// instances rather than the per-Hive client hidden by the decorator.
	maps.Insert(cmds, maps.All(k8sClient.FakeClientCommands(rt.client)))
	maps.Insert(cmds, maps.All(script.DefaultCmds()))
	cmds["hive/recreate"] = script.Command(
		script.CmdUsage{
			Summary: "recreate the test Hive while retaining Kubernetes and BPF map state",
			Args:    "[flags...]",
			Detail: []string{
				"The current Hive must be stopped before it is recreated.",
				"The new Hive has a fresh StateDB, while the fake Kubernetes API and LB maps are retained to model an agent restart.",
				"Flags override values from the script shebang for the replacement Hive.",
			},
		},
		func(_ *script.State, args ...string) (script.WaitFunc, error) {
			return nil, rt.recreate(args...)
		},
	)
	return h, cmds, nil
}

func (rt *scriptRuntime) recreate(extraArgs ...string) error {
	_, cmds, err := rt.newHive(extraArgs)
	if err != nil {
		return err
	}
	if rt.engine.Cmds == nil {
		rt.engine.Cmds = cmds
	} else {
		clear(rt.engine.Cmds)
		maps.Copy(rt.engine.Cmds, cmds)
	}
	return nil
}

type testCommands struct {
	w      *writer.Writer
	lns    *node.LocalNodeStore
	ops    *lbreconciler.BPFOps
	waitFn loadbalancer.InitWaitFunc
}

func (tc testCommands) cmds() map[string]script.Cmd {
	return map[string]script.Cmd{
		"test/update-backend-health":        tc.updateHealth(),
		"test/bpfops-reset":                 tc.opsReset(),
		"test/bpfops-summary":               tc.opsSummary(),
		"test/set-node-labels":              tc.setNodeLabels(),
		"test/set-node-ip":                  tc.setNodeIP(),
		"test/set-is-service-healthchecked": tc.setIsServiceHealthChecked(),
		"test/init-wait":                    tc.initWait(),
	}
}

func (tc testCommands) updateHealth() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Update backend healthyness",
			Args:    "service-name backend-addr healthy",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 3 {
				return nil, fmt.Errorf("%w: expected service name, backend address and health", script.ErrUsage)
			}
			ns, name, _ := strings.Cut(args[0], "/")
			svc := loadbalancer.NewServiceName(ns, name)

			var beAddr loadbalancer.L3n4Addr
			if err := beAddr.ParseFromString(args[1]); err != nil {
				return nil, err
			}

			healthy, err := strconv.ParseBool(args[2])
			if err != nil {
				return nil, err
			}

			txn := tc.w.WriteTxn()
			_, err = tc.w.UpdateBackendHealth(txn, svc, beAddr, healthy)
			if err != nil {
				txn.Abort()
				return nil, err
			}
			txn.Commit()
			return nil, nil
		})
}

func (tc testCommands) opsReset() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Reset and restart BPF ops",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			return nil, tc.ops.ResetAndRestore()
		})
}

func (tc testCommands) opsSummary() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Write out summary of BPFOps state",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			return func(s *script.State) (stdout string, stderr string, err error) {
				stdout = tc.ops.StateSummary()
				return
			}, nil
		})
}

func (tc testCommands) setNodeLabels() script.Cmd {
	return script.Command(
		script.CmdUsage{Summary: "Set local node labels", Args: "key=value..."},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			labels := map[string]string{}
			for _, arg := range args {
				key, value, found := strings.Cut(arg, "=")
				if !found {
					return nil, fmt.Errorf("bad key=value: %q", arg)
				}
				labels[key] = value
			}
			tc.lns.Update(func(n *node.LocalNode) {
				n.Labels = labels
				s.Logf("Labels set to %v\n", labels)
			})
			return nil, nil
		})
}

func (tc testCommands) setNodeIP() script.Cmd {
	return script.Command(
		script.CmdUsage{Summary: "Set local node IP", Args: "ip"},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 1 {
				return nil, fmt.Errorf("%w: expected 'ip'", script.ErrUsage)
			}
			ip := net.ParseIP(args[0])
			tc.lns.Update(func(n *node.LocalNode) {
				n.IPAddresses = []nodeTypes.Address{
					{Type: addressing.NodeExternalIP, IP: ip},
				}
				s.Logf("NodeIP set to %s\n", ip)
			})
			return nil, nil
		})
}

func (tc testCommands) setIsServiceHealthChecked() script.Cmd {
	return script.Command(
		script.CmdUsage{Summary: "Set isIServiceHealthChecked that reports services as being healthchecked based on the presence of the given annotation", Args: "annotation"},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 1 {
				return nil, fmt.Errorf("%w: expected 'annotation'", script.ErrUsage)
			}

			tc.w.SetIsServiceHealthCheckedFunc(func(svc *loadbalancer.Service) bool {
				return svc.Annotations != nil && svc.Annotations[args[0]] != ""
			})
			return nil, nil
		})
}

func (tc testCommands) initWait() script.Cmd {
	return script.Command(
		script.CmdUsage{Summary: "Wait for InitWaitFunc() to return"},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			return nil, tc.waitFn(s.Context())
		})
}
