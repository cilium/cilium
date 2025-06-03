// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package healthserver_test

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"slices"
	"strings"
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
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/testutils"
	"github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/loadbalancer"
	lbcell "github.com/cilium/cilium/pkg/loadbalancer/cell"
	"github.com/cilium/cilium/pkg/loadbalancer/healthserver"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

var debug = flag.Bool("debug", false, "Enable debug logging")

func TestScript(t *testing.T) {
	// version/capabilities are unfortunately a global variable, so we're forcing it here.
	// This makes it difficult to have different k8s version/capabilities (e.g. use Endpoints
	// not EndpointSlice) in the tests here, which is why we're currently only testing against
	// the default.
	// Issue for fixing this: https://github.com/cilium/cilium/issues/35537
	version.Force(testutils.DefaultVersion)

	// Set the node name
	nodeTypes.SetName("testnode")

	var opts []hivetest.LogOption
	if *debug {
		opts = append(opts, hivetest.LogLevel(slog.LevelDebug))
		logging.SetLogLevelToDebug()
	}
	log := hivetest.Logger(t, opts...)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	scripttest.Test(t,
		ctx,
		func(t testing.TB, args []string) *script.Engine {
			h := hive.New(
				client.FakeClientCell,
				daemonk8s.ResourcesCell,
				daemonk8s.TablesCell,
				metrics.Cell,

				lbcell.Cell,

				cell.Config(loadbalancer.TestConfig{}),
				maglev.Cell,
				node.LocalNodeStoreCell,
				cell.Provide(
					func(cfg loadbalancer.TestConfig) *loadbalancer.TestConfig { return &cfg },
					tables.NewNodeAddressTable,
					statedb.RWTable[tables.NodeAddress].ToTable,
					source.NewSources,
					func(cfg loadbalancer.TestConfig) *option.DaemonConfig {
						return &option.DaemonConfig{
							EnableIPv4:                      true,
							EnableIPv6:                      true,
							KubeProxyReplacement:            option.KubeProxyReplacementTrue,
							EnableNodePort:                  true,
							EnableInternalTrafficPolicy:     true,
							EnableHealthCheckLoadBalancerIP: true,
						}
					},
				),

				cell.Invoke(statedb.RegisterTable[tables.NodeAddress]),
			)

			flags := pflag.NewFlagSet("", pflag.ContinueOnError)
			h.RegisterFlags(flags)

			// Set some defaults
			flags.Set("enable-experimental-lb", "true")
			flags.Set("lb-retry-backoff-min", "10ms") // as we're doing fault injection we want
			flags.Set("lb-retry-backoff-max", "10ms") // tiny backoffs
			flags.Set("bpf-lb-maglev-table-size", "1021")

			// Parse the shebang arguments in the script.
			require.NoError(t, flags.Parse(args), "flags.Parse")

			t.Cleanup(func() {
				assert.NoError(t, h.Stop(log, context.TODO()))
			})
			cmds, err := h.ScriptCommands(log)
			require.NoError(t, err, "ScriptCommands")
			maps.Insert(cmds, maps.All(script.DefaultCmds()))
			cmds["http/get"] = httpGetCmd

			return &script.Engine{
				Cmds:             cmds,
				RetryInterval:    20 * time.Millisecond,
				MaxRetryInterval: 500 * time.Millisecond,
			}
		}, []string{
			fmt.Sprintf("HEALTHADDR=%s", cmtypes.AddrClusterFrom(healthserver.ChooseHealthServerLoopbackAddressForTesting(), 0)),
		}, "testdata/*.txtar")
}

var httpGetCmd = script.Command(
	script.CmdUsage{
		Summary: "HTTP get the given url into the given file",
		Args:    "url file",
	},
	func(s *script.State, args ...string) (script.WaitFunc, error) {
		if len(args) != 2 {
			return nil, fmt.Errorf("expected url and file")
		}
		resp, err := http.Get(args[0])
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		f, err := os.OpenFile(s.Path(args[1]), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}
		defer f.Close()

		fmt.Fprintf(f, "%s\n", resp.Status)

		for _, k := range slices.Sorted(maps.Keys(resp.Header)) {
			h := resp.Header[k]
			if k == "Date" {
				h = []string{"<omitted>"}
			}
			fmt.Fprintf(f, "%s=%s\n", k, strings.Join(h, ", "))
		}
		fmt.Fprintln(f, "---")
		_, err = io.Copy(f, resp.Body)
		return nil, err
	},
)
