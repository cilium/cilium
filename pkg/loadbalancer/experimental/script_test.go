// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package experimental

import (
	"bufio"
	"context"
	"maps"
	"os"
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
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/testutils"
	"github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/option"
)

func TestScript(t *testing.T) {
	// version/capabilities are unfortunately a global variable, so we're forcing it here.
	// This makes it difficult to have different k8s version/capabilities (e.g. use Endpoints
	// not EndpointSlice) in the tests here, which is why we're currently only testing against
	// the default.
	// Issue for fixing this: https://github.com/cilium/cilium/issues/35537
	version.Force(testutils.DefaultVersion)

	// pkg/k8s/endpoints.go uses this in ParseEndpointSlice*
	option.Config.EnableK8sTerminatingEndpoint = true

	log := hivetest.Logger(t)
	scripttest.Test(t,
		context.Background(),
		func(t testing.TB) *script.Engine {
			h := hive.New(
				client.FakeClientCell,
				daemonk8s.ResourcesCell,
				Cell,
				cell.Config(TestConfig{
					// By default 10% of the time the LBMap operations fail
					TestFaultProbability: 0.1,
				}),
				cell.Provide(
					func(cfg TestConfig) *TestConfig { return &cfg },
					tables.NewNodeAddressTable,
					statedb.RWTable[tables.NodeAddress].ToTable,
					func() *option.DaemonConfig {
						return &option.DaemonConfig{
							EnableIPv4:        true,
							EnableIPv6:        true,
							SockRevNatEntries: 1000,
							LBMapEntries:      1000,
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

			// Parse and process the "#! --flag=true" magic line.
			_, scriptFile, _ := strings.Cut(t.Name(), "/")
			if args := parseArgsLine("testdata/" + scriptFile); len(args) > 0 {
				require.NoError(t, flags.Parse(args), "flags.Parse")
				t.Logf("Parsed arguments: %v", args)
			}

			t.Cleanup(func() {
				assert.NoError(t, h.Stop(log, context.TODO()))
			})
			cmds, err := h.ScriptCommands(log)
			require.NoError(t, err, "ScriptCommands")
			maps.Insert(cmds, maps.All(script.DefaultCmds()))

			return &script.Engine{
				Cmds: cmds,
			}
		}, []string{}, "testdata/*.txtar")
}

func parseArgsLine(file string) []string {
	f, err := os.Open(file)
	if err != nil {
		panic(err)
	}
	b, _, _ := bufio.NewReader(f).ReadLine()
	if strings.HasPrefix(string(b), "#! ") {
		line := string(b[3:])
		return strings.Split(line, " ")
	}
	return nil
}
