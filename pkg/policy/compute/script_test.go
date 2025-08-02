// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package compute

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
	"go.uber.org/goleak"

	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/testutils"
	"github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
	"github.com/cilium/cilium/pkg/time"
)

var debug = flag.Bool("debug", true, "Enable debug logging")

func TestScript(t *testing.T) {
	defer goleak.VerifyNone(t)

	version.Force(testutils.DefaultVersion)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	var opts []hivetest.LogOption
	if *debug {
		opts = append(opts, hivetest.LogLevel(slog.LevelDebug))
		logging.SetLogLevelToDebug()
	}

	scripttest.Test(t,
		ctx,
		func(t testing.TB, args []string) *script.Engine {
			log := hivetest.Logger(t, opts...)
			h := hive.New(
				k8sClient.FakeClientCell(),
				daemonk8s.ResourcesCell,
				metrics.Cell,

				cell.Provide(
					func() *option.DaemonConfig {
						return &option.DaemonConfig{
							EnableIPv4: true,
							EnableIPv6: true,
						}
					},
				),

				cell.Invoke(
					func(t statedb.RWTable[Result], db_ *statedb.DB, c_ PolicyRecomputer) error {
						// table = t
						// db = db_
						// computer = c_
						return nil
					},
				),

				cell.ProvidePrivate(func() policy.PolicyRepository {
					return policy.NewPolicyRepository(log, nil, nil, nil, nil, testpolicy.NewPolicyMetricsNoop())
				}),
				identitymanager.Cell,

				cell.Provide(
					func(params Params) PolicyRecomputer {
						return NewIdentityPolicyRecomputer(params)
					},
				),
				cell.ProvidePrivate(newTable),
			)

			flags := pflag.NewFlagSet("", pflag.ContinueOnError)
			h.RegisterFlags(flags)

			// Set some defaults
			// flags.Set("enable-experimental-lb", "true")
			// require.NoError(t, flags.Parse(args), "flags.Parse")

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
