// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"maps"
	"os"
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

	operatorK8s "github.com/cilium/cilium/operator/k8s"
	operatorOption "github.com/cilium/cilium/operator/option"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/testutils"
	"github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
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

	operatorOption.Config.SyncK8sServices = true
	option.Config.KVStore = "dummy"

	// Due to the kvstore global variables we cannot run these tests in parallel
	// (scripttest calls t.Parallel()). Use a mutex to serialize the test execution.
	// Remove this once kvstore globals are removed.
	var serializeMu lock.Mutex

	setup := func(t testing.TB, args []string) *script.Engine {
		serializeMu.Lock()
		t.Cleanup(serializeMu.Unlock)

		storeFactory := store.NewFactory(hivetest.Logger(t), store.MetricsProvider())

		h := hive.New(
			client.FakeClientCell(),
			operatorK8s.ResourcesCell,
			cell.Config(cmtypes.DefaultClusterInfo),
			cell.Invoke(cmtypes.ClusterInfo.Validate),
			cell.Provide(func(db *statedb.DB) (kvstore.BackendOperations, promise.Promise[kvstore.BackendOperations], uhive.ScriptCmdOut) {
				kvstore.SetupInMemory(db)
				client := kvstore.SetupDummy(t, "in-memory")
				r, p := promise.New[kvstore.BackendOperations]()
				r.Resolve(client)
				return client, p, uhive.NewScriptCmd("kvstore/list", kvstoreListCommand(client))
			}),

			cell.Provide(func(be promise.Promise[kvstore.BackendOperations]) ServiceSyncConfig {
				return ServiceSyncConfig{
					Enabled: true,
					Backend: be,
				}
			}),
			ServiceSyncCell,

			cell.Provide(
				func() store.Factory {
					return storeFactory
				},
			),
		)

		flags := pflag.NewFlagSet("", pflag.ContinueOnError)
		h.RegisterFlags(flags)

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
			RetryInterval:    20 * time.Millisecond,
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

func kvstoreListCommand(client kvstore.BackendOperations) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "list kvstore key-value pairs",
			Args:    "prefix (output file)",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			prefix := ""
			if len(args) > 0 {
				prefix = args[0]
			}
			kvs, err := client.ListPrefix(s.Context(), prefix)
			if err != nil {
				return nil, err
			}
			return func(s *script.State) (stdout string, stderr string, err error) {
				var b bytes.Buffer
				for k, v := range kvs {
					fmt.Fprintf(&b, "# %s\n", k)
					if err := json.Indent(&b, v.Data, "", "  "); err != nil {
						fmt.Fprintf(&b, "ERROR: %s", err)
					}
					fmt.Fprintln(&b)
				}
				if len(args) == 2 {
					err = os.WriteFile(s.Path(args[1]), b.Bytes(), 0644)
				} else {
					stdout = b.String()
				}
				return
			}, nil
		},
	)
}
