// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"flag"
	"log/slog"
	"maps"
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
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/testutils"
	"github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/time"
)

var debug = flag.Bool("debug", false, "Enable debug logging")

func TestScript(t *testing.T) {
	// Catch any leaked goroutines.
	t.Cleanup(func() {
		goleak.VerifyNone(t,
			// Ignore goroutines possibly left by other tests.
			goleak.IgnoreCurrent(),

			// Ignore goroutine started by the workqueue. It reports metrics
			// on unfinished work with default tick period of 0.5s - it terminates
			// no longer than 0.5s after the workqueue is stopped.
			goleak.IgnoreTopFunction("k8s.io/client-go/util/workqueue.(*Type).updateUnfinishedWorkLoop"),
		)
	})

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

		h := hive.New(
			k8sClient.FakeClientCell(),
			cell.Provide(k8s.ServiceResource),
			operatorK8s.ResourcesCell,
			cell.Config(cmtypes.DefaultClusterInfo),
			cell.Invoke(cmtypes.ClusterInfo.Validate),
			cell.Provide(func(db *statedb.DB) (kvstore.Client, uhive.ScriptCmdsOut) {
				client := kvstore.NewInMemoryClient(db, "__local__")
				return client, uhive.NewScriptCmds(kvstore.Commands(client))
			}),

			cell.Provide(func() ServiceSyncConfig {
				return ServiceSyncConfig{Enabled: true}
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
