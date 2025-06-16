// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh_test

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

	"github.com/cilium/cilium/clustermesh-apiserver/clustermesh"
	cmk8s "github.com/cilium/cilium/clustermesh-apiserver/clustermesh/k8s"
	"github.com/cilium/cilium/clustermesh-apiserver/syncstate"
	clustercfgcell "github.com/cilium/cilium/pkg/clustermesh/clustercfg/cell"
	"github.com/cilium/cilium/pkg/clustermesh/operator"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/hive"
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
	// Catch any leaked goroutines. Ignoring goroutines possibly left by other tests.
	t.Cleanup(func() {
		goleak.VerifyNone(t,
			goleak.IgnoreCurrent(),

			// To ignore goroutine started by the workqueue. It reports metrics
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

	setup := func(t testing.TB, args []string) *script.Engine {
		storeFactory := store.NewFactory(hivetest.Logger(t), store.MetricsProvider())

		h := hive.New(
			cell.Config(cmtypes.DefaultClusterInfo),
			cell.Config(operator.MCSAPIConfig{}),
			cell.Invoke(cmtypes.ClusterInfo.Validate),

			k8sClient.FakeClientCell(),
			cmk8s.ResourcesCell,

			cell.Provide(func(db *statedb.DB) (kvstore.Client, uhive.ScriptCmdsOut) {
				client := kvstore.NewInMemoryClient(db, "__local__")
				return client, uhive.NewScriptCmds(kvstore.Commands(client))
			}),

			cell.Provide(
				func() store.Factory {
					return storeFactory
				},
			),

			cell.Provide(func() syncstate.SyncState {
				return syncstate.SyncState{StoppableWaitGroup: lock.NewStoppableWaitGroup()}
			}),

			clustercfgcell.WithSyncedCanaries(true),
			clustercfgcell.Cell,
			clustermesh.Synchronization,
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
