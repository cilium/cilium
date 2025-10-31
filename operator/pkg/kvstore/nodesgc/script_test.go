// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodesgc

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
	"k8s.io/client-go/util/workqueue"

	operatorK8s "github.com/cilium/cilium/operator/k8s"
	operatorOption "github.com/cilium/cilium/operator/option"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/hive"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	k8sTestutils "github.com/cilium/cilium/pkg/k8s/testutils"
	"github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/time"
)

var debug = flag.Bool("debug", false, "Enable debug logging")

func TestScript(t *testing.T) {
	defer testutils.GoleakVerifyNone(t)

	version.Force(k8sTestutils.DefaultVersion)

	var opts []hivetest.LogOption
	if *debug {
		opts = append(opts, hivetest.LogLevel(slog.LevelDebug))
		logging.SetLogLevelToDebug()
	}
	log := hivetest.Logger(t, opts...)

	// Override the settings for testing purposes
	wqRateLimiter = workqueue.NewTypedItemExponentialFailureRateLimiter[nodeName](10*time.Millisecond, 10*time.Millisecond)
	kvstoreUpsertQueueDelay = 0 * time.Second
	operatorOption.Config.CiliumPodLabels = "k8s-app=cilium"

	setup := func(t testing.TB, args []string) *script.Engine {
		h := hive.New(
			cell.Config(cmtypes.DefaultClusterInfo),

			cell.Provide(
				func() store.Factory { return store.NewFactory(hivetest.Logger(t), store.MetricsProvider()) },

				func(db *statedb.DB) (kvstore.Client, uhive.ScriptCmdsOut) {
					client := kvstore.NewInMemoryClient(db, "__local__")
					return client, uhive.NewScriptCmds(kvstore.Commands(client))
				},
			),

			k8sClient.FakeClientCell(),
			operatorK8s.ResourcesCell,

			Cell,
		)

		flags := pflag.NewFlagSet("", pflag.ContinueOnError)
		h.RegisterFlags(flags)

		// Parse the shebang arguments in the script.
		require.NoError(t, flags.Parse(args), "flags.Parse")

		t.Cleanup(func() {
			assert.NoError(t, h.Stop(log, context.Background()))
		})

		cmds, err := h.ScriptCommands(log)
		require.NoError(t, err, "ScriptCommands")
		maps.Insert(cmds, maps.All(script.DefaultCmds()))

		return &script.Engine{
			Cmds:          cmds,
			RetryInterval: 10 * time.Millisecond,
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
