// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"context"
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

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s/client"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/time"
)

// TestScript runs all the testdata/*.txtar script tests. The tests are
// run in parallel. If you need to update the expected files inside the txtar
// files you can run 'go test . -scripttest.update' to update the files.
func TestScript(t *testing.T) {
	now := time.Now
	time.Now = func() time.Time {
		return time.Date(2000, 1, 1, 10, 30, 0, 0, time.UTC)
	}
	t.Cleanup(func() { time.Now = now })
	t.Setenv("TZ", "")
	nodeTypes.SetName("testnode")

	log := hivetest.Logger(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	scripttest.Test(t,
		ctx,
		func(t testing.TB, args []string) *script.Engine {
			h := hive.New(
				client.FakeClientCell,
				TablesCell,

				// Instantiate the tables we're testing. Without this the
				// tables and reflectors would not be created (as nothing
				// would depend on them).
				cell.Invoke(
					func(statedb.Table[LocalPod]) {},
				),
			)

			flags := pflag.NewFlagSet("", pflag.ContinueOnError)
			h.RegisterFlags(flags)

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
