// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"context"
	"log/slog"
	"maps"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/time"
)

// TestScript runs all the testdata/*.txtar script tests. The tests are
// run in parallel. If you need to update the expected files inside the txtar
// files you can run 'go test . -scripttest.update' to update the files.
func TestScript(t *testing.T) {
	log := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	scripttest.Test(t,
		ctx,
		func(t testing.TB, args []string) *script.Engine {
			h := hive.New(
				FakeClientCell,
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
