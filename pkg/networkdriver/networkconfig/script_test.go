// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkconfig

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
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/networkdriver/config"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/time"
)

func TestScript(t *testing.T) {
	now := time.Now
	time.Now = func() time.Time {
		return time.Date(2000, 1, 1, 10, 30, 0, 0, time.UTC)
	}
	since := time.Since
	time.Since = func(time.Time) time.Duration {
		return time.Minute
	}
	t.Cleanup(func() {
		time.Now = now
		time.Since = since
	})
	t.Setenv("TZ", "")

	log := hivetest.Logger(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	scripttest.Test(t,
		ctx,
		func(t testing.TB, args []string) *script.Engine {
			h := hive.New(
				k8sClient.FakeClientCell(),
				cell.Config(config.Config{Enabled: true}),
				Cell,
				cell.Provide(func() promise.Promise[synced.CRDSync] {
					r, p := promise.New[synced.CRDSync]()
					r.Resolve(synced.CRDSync{})
					return p
				}),
				cell.Invoke(func(statedb.Table[LocalResourceNetworkConfig]) {}),
			)

			flags := pflag.NewFlagSet("", pflag.ContinueOnError)
			h.RegisterFlags(flags)

			t.Cleanup(func() {
				assert.NoError(t, h.Stop(log, context.TODO()))
			})
			cmds, err := h.ScriptCommands(log)
			require.NoError(t, err, "ScriptCommands")
			maps.Insert(cmds, maps.All(script.DefaultCmds()))
			return &script.Engine{Cmds: cmds}
		}, []string{}, "testdata/*.txtar")
}
