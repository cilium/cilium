// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

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
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/operator/k8s"
	"github.com/cilium/cilium/pkg/hive"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

var debug = flag.Bool("debug", false, "Enable debug logging")

func TestScript(t *testing.T) {
	t.Cleanup(func() { testutils.GoleakVerifyNone(t) })

	setup := func(t testing.TB, args []string) *script.Engine {
		h := hive.New(
			k8sClient.FakeClientCell(),
			k8s.ResourcesCell,
			cell.Provide(func() *option.DaemonConfig {
				return &option.DaemonConfig{
					EnableIPv4:                true,
					EnableIPv6:                true,
					EnableCiliumNetworkDriver: true,
				}
			}),
			Cell,
		)

		flags := pflag.NewFlagSet("", pflag.ContinueOnError)
		h.RegisterFlags(flags)

		var opts []hivetest.LogOption
		if *debug {
			opts = append(opts, hivetest.LogLevel(slog.LevelDebug))
			logging.SetLogLevelToDebug()
		}
		log := hivetest.Logger(t, opts...)

		t.Cleanup(func() {
			assert.NoError(t, h.Stop(log, context.TODO()))
		})

		cmds, err := h.ScriptCommands(log)
		require.NoError(t, err, "ScriptCommands")
		maps.Insert(cmds, maps.All(script.DefaultCmds()))

		return &script.Engine{Cmds: cmds}
	}

	scripttest.Test(t,
		t.Context(),
		setup,
		[]string{},
		"testdata/*.txtar",
	)
}
