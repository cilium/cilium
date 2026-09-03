// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"flag"
	"log/slog"
	"maps"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	operatorK8s "github.com/cilium/cilium/operator/k8s"
	"github.com/cilium/cilium/pkg/hive"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/logging"
	networkdriverConfig "github.com/cilium/cilium/pkg/networkdriver/config"
	"github.com/cilium/cilium/pkg/testutils"
)

var debug = flag.Bool("debug", false, "Enable debug logging")

func TestScript(t *testing.T) {
	t.Cleanup(func() { testutils.GoleakVerifyNone(t) })

	setup := func(t testing.TB, args []string) *script.Engine {
		h := hive.New(
			k8sClient.FakeClientCell(),
			operatorK8s.ResourcesCell,
			cell.Config(networkdriverConfig.DefaultConfig),
			Cell,
		)

		flags := pflag.NewFlagSet("", pflag.ContinueOnError)
		h.RegisterFlags(flags)
		require.NoError(t, flags.Parse(args), "flags.Parse")

		var options []hivetest.LogOption
		if *debug {
			options = append(options, hivetest.LogLevel(slog.LevelDebug))
			logging.SetLogLevel(slog.LevelDebug)
		}
		logger := hivetest.Logger(t, options...)

		t.Cleanup(func() {
			assert.NoError(t, h.Stop(logger, context.Background()))
		})

		commands, err := h.ScriptCommands(logger)
		require.NoError(t, err, "ScriptCommands")
		maps.Insert(commands, maps.All(script.DefaultCmds()))

		return &script.Engine{
			Cmds:          commands,
			RetryInterval: 10 * time.Millisecond,
		}
	}

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)

	scripttest.Test(
		t,
		ctx,
		setup,
		[]string{},
		"testdata/*.txtar",
	)
}
