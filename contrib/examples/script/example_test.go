package script

import (
	"context"
	"maps"
	"testing"
	"time"

	"github.com/cilium/hive"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
)

func TestScript(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)

	// Run the test scripts in parallel using the [ctx] defined above. This
	// gives each test script 5 seconds to complete. Without a context that
	// times out we would default to the 10 minute test timeout. Choose a
	// timeout that is suitable large for your tests that has enough buffer,
	// but still makes a good feedback cycle when working on new or failing
	// tests.
	scripttest.Test(
		t,
		ctx,
		func(t testing.TB, args []string) *script.Engine {
			log := hivetest.Logger(t)

			// Define a "test" hive consisting of the cell being tested and
			// its dependencies.
			h := hive.New(
				Cell,

				// dependencies of [Cell] would go here.
			)
			flags := pflag.NewFlagSet("", pflag.ContinueOnError)
			h.RegisterFlags(flags)

			// Gather the commands provided by cells in the hive [h] and add
			// the default script commands.
			cmds, err := h.ScriptCommands(log)
			require.NoError(t, err, "ScriptCommands")
			maps.Insert(cmds, maps.All(script.DefaultCmds()))

			// Stop the hive automatically after the test is complete.
			t.Cleanup(func() { h.Stop(log, context.Background()) })

			// Return the engine for executing the test scripts.
			return &script.Engine{
				Cmds: cmds,
			}
		},
		[]string{},         // Environment
		"testdata/*.txtar", // Scripts to execute
	)
}
