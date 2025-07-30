// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package test

import (
	"context"
	"flag"
	"log/slog"
	"maps"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	testk8s "github.com/cilium/cilium/pkg/k8s/testutils"
	"github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/policy"
	policycell "github.com/cilium/cilium/pkg/policy/cell"
	"github.com/cilium/cilium/pkg/policy/compute"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/time"
)

var debug = flag.Bool("debug", false, "Enable debug logging")

func TestScript(t *testing.T) {
	// trigger.waiter and SelectorCache.handleUserNotifications do not shut
	// down on hive.Stop in production either.
	defer testutils.GoleakVerifyNone(t,
		testutils.GoleakIgnoreAnyFunction("github.com/cilium/cilium/pkg/trigger.(*Trigger).waiter"),
		testutils.GoleakIgnoreAnyFunction("github.com/cilium/cilium/pkg/policy.(*SelectorCache).handleUserNotifications"),
	)

	version.Force(testk8s.DefaultVersion)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	var opts []hivetest.LogOption
	if *debug {
		opts = append(opts, hivetest.LogLevel(slog.LevelDebug))
		logging.SetLogLevel(slog.LevelDebug)
	}

	log := hivetest.Logger(t, opts...)
	scripttest.Test(t,
		ctx,
		func(t testing.TB, args []string) *script.Engine {
			f := newTestFixture(t, log, nil)

			flags := pflag.NewFlagSet("", pflag.ContinueOnError)
			f.hive.RegisterFlags(flags)

			cmds, err := f.hive.ScriptCommands(log)
			require.NoError(t, err)
			maps.Insert(cmds, maps.All(script.DefaultCmds()))
			maps.Insert(cmds, maps.All(compute.PolicyComputerScriptCmds(f.computer.(*compute.IdentityPolicyComputer))))
			maps.Insert(cmds, maps.All(policy.RepositoryScriptCmds(f.repo.(*policy.Repository))))
			maps.Insert(cmds, maps.All(identitymanager.ScriptCmds(f.idmgr.(*identitymanager.IdentityManager))))
			maps.Insert(cmds, maps.All(cache.ScriptCmds(f.allocator.(*cache.CachingIdentityAllocator))))
			maps.Insert(cmds, maps.All(policycell.PolicyImporterScriptCmds(f.importer.(*policycell.Importer))))
			maps.Insert(cmds, maps.All(endpointmanager.ScriptCmds(f.epm, f.templateEP)))
			return &script.Engine{
				Cmds:          cmds,
				RetryInterval: 10 * time.Millisecond,
			}
		}, []string{}, "testdata/*.txtar")
}
