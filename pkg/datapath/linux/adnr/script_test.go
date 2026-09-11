// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package adnr

import (
	"context"
	"maps"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/datapath/linux"
	routeReconciler "github.com/cilium/cilium/pkg/datapath/linux/route/reconciler"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

func TestScript(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)

	scripttest.Test(t, ctx, func(t testing.TB, args []string) *script.Engine {
		// We set the name of the local node so that we can recognize it in the test data.
		types.SetName("local-node")

		cfg := &option.DaemonConfig{
			EnableAutoDirectRouting:      true,
			EnableIPv4:                   true,
			EnableIPv6:                   true,
			DirectRoutingSkipUnreachable: false,
		}

		h := hive.New(
			routeReconciler.TableCell,
			cell.Provide(node.NewNodeTable),
			cell.Provide(statedb.RWTable[*node.Node].ToTable),
			cell.Provide(tables.NewRouteTable),
			cell.Provide(statedb.RWTable[*tables.Route].ToTable),
			cell.Provide(func() reconciler.Reconciler[*routeReconciler.DesiredRoute] {
				return nil
			}),
			cell.Provide(func() *option.DaemonConfig {
				return cfg
			}),
			cell.Provide(linux.NewNodePolicy),
			Cell,
		)
		flags := pflag.NewFlagSet("", pflag.ContinueOnError)

		// we need to map the flag to the config so that the script can set them
		flags.BoolVar(
			&cfg.DirectRoutingSkipUnreachable,
			"direct-routing-skip-unreachable",
			false,
			"Skip unreachable nodes",
		)
		require.NoError(t, flags.Parse(args))

		log := hivetest.Logger(t)
		t.Cleanup(func() {
			assert.NoError(t, h.Stop(log, context.Background()))
		})

		cmds, err := h.ScriptCommands(log)
		require.NoError(t, err)
		maps.Copy(cmds, script.DefaultCmds())
		return &script.Engine{Cmds: cmds}
	}, []string{}, "testdata/*.txtar")
}
