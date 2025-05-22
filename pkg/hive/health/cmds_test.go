// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package health

import (
	"context"
	"maps"
	"testing"

	"github.com/cilium/cilium/pkg/hive/health/types"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	"github.com/cilium/statedb"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHealthCommands(t *testing.T) {
	log := hivetest.Logger(t)
	scripttest.Test(t,
		context.Background(),
		func(t testing.TB, args []string) *script.Engine {
			h := hive.New(
				statedb.Cell,
				Cell,
				job.Cell,
				cell.Provide(func(lc cell.Lifecycle, p types.Provider, jr job.Registry) job.Group {
					h := p.ForModule(cell.FullModuleID{"test"})
					return jr.NewGroup(h, lc)
				}),
				cell.Invoke(func(p types.Provider) {
					hr := p.ForModule(cell.FullModuleID{"agent", "m0"})
					hr.NewScope("c0").OK("ok")
				}),
			)
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
