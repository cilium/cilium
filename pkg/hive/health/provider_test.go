// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package health

import (
	"fmt"
	"testing"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/hive/health/types"
)

func allStatus(db *statedb.DB, statusTable statedb.RWTable[types.Status]) []types.Status {
	return statedb.Collect(statusTable.All(db.ReadTxn()))
}

func byLevel(db *statedb.DB, statusTable statedb.RWTable[types.Status], l types.Level) []types.Status {
	return statedb.Collect(statusTable.List(db.ReadTxn(), LevelIndex.Query(l)))
}

func TestProvider(t *testing.T) {
	assert := assert.New(t)
	h := hive.New(
		statedb.Cell,
		cell.Provide(newHealthV2Provider),
		cell.ProvidePrivate(newTablesPrivate),
		cell.Invoke(func(statusTable statedb.RWTable[types.Status], db *statedb.DB, p types.Provider, sd hive.Shutdowner) error {
			h := p.ForModule(cell.FullModuleID{"foo", "bar"})
			hm2 := p.ForModule(cell.FullModuleID{"foo", "bar2"})
			hm2.NewScope("zzz").OK("yay2")

			h = h.NewScope("zzz")
			h.OK("yay")
			h.Degraded("noo", fmt.Errorf("err0"))

			h2 := h.NewScope("xxx")
			h2.OK("222")

			sd.Shutdown()
			all := allStatus(db, statusTable)
			assert.Len(all, 3)
			assert.Equal("foo.bar.zzz", all[0].ID.String())

			degraded := byLevel(db, statusTable, types.LevelDegraded)

			assert.Len(degraded, 1)
			assert.Equal("noo", degraded[0].Message)
			assert.Equal("err0", degraded[0].Error)
			assert.Equal(uint64(1), degraded[0].Count)

			ok := byLevel(db, statusTable, types.LevelOK)
			assert.Len(ok, 2)

			assert.Empty(byLevel(db, statusTable, types.LevelStopped))

			h2.Stopped("done")
			all = allStatus(db, statusTable)

			for _, s := range all {
				if s.ID.String() == "foo.bar.zzz.xxx" {
					assert.NotZero(s.Stopped)
					assert.EqualValues(types.LevelStopped, s.Level)
					continue
				}
				assert.Zero(s.Stopped)
			}
			return nil
		}),
	)
	assert.NoError(h.Run(hivetest.Logger(t)))
}
