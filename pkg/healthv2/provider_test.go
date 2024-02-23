// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package healthv2

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/healthv2/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/statedb"
)

func allStatus(p *HealthProvider) []types.Status {
	ss := []types.Status{}
	tx := p.db.ReadTxn()
	iter, _ := p.Statuses.All(tx)
	for {
		s, _, ok := iter.Next()
		if !ok {
			break
		}
		ss = append(ss, s)
	}
	return ss
}

func byLevel(p *HealthProvider, l types.Level) []types.Status {
	ss := []types.Status{}
	tx := p.db.ReadTxn()
	q := p.LevelIndex.Query(l)
	iter, _ := p.Statuses.Get(tx, q)
	for {
		s, _, ok := iter.Next()
		if !ok {
			break
		}
		ss = append(ss, s)
	}
	return ss
}

func TestProvider(t *testing.T) {
	assert := assert.New(t)
	h := hive.New(
		statedb.Cell,
		cell.Provide(newHealthV2Provider),
		cell.Invoke(func(p *HealthProvider, sd hive.Shutdowner) error {
			h := p.ForModule(types.FullModuleID{"foo", "bar"})
			hm2 := p.ForModule(types.FullModuleID{"foo", "bar2"})
			hm2.NewScope("zzz").OK("yay2")

			h = h.NewScope("zzz")
			h.OK("yay")
			h.Degraded("noo", fmt.Errorf("err0"))

			h2 := h.NewScope("xxx")
			h2.OK("222")

			sd.Shutdown()
			all := allStatus(p)
			assert.Len(all, 3)
			assert.Equal("foo.bar.zzz", all[0].ID.String())

			degraded := byLevel(p, types.LevelDegraded)

			assert.Len(degraded, 1)
			assert.Equal(fmt.Errorf("err0"), degraded[0].Error)
			assert.Equal(degraded[0].Count, uint64(1))

			ok := byLevel(p, types.LevelOK)
			assert.Len(ok, 2)

			assert.Len(byLevel(p, types.LevelStopped), 0)

			h2.Stopped("done")
			all = allStatus(p)

			for _, s := range all {
				if s.ID.String() == "foo.bar.zzz.xxx" {
					assert.NotZero(s.Stopped)
					continue
				}
				assert.Zero(s.Stopped)
			}
			return nil
		}),
	)
	assert.NoError(h.Run())
}
