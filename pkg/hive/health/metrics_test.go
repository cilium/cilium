// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package health

import (
	"context"
	"iter"
	"testing"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/hive/health/types"
	"github.com/cilium/cilium/pkg/time"
)

const (
	degradedModuleID = "test"
	okModuleID       = "test2"
)

func Test_Metrics(t *testing.T) {

	var db *statedb.DB
	var table statedb.Table[types.Status]
	publishAsserted := make(chan struct{})
	// Using upstream hive here to avoid import cycles and be able to inject the right metric
	// publishing func for the test.
	h := hive.New(
		statedb.Cell,
		job.Cell,

		cell.ProvidePrivate(newTablesPrivate),
		cell.Provide(
			newHealthV2Provider,
			statedb.RWTable[types.Status].ToTable,
		),
		cell.Provide(func(lc cell.Lifecycle, p types.Provider, jr job.Registry) job.Group {
			h := p.ForModule(cell.FullModuleID{"test"})
			return jr.NewGroup(h, lc)
		}),

		cell.Module("health-metrics-test", "hive module health metrics test",
			cell.Provide(newMetrics),
			cell.Invoke(func(p metricPublisherParams) {
				publish := func(stats map[types.Level]uint64, idToStatus map[string]uint64) {
					assertPublish(t, table, db, stats, idToStatus)
					publishAsserted <- struct{}{}
				}

				p.JobGroup.Add(job.OneShot("module-status-metrics",
					func(ctx context.Context, health cell.Health) error {
						return publishJob(ctx, p, publish)
					}))
			}),

			// Generate some test module health data
			cell.Invoke(func(db_ *statedb.DB, table_ statedb.RWTable[types.Status]) {
				db = db_
				table = table_
				txn := db_.WriteTxn(table_)
				_, _, err := table_.Insert(txn, types.Status{
					ID: types.Identifier{
						Module: cell.FullModuleID{degradedModuleID},
					},
					Level: types.LevelDegraded,
				})
				assert.NoError(t, err)
				_, _, err = table_.Insert(txn, types.Status{
					ID: types.Identifier{
						Module: cell.FullModuleID{okModuleID},
					},
					Level: types.LevelOK,
				})
				assert.NoError(t, err)
				txn.Commit()
			}),
		),
	)
	require.NotNil(t, h)

	tlog := hivetest.Logger(t)
	err := h.Start(tlog, context.TODO())
	require.NoError(t, err)

	t.Cleanup(func() {
		err = h.Stop(tlog, context.TODO())
		require.NoError(t, err)
	})
	select {
	case <-publishAsserted:
	case <-time.After(1 * time.Second):
		t.Error("Timeout waiting for assertion")
	}
}

func assertPublish(t *testing.T, table statedb.Table[types.Status], db *statedb.DB, resMetrics map[types.Level]uint64, idToStatusMetrics map[string]uint64) {
	it := table.All(db.ReadTxn())
	ok, degraded, stopped := count(it)

	assert.Equal(t, resMetrics[types.LevelOK], ok)
	assert.Greater(t, resMetrics[types.LevelOK], uint64(1))
	assert.Equal(t, resMetrics[types.LevelDegraded], degraded)
	assert.Equal(t, uint64(1), resMetrics[types.LevelDegraded])
	assert.Equal(t, resMetrics[types.LevelStopped], stopped)

	assert.Equal(t, idToStatusMetrics[degradedModuleID], degraded)
	assert.Equal(t, uint64(0), idToStatusMetrics[okModuleID])
}

func count(it iter.Seq2[types.Status, statedb.Revision]) (ok uint64, degraded uint64, stopped uint64) {
	for obj := range it {
		switch obj.Level {
		case types.LevelOK:
			ok++
		case types.LevelDegraded:
			degraded++
		case types.LevelStopped:
			stopped++
		}
	}
	return
}
