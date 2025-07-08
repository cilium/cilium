// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package health

import (
	"context"
	"log/slog"

	"github.com/cilium/cilium/pkg/hive/health/types"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
)

const (
	healthLoggerInterval = 10 * time.Minute
)

func registerHealthLogger(jg job.Group, p healthLoggerParams) {
	hl := &healthLogger{
		healthLoggerParams: p,
		prevDegraded:       map[types.HealthID]types.Status{},
	}
	jg.Add(
		job.Timer(
			"health-logger",
			hl.report,
			10*time.Minute,
		),
	)
}

type healthLoggerParams struct {
	cell.In

	Log         *slog.Logger
	DB          *statedb.DB
	StatusTable statedb.Table[types.Status]
}

// logger periodically reports degraded modules in logs and reports the
// recovery back to normal.
type healthLogger struct {
	healthLoggerParams

	prevDegraded map[types.HealthID]types.Status
	since        map[types.HealthID]time.Time
}

func (l *healthLogger) report(ctx context.Context) error {
	txn := l.DB.ReadTxn()

	// Grab all degraded statuses
	degraded := map[types.HealthID]types.Status{}
	for s := range l.StatusTable.List(txn, LevelIndex.Query(types.LevelDegraded)) {
		degraded[s.ID.HealthID()] = s
	}

	// Remove existing statuses from [degraded] and add the no longer degraded statuses
	// to [recovered]. This leaves only newly degraded statuses to [degraded].
	recovered := map[types.HealthID]types.Status{}
	for id, s := range l.prevDegraded {
		newStatus, found := degraded[id]
		if !found {
			delete(l.prevDegraded, id)
			recovered[id] = s
		} else if s.Updated == newStatus.Updated {
			l.prevDegraded[id] = s
			delete(degraded, id)
		}
	}
	for id, s := range degraded {
		l.since[id] = s.Updated
		l.prevDegraded[id] = s
	}

	// If there are no newly degraded statuses nor any recovered statuses then nothing has
	// changed since last time.
	if len(degraded) == 0 && len(recovered) == 0 {
		return nil
	}

	// TODO: Or should this be a single call to report health and have everything in attributes?
	l.Log.Info("--- Module health update ---")
	for id, s := range l.prevDegraded {
		l.Log.Warn("Degraded", "id", s.ID, "message", s.Message, "error", s.Error, "since", time.Since(l.since[id]))
	}
	for id, oldStatus := range recovered {
		newStatus, _, _ := l.StatusTable.Get(txn, PrimaryIndex.Query(id))
		l.Log.Info("Recovered",
			"id", id,
			"message", newStatus.Message,
			"old-message", oldStatus.Message,
			"old-error", oldStatus.Error,
			"duration", time.Since(l.since[id]))
		delete(l.since, id)
	}

	return nil
}
