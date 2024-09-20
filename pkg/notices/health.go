// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package notices

import (
	"context"
	"fmt"

	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/hive/health/types"
	"github.com/cilium/cilium/pkg/time"
)

const (
	healthTitle = "Health"
)

var (
	// healthPostInterval is how often the status table is checked for degraded modules.
	// Variable so tests can override this.
	healthPostInterval = time.Minute
)

// registerPostHealth registers a background timer job to periodically post a notice about degraded
// components.
func registerPostHealth(jg job.Group, n Notices, db *statedb.DB, statuses statedb.Table[types.Status]) {
	jg.Add(job.Timer(
		"post-health",
		postHealth{n, db, statuses}.update,
		healthPostInterval,
	))
}

type postHealth struct {
	notices  Notices
	db       *statedb.DB
	statuses statedb.Table[types.Status]
}

func (ph postHealth) update(ctx context.Context) error {
	var (
		oldestID        string
		oldestMessage   string
		oldestUpdatedAt time.Time
		numDegraded     int
	)
	for status := range ph.statuses.All(ph.db.ReadTxn()) {
		if status.Level == types.LevelDegraded {
			if oldestID == "" || status.Updated.Before(oldestUpdatedAt) {
				oldestUpdatedAt = status.Updated
				oldestMessage = status.Message + ": " + status.Error
				oldestID = status.ID.String()
			}
			numDegraded++
		}
	}

	if numDegraded > 0 {
		ph.notices.Post(
			healthTitle,
			fmt.Sprintf("Degraded: %d unhealthy component(s). Oldest: %s: %q",
				numDegraded,
				oldestID,
				oldestMessage,
			),
			time.Hour,
		)
	} else {
		ph.notices.Retract(healthTitle)
	}

	return nil
}
