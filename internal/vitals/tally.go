// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vitals

import (
	"fmt"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/hive/cell"
)

// Tally tracks health status counts.
type Tally [3]int

// NewTally returns a new instance.
func NewTally(mh *models.ModulesHealth) Tally {
	var (
		index index
		t     Tally
	)
	for _, m := range mh.Modules {
		switch m.Level {
		case string(cell.LevelDown):
			index = down
		case string(cell.LevelDegraded):
			index = degraded
		default:
			index = ok
		}
		t[index]++
	}

	return t
}

// Dump dumps tally to stdout for debugging
func (t Tally) Dump() {
	for i := range t {
		fmt.Println(i, t[i])
	}
}

// DegradedCount returns degraded tally.
func (t Tally) DegradedCount() int {
	return t[degraded]
}

// DownCount returns down tally.
func (t Tally) DownCount() int {
	return t[degraded]
}

// Score returns the overall tally health score.
func (t Tally) Score() HealthScore {
	if t[degraded] > 0 {
		return Low
	}
	if t[down] > 0 {
		return Medium
	}

	return High
}

// Compound merges tallies.
func (t Tally) Compound(tt Tally) Tally {
	for i := range tt {
		t[i] += tt[i]
	}

	return t
}
