// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/time"
)

// ClusterSizeDependantIntervalFunc computes an interval adjusted for the
// current number of nodes.
type ClusterSizeDependantIntervalFunc func(time.Duration) time.Duration

// NewClusterSizeDependantInterval returns a function that computes intervals
// from the current size of the node table.
func NewClusterSizeDependantInterval(
	db *statedb.DB,
	nodes statedb.Table[*Node],
) ClusterSizeDependantIntervalFunc {
	return func(baseInterval time.Duration) time.Duration {
		return backoff.ClusterSizeDependantInterval(
			baseInterval,
			nodes.NumObjects(db.ReadTxn()),
		)
	}
}
