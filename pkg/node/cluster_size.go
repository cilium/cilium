// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/time"
)

// ClusterSizeDependantIntervalFunc returns a time.Duration that is dependent on
// the cluster size, i.e. the number of nodes that have been discovered. This
// can be used to control sync intervals of shared or centralized resources to
// avoid overloading these resources as the cluster grows.
//
// Example sync interval with baseInterval = 1 * time.Minute
//
// nodes | sync interval
// ------+-----------------
// 1     |   41.588830833s
// 2     | 1m05.916737320s
// 4     | 1m36.566274746s
// 8     | 2m11.833474640s
// 16    | 2m49.992800643s
// 32    | 3m29.790453687s
// 64    | 4m10.463236193s
// 128   | 4m51.588744261s
// 256   | 5m32.944565093s
// 512   | 6m14.416550710s
// 1024  | 6m55.946873494s
// 2048  | 7m37.506428894s
// 4096  | 8m19.080616652s
// 8192  | 9m00.662124608s
// 16384 | 9m42.247293667s
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
