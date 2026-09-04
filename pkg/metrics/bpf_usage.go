// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"golang.org/x/sync/singleflight"
)

var bpfUsageGroup singleflight.Group

const bpfUsageFlightKey = "collect"

// getBPFUsage returns memory usage of BPF programs matching cil_/tail_ prefixes and
// their associated maps. Concurrent callers share a single kernel walk.
func getBPFUsage() (*bpfUsage, error) {
	results, err, _ := bpfUsageGroup.Do(bpfUsageFlightKey, func() (any, error) {
		return newBPFVisitor([]string{"cil_", "tail_"}).Usage()
	})
	if err != nil {
		return nil, err
	}
	return results.(*bpfUsage), nil
}
