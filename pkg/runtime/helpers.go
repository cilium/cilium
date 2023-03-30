// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package runtime

import (
	"runtime/metrics"

	"github.com/cilium/cilium/pkg/logging/logfields"
	cmx "github.com/cilium/cilium/pkg/metrics"
	"github.com/sirupsen/logrus"
)

func rtLogger(log logrus.FieldLogger) logrus.FieldLogger {
	return log.WithFields(logrus.Fields{
		logfields.LogSubsys: cmx.SubsystemRuntime,
	})
}

func compact(h *metrics.Float64Histogram) {
	nc, nb := make([]uint64, 0, len(h.Counts)), make([]float64, 0, len(h.Counts))
	for i, c := range h.Counts {
		if c == 0 {
			continue
		}
		if i >= len(h.Buckets) {
			break
		}
		if h.Buckets[i] > 0 {
			nc, nb = append(nc, c), append(nb, h.Buckets[i])
		}
	}
	h.Counts, h.Buckets = nc, nb
}

func computeMedian(h *metrics.Float64Histogram) float64 {
	compact(h)
	var total uint64
	for _, c := range h.Counts {
		total += c
	}
	m, total := total/2, 0
	if m == 0 {
		return 0
	}
	for i, c := range h.Counts {
		total += c
		if total >= m {
			return h.Buckets[i]
		}
	}

	return 0
}
