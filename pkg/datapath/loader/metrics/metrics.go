// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"github.com/cilium/cilium/pkg/spanstat"
)

// SpanStat is a statistics structure for storing metrics related to datapath
// load operations.
type SpanStat struct {
	BpfCompilation spanstat.SpanStat
	BpfWaitForELF  spanstat.SpanStat
	BpfLoadProg    spanstat.SpanStat
}

// GetMap returns a map of statistic names to stats
func (s *SpanStat) GetMap() map[string]*spanstat.SpanStat {
	return map[string]*spanstat.SpanStat{
		"bpfCompilation": &s.BpfCompilation,
		"bpfWaitForELF":  &s.BpfWaitForELF,
		"bpfLoadProg":    &s.BpfLoadProg,
	}
}
