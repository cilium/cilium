// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"context"
	"slices"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

func filterByIPTraceID(tids []uint64) FilterFunc {
	return func(ev *v1.Event) bool {
		if ev == nil {
			return false
		}
		flow := ev.GetFlow()
		if flow == nil {
			return false
		}

		return slices.Contains(tids, flow.IPTraceID.TraceID)
	}
}

// TraceIDFilter implements filtering based on IP trace IDs.
type IPTraceIDFilter struct{}

// OnBuildFilter builds a IP trace ID filter.
func (t *IPTraceIDFilter) OnBuildFilter(_ context.Context, ff *flowpb.FlowFilter) ([]FilterFunc, error) {
	var fs []FilterFunc
	if ids := ff.GetIpTraceId(); len(ids) > 0 {
		fs = append(fs, filterByIPTraceID(ids))
	}
	return fs, nil
}
