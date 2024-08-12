// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble
package filters

import (
	"context"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

// filterByIpTraceId returns a filter function that matches events with the
// given IP Trace IDs.
func filterByIpTraceId(ipTraceIDs []uint64) FilterFunc {
	return func(ev *v1.Event) bool {
		flowTraceIDs := ev.GetFlow().GetIpTraceId()
		if flowTraceIDs == nil {
			return false
		}
		for _, trace_id := range ipTraceIDs {
			if trace_id == flowTraceIDs.GetTraceId() {
				return true
			}
		}
		return false
	}
}

// IPTraceIDFilter implements filtering based on flow IPTraceIDs.
type IPTraceIDFilter struct{}

// OnBuildFilter builds an IP Trace ID filter.
func (e *IPTraceIDFilter) OnBuildFilter(ctx context.Context, ff *flowpb.FlowFilter) ([]FilterFunc, error) {
	var fs []FilterFunc
	if ids := ff.GetIpTraceId(); len(ids) > 0 {
		fs = append(fs, filterByIpTraceId(ids))
	}
	return fs, nil
}
