// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"context"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

func filterByTraceID(tids []string) FilterFunc {
	return func(ev *v1.Event) bool {
		traceID := ev.GetFlow().GetTraceContext().GetParent().GetTraceId()
		for _, tid := range tids {
			if tid == traceID {
				return true
			}
		}
		return false
	}
}

// TraceIDFilter implements filtering based on trace IDs.
type TraceIDFilter struct{}

// OnBuildFilter builds a trace ID filter.
func (t *TraceIDFilter) OnBuildFilter(_ context.Context, ff *flowpb.FlowFilter) ([]FilterFunc, error) {
	var fs []FilterFunc
	if tids := ff.GetTraceId(); tids != nil {
		fs = append(fs, filterByTraceID(tids))
	}
	return fs, nil
}
