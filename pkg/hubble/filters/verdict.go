// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"context"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

func filterByVerdicts(vs []flowpb.Verdict) FilterFunc {
	return func(ev *v1.Event) bool {
		flow := ev.GetFlow()
		if flow == nil {
			return false
		}
		for _, verdict := range vs {
			if verdict == flow.GetVerdict() {
				return true
			}
		}

		return false
	}
}

// VerdictFilter implements filtering based on forwarding verdict
type VerdictFilter struct{}

// OnBuildFilter builds a forwarding verdict filter
func (v *VerdictFilter) OnBuildFilter(ctx context.Context, ff *flowpb.FlowFilter) ([]FilterFunc, error) {
	var fs []FilterFunc

	if ff.GetVerdict() != nil {
		fs = append(fs, filterByVerdicts(ff.GetVerdict()))
	}

	return fs, nil
}
