// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"context"
	"slices"

	"github.com/cilium/cilium/api/v1/flow"
	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

func filterByVerdicts(vs []flow.Verdict) FilterFunc {
	return func(ev *v1.Event) bool {
		fl := ev.GetFlow()
		if fl == nil {
			return false
		}

		return slices.Contains(vs, flow.Verdict(fl.Verdict))
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
