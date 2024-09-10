// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"context"
	"slices"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

func filterByDropReasonDesc(dropReasons []flowpb.DropReason) FilterFunc {
	return func(ev *v1.Event) bool {
		flow := ev.GetFlow()
		if flow == nil {
			return false
		}
		verdict := flow.GetVerdict()
		if verdict != flowpb.Verdict_DROPPED {
			return false
		}
		return slices.Contains(dropReasons, flow.GetDropReasonDesc())
	}
}

type DropReasonDescFilter struct{}

func (f *DropReasonDescFilter) OnBuildFilter(ctx context.Context, ff *flowpb.FlowFilter) ([]FilterFunc, error) {
	var fs []FilterFunc
	if ff.GetDropReasonDesc() != nil {
		fs = append(fs, filterByDropReasonDesc(ff.GetDropReasonDesc()))
	}
	return fs, nil
}
