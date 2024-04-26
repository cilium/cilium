// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"context"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

func filterByDropReasonDesc(dropReasons []flowpb.DropReason) (FilterFunc, error) {
	return func(ev *v1.Event) bool {
		flow := ev.GetFlow()
		if flow == nil {
			return false
		}
		reasonDesc := flow.GetDropReasonDesc()
		verdict := flow.GetVerdict()
		if verdict != flowpb.Verdict_DROPPED {
			return false
		}
		for _, reason := range dropReasons {
			if reason == reasonDesc {
				return true
			}
		}
		return false
	}, nil
}

type DropReasonDescFilter struct{}

func (f *DropReasonDescFilter) OnBuildFilter(ctx context.Context, ff *flowpb.FlowFilter) ([]FilterFunc, error) {
	var fs []FilterFunc
	if ff.GetDropReasonDesc() != nil {
		filter, err := filterByDropReasonDesc(ff.GetDropReasonDesc())
		if err != nil {
			return nil, err
		}
		fs = append(fs, filter)
	}
	return fs, nil
}
