// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"context"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

func filterByTrafficDirection(directions []flowpb.TrafficDirection) FilterFunc {
	return func(ev *v1.Event) bool {
		flow := ev.GetFlow()
		if flow == nil {
			return false
		}
		for _, d := range directions {
			if d == flow.GetTrafficDirection() {
				return true
			}
		}
		return false
	}
}

// TrafficDirectionFilter implements filtering based on flow traffic direction
// (e.g. ingress or egress).
type TrafficDirectionFilter struct{}

// OnBuildFilter builds a a flow traffic direction filter.
func (e *TrafficDirectionFilter) OnBuildFilter(ctx context.Context, ff *flowpb.FlowFilter) ([]FilterFunc, error) {
	var fs []FilterFunc

	if directions := ff.GetTrafficDirection(); len(directions) > 0 {
		fs = append(fs, filterByTrafficDirection(directions))
	}

	return fs, nil
}
