// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"context"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

func filterByWorkload(wf []*flowpb.Workload, getEndpoint func(*v1.Event) *flowpb.Endpoint) FilterFunc {
	return func(ev *v1.Event) bool {
		for _, w := range getEndpoint(ev).GetWorkloads() {
			for _, f := range wf {
				if (f.GetName() == "" || f.GetName() == w.GetName()) &&
					(f.GetKind() == "" || f.GetKind() == w.GetKind()) {
					return true
				}
			}
		}
		return false
	}
}

// WorkloadFilter implements filtering based on endpoint workload
type WorkloadFilter struct{}

// OnBuildFilter builds an endpoint workload filter
func (*WorkloadFilter) OnBuildFilter(ctx context.Context, ff *flowpb.FlowFilter) ([]FilterFunc, error) {
	var fs []FilterFunc

	if wf := ff.GetSourceWorkload(); len(wf) > 0 {
		fs = append(fs, filterByWorkload(wf, sourceEndpoint))
	}

	if wf := ff.GetDestinationWorkload(); len(wf) > 0 {
		fs = append(fs, filterByWorkload(wf, destinationEndpoint))
	}

	return fs, nil
}
