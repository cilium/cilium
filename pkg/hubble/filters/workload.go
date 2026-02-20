// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"context"
	"slices"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/ir"
)

func filterByWorkload(wf []ir.Workload, getEndpoint func(*v1.Event) ir.Endpoint) FilterFunc {
	return func(ev *v1.Event) bool {
		for _, w := range getEndpoint(ev).Workloads {
			if slices.ContainsFunc(wf, func(f ir.Workload) bool {
				return (f.Name == "" || f.Name == w.Name) &&
					(f.Kind == "" || f.Kind == w.Kind)
			}) {
				return true
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
		fs = append(fs, filterByWorkload(ir.ProtoToWorkloads(wf), sourceEndpoint))
	}

	if wf := ff.GetDestinationWorkload(); len(wf) > 0 {
		fs = append(fs, filterByWorkload(ir.ProtoToWorkloads(wf), destinationEndpoint))
	}

	return fs, nil
}
