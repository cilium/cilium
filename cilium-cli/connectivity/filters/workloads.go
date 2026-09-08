// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package filters

import (
	"fmt"
	"slices"
	"strings"

	flowpb "github.com/cilium/cilium/api/v1/flow"
)

type workloadsFilter struct {
	source      *flowpb.Workload
	destination *flowpb.Workload
}

// Workloads matches source and destination workloads. A nil workload is not
// checked.
func Workloads(source, destination *flowpb.Workload) FlowFilterImplementation {
	return &workloadsFilter{source: source, destination: destination}
}

func (f *workloadsFilter) Match(flow *flowpb.Flow, _ *FlowContext) bool {
	return workloadMatches(flow.GetSource().GetWorkloads(), f.source) &&
		workloadMatches(flow.GetDestination().GetWorkloads(), f.destination)
}

func (f *workloadsFilter) String(_ *FlowContext) string {
	var workloads []string
	if f.source != nil {
		workloads = append(workloads, fmt.Sprintf("source=%s/%s", f.source.GetKind(), f.source.GetName()))
	}
	if f.destination != nil {
		workloads = append(workloads, fmt.Sprintf("destination=%s/%s", f.destination.GetKind(), f.destination.GetName()))
	}
	return "workloads(" + strings.Join(workloads, ",") + ")"
}

func workloadMatches(workloads []*flowpb.Workload, expected *flowpb.Workload) bool {
	if expected == nil {
		return true
	}
	return slices.ContainsFunc(workloads, func(workload *flowpb.Workload) bool {
		return workload.GetName() == expected.GetName() && workload.GetKind() == expected.GetKind()
	})
}
