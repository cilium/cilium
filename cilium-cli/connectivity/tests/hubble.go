// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"fmt"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/filters"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

const (
	hubbleWorkloadSourceName      = "client"
	hubbleWorkloadDestinationName = "echo-other-node"
)

type hubbleWorkload struct {
	check.ScenarioBase
}

// HubbleWorkload validates workload metadata on both sides of cross-node
// flows.
func HubbleWorkload() check.Scenario {
	return &hubbleWorkload{ScenarioBase: check.NewScenarioBase()}
}

func (s *hubbleWorkload) Name() string {
	return "cross-node"
}

func (s *hubbleWorkload) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()
	source := podWithName(ct.ClientPods(), hubbleWorkloadSourceName)
	destination := podWithName(ct.EchoPods(), hubbleWorkloadDestinationName)
	if source == nil || destination == nil {
		t.Fatalf("Failed to find %s and %s Pods", hubbleWorkloadSourceName, hubbleWorkloadDestinationName)
	}
	if source.NodeName() == destination.NodeName() {
		t.Fatalf("Pods are not on different nodes: %s", source.NodeName())
	}

	sourceWorkload := &flowpb.Workload{Name: hubbleWorkloadSourceName, Kind: "Deployment"}
	destinationWorkload := &flowpb.Workload{Name: hubbleWorkloadDestinationName, Kind: "Deployment"}

	t.ForEachIPFamily(func(ipFam features.IPFamily) {
		t.NewAction(s, fmt.Sprintf("curl-%s", ipFam), source, destination, ipFam).Run(func(a *check.Action) {
			a.ExecInPod(ctx, a.CurlCommand(destination))

			workloadRequest := filters.And(
				filters.IP(source.Address(ipFam), destination.Address(ipFam)),
				filters.Workloads(sourceWorkload, destinationWorkload),
			)
			l7Request := filters.And(workloadRequest, filters.HTTP(0, "GET", ""))

			sourceFlow := filters.FlowRequirement{
				Filter: filters.And(workloadRequest, filters.NodeName(source.NodeName())),
				Msg:    "source-node flow with source and destination workloads",
			}
			sourceL7Flow := filters.FlowRequirement{
				Filter: filters.And(l7Request, filters.NodeName(source.NodeName())),
				Msg:    "source-node HTTP flow with source and destination workloads",
			}
			a.ValidateFlows(ctx, source, []filters.FlowSetRequirement{
				{First: sourceFlow, Last: sourceFlow},
				{First: sourceL7Flow, Last: sourceL7Flow},
			})

			destinationFlow := filters.FlowRequirement{
				Filter: filters.And(workloadRequest, filters.NodeName(destination.NodeName())),
				Msg:    "destination-node flow with source and destination workloads",
			}
			destinationL7Flow := filters.FlowRequirement{
				Filter: filters.And(l7Request, filters.NodeName(destination.NodeName())),
				Msg:    "destination-node HTTP flow with source and destination workloads",
			}
			a.ValidateFlows(ctx, destination, []filters.FlowSetRequirement{
				{First: destinationFlow, Last: destinationFlow},
				{First: destinationL7Flow, Last: destinationL7Flow},
			})
		})
	})
}

func podWithName(pods map[string]check.Pod, name string) *check.Pod {
	for key := range pods {
		pod := pods[key]
		if pod.HasLabel("name", name) {
			return &pod
		}
	}
	return nil
}
