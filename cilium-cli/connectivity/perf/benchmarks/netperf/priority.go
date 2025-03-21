// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package netperf

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/perf/common"
	"github.com/cilium/cilium/cilium-cli/utils/features"
	"github.com/cilium/cilium/pkg/lock"
)

const (
	netQosToolName = "netQos"
)

// NetQos : Test Network QoS Enforcement
func NetQos(n string) check.Scenario {
	return &netQos{
		name:         n,
		ScenarioBase: check.NewScenarioBase(),
	}
}

type netQos struct {
	check.ScenarioBase

	lock.Mutex
	name string
}

func (s *netQos) Name() string {
	if s.name == "" {
		return netQosToolName
	}
	return fmt.Sprintf("%s:%s", netQosToolName, s.name)
}

func (s *netQos) Run(ctx context.Context, t *check.Test) {
	perfParameters := t.Context().Params().PerfParameters
	tests := []string{"TCP_STREAM"}
	tputSum := map[string]uint64{}
	var wg sync.WaitGroup

	for sample := 1; sample <= perfParameters.Samples; sample++ {
		for _, c := range t.Context().PerfClientPods() {
			c := c
			for _, server := range t.Context().PerfServerPod() {
				scenarioName := "pod-to-pod"

				sameNode := false
				for _, test := range tests {
					testName := netQosToolName + "_" + test + "_" + scenarioName
					action := t.NewAction(s, testName, &c, server, features.IPFamilyV4)
					action.CollectFlows = false
					wg.Add(1)
					go action.Run(func(a *check.Action) {
						k := common.PerfTests{
							Test:     test,
							Tool:     netQosToolName,
							SameNode: sameNode,
							Sample:   sample,
							Duration: 30 * time.Second,
							Scenario: scenarioName,
							MsgSize:  1500000,
							NetQos:   true,
						}
						perfResult := NetperfCmd(ctx, server.Pod.Status.PodIP, k, a)
						s.Lock()
						tputSum[c.Name()] += uint64(perfResult.ThroughputMetric.Throughput / 1000000)
						s.Unlock()
						wg.Done()
					})
				}
			}
		}
	}
	wg.Wait()
	var lowPrio, highPrio uint64
	t.Context().Log("\n")
	for k, v := range tputSum {
		t.Context().Infof("%s : %v", k, uint64(v))
		if strings.Contains(k, "low") {
			lowPrio = uint64(v)
		}
		if strings.Contains(k, "high") {
			highPrio = uint64(v)
		}
	}
	if lowPrio == 0 || highPrio == 0 {
		t.Failf("QoS ratio not enforced between high and low priority traffic; High : %v, Low: %v",
			highPrio, lowPrio)
		return
	}
	ratio := highPrio / lowPrio
	if !(ratio >= 8 && ratio <= 9) {
		t.Failf("QoS ratio not enforced between high and low priority traffic; High : %v, Low: %v, ratio: %v",
			highPrio, lowPrio, ratio)
	}
}
