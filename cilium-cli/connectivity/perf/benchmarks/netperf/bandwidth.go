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
	bandwidthToolName = "bandwidth"
)

// NetBandwidth : Test Network QoS Enforcement
func NetBandwidth(n string) check.Scenario {
	return &bandwidth{
		name:         n,
		ScenarioBase: check.NewScenarioBase(),
	}
}

type bandwidth struct {
	check.ScenarioBase

	lock.Mutex
	name string
}

func (s *bandwidth) Name() string {
	if s.name == "" {
		return bandwidthToolName
	}
	return fmt.Sprintf("%s:%s", bandwidthToolName, s.name)
}

func (s *bandwidth) Run(ctx context.Context, t *check.Test) {
	perfParameters := t.Context().Params().PerfParameters
	tests := []string{"TCP_STREAM"}
	tputSum := map[string]uint64{}
	var wg sync.WaitGroup

	for sample := 1; sample <= perfParameters.Samples; sample++ {
		for _, c := range t.Context().PerfClientPods() {
			c := c

			client := getTestSet(c.Name())
			for _, server := range t.Context().PerfServerPod() {
				if getTestSet(server.Name()) != client {
					continue
				}

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
	t.Context().Log("\n")
	for k, v := range tputSum {
		t.Context().Infof("%s : %v", k, uint64(v))
		if v > 11 {
			t.Failf("Bandwidth limit failed to enforced")
		}
	}
}

func getTestSet(name string) string {
	if strings.Contains(name, "ingress") {
		return "ingress"
	}
	if strings.Contains(name, "egress") {
		return "egress"
	}
	return ""
}
