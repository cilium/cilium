// Copyright 2020-2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tests

import (
	"context"
	"fmt"

	"github.com/cilium/cilium-cli/connectivity/check"
)

// PodToPod generates one HTTP request from each client pod
// to each echo (server) pod in the test context. The remote Pod is contacted
// directly, no DNS is involved.
func PodToPod(name string) check.Scenario {
	return &podToPod{
		name: name,
	}
}

// podToPod implements a Scenario.
type podToPod struct {
	name string
}

func (s *podToPod) Name() string {
	tn := "pod-to-pod"
	if s.name == "" {
		return tn
	}
	return fmt.Sprintf("%s:%s", tn, s.name)
}

func (s *podToPod) Run(ctx context.Context, t *check.Test) {
	var i int

	for _, client := range t.Context().ClientPods() {
		for _, echo := range t.Context().EchoPods() {

			t.NewAction(s, fmt.Sprintf("curl-%d", i), &client, echo).Run(func(a *check.Action) {
				a.ExecInPod(ctx, curl(echo))

				egressFlowRequirements := a.GetEgressRequirements(check.FlowParameters{})
				a.ValidateFlows(ctx, client.Name(), client.Pod.Status.PodIP, egressFlowRequirements)

				ingressFlowRequirements := a.GetIngressRequirements(check.FlowParameters{})
				if ingressFlowRequirements != nil {
					a.ValidateFlows(ctx, echo.Name(), echo.Pod.Status.PodIP, ingressFlowRequirements)
				}
			})

			i++
		}
	}
}
