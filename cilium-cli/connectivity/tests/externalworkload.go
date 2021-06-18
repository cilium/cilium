// Copyright 2021 Authors of Cilium
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

func PodToExternalWorkload(name string) check.Scenario {
	return &podToExternalWorkload{
		name: name,
	}
}

type podToExternalWorkload struct {
	name string
}

func (s *podToExternalWorkload) Name() string {
	tn := "pod-to-external-workload"
	if s.name == "" {
		return tn
	}
	return fmt.Sprintf("%s:%s", tn, s.name)
}

func (s *podToExternalWorkload) Run(ctx context.Context, t *check.Test) {
	var i int

	for _, pod := range t.Context().ClientPods() {
		for _, wl := range t.Context().ExternalWorkloads() {

			t.NewAction(s, fmt.Sprintf("ping-%d", i), &pod, wl).Run(func(a *check.Action) {
				a.ExecInPod(ctx, ping(wl))

				a.ValidateFlows(ctx, pod, a.GetEgressRequirements(check.FlowParameters{
					Protocol: check.ICMP,
				}))

				a.ValidateFlows(ctx, wl, a.GetIngressRequirements(check.FlowParameters{
					Protocol: check.ICMP,
				}))
			})

			i++
		}
	}
}
