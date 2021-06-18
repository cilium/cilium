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

// PodToCIDR sends an ICMP packet from each client Pod
// to 1.1.1.1 and 1.0.0.1.
func PodToCIDR(name string) check.Scenario {
	return &podToCIDR{
		name: name,
	}
}

// podToCIDR implements a Scenario.
type podToCIDR struct {
	name string
}

func (s *podToCIDR) Name() string {
	tn := "pod-to-cidr"
	if s.name == "" {
		return tn
	}
	return fmt.Sprintf("%s:%s", tn, s.name)
}

func (s *podToCIDR) Run(ctx context.Context, t *check.Test) {

	eps := []check.TestPeer{
		check.HTTPEndpoint("cloudflare-1001", "http://1.0.0.1"),
		check.HTTPEndpoint("cloudflare-1111", "http://1.1.1.1"),
	}

	for _, ep := range eps {
		var i int
		for _, src := range t.Context().ClientPods() {
			t.NewAction(s, fmt.Sprintf("%s-%d", ep.Name(), i), &src, ep).Run(func(a *check.Action) {
				a.ExecInPod(ctx, curl(ep))

				a.ValidateFlows(ctx, src, a.GetEgressRequirements(check.FlowParameters{
					RSTAllowed: true,
				}))
			})

			i++
		}
	}
}
