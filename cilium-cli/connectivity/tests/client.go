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

// ClientToClient sends an ICMP packet from each client Pod
// to each client Pod in the test context.
func ClientToClient(name string) check.Scenario {
	return &clientToClient{
		name: name,
	}
}

// clientToClient implements a Scenario.
type clientToClient struct {
	name string
}

func (s *clientToClient) Name() string {
	tn := "client-to-client"
	if s.name == "" {
		return tn
	}
	return fmt.Sprintf("%s:%s", tn, s.name)
}

func (s *clientToClient) Run(ctx context.Context, t *check.Test) {
	var i int

	for _, src := range t.Context().ClientPods() {
		for _, dst := range t.Context().ClientPods() {
			if src.Pod.Status.PodIP == dst.Pod.Status.PodIP {
				// Currently we only get flows once per IP,
				// skip pings to self.
				continue
			}

			t.NewAction(s, fmt.Sprintf("ping-%d", i), &src, &dst).Run(func(a *check.Action) {
				a.ExecInPod(ctx, ping(dst))

				a.ValidateFlows(ctx, src, a.GetEgressRequirements(check.FlowParameters{
					Protocol: check.ICMP,
				}))

				a.ValidateFlows(ctx, dst, a.GetIngressRequirements(check.FlowParameters{
					Protocol: check.ICMP,
				}))
			})

			i++
		}
	}
}
