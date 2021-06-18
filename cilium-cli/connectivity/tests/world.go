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

// PodToWorld sends multiple HTTP(S) requests to google.com
// from random client Pods.
func PodToWorld(name string) check.Scenario {
	return &podToWorld{
		name: name,
	}
}

// podToWorld implements a Scenario.
type podToWorld struct {
	name string
}

func (s *podToWorld) Name() string {
	tn := "pod-to-world"
	if s.name == "" {
		return tn
	}
	return fmt.Sprintf("%s:%s", tn, s.name)
}

func (s *podToWorld) Run(ctx context.Context, t *check.Test) {
	ghttp := check.HTTPEndpoint("google-http", "http://google.com")
	ghttps := check.HTTPEndpoint("google-https", "https://google.com")
	wwwghttp := check.HTTPEndpoint("www-google-http", "http://www.google.com")

	// With https, over port 443.
	if client := t.Context().RandomClientPod(); client != nil {
		cmd := curl(ghttps)

		t.NewAction(s, "https-to-google", client, ghttps).Run(func(a *check.Action) {
			a.ExecInPod(ctx, cmd)

			a.ValidateFlows(ctx, client, a.GetEgressRequirements(check.FlowParameters{
				DNSRequired: true,
				RSTAllowed:  true,
			}))
		})
	}

	// With http, over port 80.
	if client := t.Context().RandomClientPod(); client != nil {
		cmd := curl(ghttp)

		t.NewAction(s, "http-to-google", client, ghttp).Run(func(a *check.Action) {
			a.ExecInPod(ctx, cmd)

			a.ValidateFlows(ctx, client, a.GetEgressRequirements(check.FlowParameters{
				DNSRequired: true,
				RSTAllowed:  true,
			}))
		})
	}

	// With http to www.google.com.
	if client := t.Context().RandomClientPod(); client != nil {
		cmd := curl(wwwghttp)

		t.NewAction(s, "http-to-www-google", client, wwwghttp).Run(func(a *check.Action) {
			a.ExecInPod(ctx, cmd)

			a.ValidateFlows(ctx, client, a.GetEgressRequirements(check.FlowParameters{
				DNSRequired: true,
				RSTAllowed:  true,
			}))
		})
	}
}
