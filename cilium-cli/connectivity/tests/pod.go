// SPDX-License-Identifier: Apache-2.0
// Copyright 2020-2021 Authors of Cilium

package tests

import (
	"context"
	"fmt"

	"github.com/cilium/cilium-cli/connectivity/check"
)

// PodToPod generates one HTTP request from each client pod
// to each echo (server) pod in the test context. The remote Pod is contacted
// directly, no DNS is involved.
func PodToPod() check.Scenario {
	return &podToPod{}
}

// podToPod implements a Scenario.
type podToPod struct{}

func (s *podToPod) Name() string {
	return "pod-to-pod"
}

func (s *podToPod) Run(ctx context.Context, t *check.Test) {
	var i int

	for _, client := range t.Context().ClientPods() {
		client := client // copy to avoid memory aliasing when using reference

		for _, echo := range t.Context().EchoPods() {
			t.NewAction(s, fmt.Sprintf("curl-%d", i), &client, echo).Run(func(a *check.Action) {
				a.ExecInPod(ctx, curl(echo))

				a.ValidateFlows(ctx, client, a.GetEgressRequirements(check.FlowParameters{}))
				a.ValidateFlows(ctx, echo, a.GetIngressRequirements(check.FlowParameters{}))
			})

			i++
		}
	}
}

func PodToPodWithEndpoints() check.Scenario {
	return &podToPodWithEndpoints{}
}

// podToPodWithEndpoints implements a Scenario.
type podToPodWithEndpoints struct{}

func (s *podToPodWithEndpoints) Name() string {
	return "pod-to-pod-with-endpoints"
}

func (s *podToPodWithEndpoints) Run(ctx context.Context, t *check.Test) {
	var i int

	for _, client := range t.Context().ClientPods() {
		client := client // copy to avoid memory aliasing when using reference

		for _, echo := range t.Context().EchoPods() {
			curlEndpoints(ctx, s, t, fmt.Sprintf("curl-%d", i), &client, echo)

			i++
		}
	}
}

func curlEndpoints(ctx context.Context, s check.Scenario, t *check.Test,
	name string, client *check.Pod, echo check.TestPeer) {

	baseURL := fmt.Sprintf("%s://%s:%d", echo.Scheme(), echo.Address(), echo.Port())

	// Manually construct an HTTP endpoint for each API endpoint.
	for _, path := range []string{"public", "private"} {
		epName := fmt.Sprintf("%s-%s", name, path)
		url := fmt.Sprintf("%s/%s", baseURL, path)
		ep := check.HTTPEndpoint(epName, url)

		t.NewAction(s, epName, client, ep).Run(func(a *check.Action) {
			a.ExecInPod(ctx, curl(ep))

			a.ValidateFlows(ctx, client, a.GetEgressRequirements(check.FlowParameters{}))
			a.ValidateFlows(ctx, ep, a.GetIngressRequirements(check.FlowParameters{}))
		})

		// Additionally test private endpoint access with HTTP header expected by policy.
		if path == "private" {
			epName += "with-header"
			ep = check.HTTPEndpointWithLabels(epName, url, map[string]string{
				"X-Very-Secret-Token": "42",
			})
			t.NewAction(s, epName, client, ep).Run(func(a *check.Action) {
				a.ExecInPod(ctx, curl(ep, "-H", "X-Very-Secret-Token: 42"))

				a.ValidateFlows(ctx, client, a.GetEgressRequirements(check.FlowParameters{}))
				a.ValidateFlows(ctx, ep, a.GetIngressRequirements(check.FlowParameters{}))
			})
		}
	}
}
