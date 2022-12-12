// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"fmt"

	"github.com/cilium/cilium-cli/connectivity/check"
)

// PodToWorld sends multiple HTTP(S) requests to one.one.one.one
// from random client Pods.
func PodToWorld() check.Scenario {
	return &podToWorld{}
}

// podToWorld implements a Scenario.
type podToWorld struct{}

func (s *podToWorld) Name() string {
	return "pod-to-world"
}

func (s *podToWorld) Run(ctx context.Context, t *check.Test) {
	http := check.HTTPEndpoint("one-one-one-one-http", "http://one.one.one.one")
	https := check.HTTPEndpoint("one-one-one-one-https", "https://one.one.one.one")
	httpsindex := check.HTTPEndpoint("one-one-one-one-https-index", "https://one.one.one.one/index.html")

	fp := check.FlowParameters{
		DNSRequired: true,
		RSTAllowed:  true,
	}

	var i int
	ct := t.Context()

	for _, client := range ct.ClientPods() {
		client := client // copy to avoid memory aliasing when using reference

		// With http, over port 80.
		t.NewAction(s, fmt.Sprintf("http-to-one-one-one-one-%d", i), &client, http).Run(func(a *check.Action) {
			a.ExecInPod(ctx, ct.CurlCommand(http))
			a.ValidateFlows(ctx, client, a.GetEgressRequirements(fp))
		})

		// With https, over port 443.
		t.NewAction(s, fmt.Sprintf("https-to-one-one-one-one-%d", i), &client, https).Run(func(a *check.Action) {
			a.ExecInPod(ctx, ct.CurlCommand(https))
			a.ValidateFlows(ctx, client, a.GetEgressRequirements(fp))
		})

		// With https, over port 443, index.html.
		t.NewAction(s, fmt.Sprintf("https-to-one-one-one-one-index-%d", i), &client, httpsindex).Run(func(a *check.Action) {
			a.ExecInPod(ctx, ct.CurlCommand(httpsindex))
			a.ValidateFlows(ctx, client, a.GetEgressRequirements(fp))
		})

		i++
	}
}

// PodToWorld2 sends an HTTPS request to cilium.io from from random client
// Pods.
func PodToWorld2() check.Scenario {
	return &podToWorld2{}
}

// podToWorld2 implements a Scenario.
type podToWorld2 struct{}

func (s *podToWorld2) Name() string {
	return "pod-to-world-2"
}

func (s *podToWorld2) Run(ctx context.Context, t *check.Test) {
	https := check.HTTPEndpoint("cilium-io-https", "https://cilium.io")

	fp := check.FlowParameters{
		DNSRequired: true,
		RSTAllowed:  true,
	}

	var i int
	ct := t.Context()

	for _, client := range ct.ClientPods() {
		client := client // copy to avoid memory aliasing when using reference

		// With https, over port 443.
		t.NewAction(s, fmt.Sprintf("https-cilium-io-%d", i), &client, https).Run(func(a *check.Action) {
			a.ExecInPod(ctx, ct.CurlCommand(https))
			a.ValidateFlows(ctx, client, a.GetEgressRequirements(fp))
		})

		i++
	}
}
