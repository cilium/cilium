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
type podToWorld struct {
}

func (s *podToWorld) Name() string {
	return "pod-to-world"
}

func (s *podToWorld) Run(ctx context.Context, t *check.Test) {
	extTarget := t.Context().Params().ExternalTarget
	http := check.HTTPEndpoint(extTarget+"-http", "http://"+extTarget)
	https := check.HTTPEndpoint(extTarget+"-https", "https://"+extTarget)
	httpsindex := check.HTTPEndpoint(extTarget+"-https-index", fmt.Sprintf("https://%s/index.html", extTarget))

	fp := check.FlowParameters{
		DNSRequired: true,
		RSTAllowed:  true,
	}

	var i int
	ct := t.Context()

	for _, client := range ct.ClientPods() {
		client := client // copy to avoid memory aliasing when using reference

		// With http, over port 80.
		t.NewAction(s, fmt.Sprintf("http-to-%s-%d", extTarget, i), &client, http, check.IPFamilyNone).Run(func(a *check.Action) {
			a.ExecInPod(ctx, ct.CurlCommand(http, check.IPFamilyNone))
			a.ValidateFlows(ctx, client, a.GetEgressRequirements(fp))
		})

		// With https, over port 443.
		t.NewAction(s, fmt.Sprintf("https-to-%s-%d", extTarget, i), &client, https, check.IPFamilyNone).Run(func(a *check.Action) {
			a.ExecInPod(ctx, ct.CurlCommand(https, check.IPFamilyNone))
			a.ValidateFlows(ctx, client, a.GetEgressRequirements(fp))
		})

		// With https, over port 443, index.html.
		t.NewAction(s, fmt.Sprintf("https-to-%s-index-%d", extTarget, i), &client, httpsindex, check.IPFamilyNone).Run(func(a *check.Action) {
			a.ExecInPod(ctx, ct.CurlCommand(httpsindex, check.IPFamilyNone))
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
		t.NewAction(s, fmt.Sprintf("https-cilium-io-%d", i), &client, https, check.IPFamilyNone).Run(func(a *check.Action) {
			a.ExecInPod(ctx, ct.CurlCommand(https, check.IPFamilyNone))
			a.ValidateFlows(ctx, client, a.GetEgressRequirements(fp))
		})

		i++
	}
}
