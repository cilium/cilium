// SPDX-License-Identifier: Apache-2.0
// Copyright 2020-2021 Authors of Cilium

package tests

import (
	"context"
	"fmt"

	"github.com/cilium/cilium-cli/connectivity/check"
)

// PodToWorld sends multiple HTTP(S) requests to one.one.one.one
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
	http := check.HTTPEndpoint("one-one-one-one-http", "http://one.one.one.one")
	https := check.HTTPEndpoint("one-one-one-one-https", "https://one.one.one.one")
	httpsindex := check.HTTPEndpoint("one-one-one-one-https-index", "https://one.one.one.one/index.html")

	fp := check.FlowParameters{
		DNSRequired: true,
		RSTAllowed:  true,
	}

	var i int

	for _, client := range t.Context().ClientPods() {
		// With http, over port 80.
		t.NewAction(s, fmt.Sprintf("http-to-one-one-one-one-%d", i), &client, http).Run(func(a *check.Action) {
			a.ExecInPod(ctx, curl(http))
			a.ValidateFlows(ctx, client, a.GetEgressRequirements(fp))
		})

		// With https, over port 443.
		t.NewAction(s, fmt.Sprintf("https-to-one-one-one-one-%d", i), &client, https).Run(func(a *check.Action) {
			a.ExecInPod(ctx, curl(https))
			a.ValidateFlows(ctx, client, a.GetEgressRequirements(fp))
		})

		// With https, over port 443, index.html.
		t.NewAction(s, fmt.Sprintf("https-to-one-one-one-one-index-%d", i), &client, httpsindex).Run(func(a *check.Action) {
			a.ExecInPod(ctx, curl(httpsindex))
			a.ValidateFlows(ctx, client, a.GetEgressRequirements(fp))
		})

		i++
	}
}
