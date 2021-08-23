// SPDX-License-Identifier: Apache-2.0
// Copyright 2020-2021 Authors of Cilium

package tests

import (
	"context"
	"fmt"

	"github.com/cilium/cilium-cli/connectivity/check"
)

// PodToWorld sends multiple HTTP(S) requests to cilium.io
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
	chttp := check.HTTPEndpoint("cilium-io-http", "http://cilium.io")
	chttps := check.HTTPEndpoint("cilium-io-https", "https://cilium.io")
	jhttp := check.HTTPEndpoint("jenkins-cilium-io-http", "http://jenkins.cilium.io")

	fp := check.FlowParameters{
		DNSRequired: true,
		RSTAllowed:  true,
	}

	var i int

	for _, client := range t.Context().ClientPods() {
		// With https, over port 443.
		t.NewAction(s, fmt.Sprintf("https-to-cilium-io-%d", i), &client, chttps).Run(func(a *check.Action) {
			a.ExecInPod(ctx, curl(chttps))
			a.ValidateFlows(ctx, client, a.GetEgressRequirements(fp))
		})

		// With http, over port 80.
		t.NewAction(s, fmt.Sprintf("http-to-cilium-io-%d", i), &client, chttp).Run(func(a *check.Action) {
			a.ExecInPod(ctx, curl(chttp))
			a.ValidateFlows(ctx, client, a.GetEgressRequirements(fp))
		})

		// With http to jenkins.cilium.io.
		t.NewAction(s, fmt.Sprintf("http-to-jenkins-cilium-%d", i), &client, jhttp).Run(func(a *check.Action) {
			a.ExecInPod(ctx, curl(jhttp))
			a.ValidateFlows(ctx, client, a.GetEgressRequirements(fp))
		})

		i++
	}
}
