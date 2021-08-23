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

				a.ValidateFlows(ctx, client, a.GetEgressRequirements(check.FlowParameters{}))
				a.ValidateFlows(ctx, echo, a.GetIngressRequirements(check.FlowParameters{}))
			})

			i++
		}
	}
}
