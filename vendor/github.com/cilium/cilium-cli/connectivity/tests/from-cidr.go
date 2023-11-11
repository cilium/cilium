// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"net"
	"strconv"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/utils/features"
)

// FromCIDRToPod generates HTTP request from each node without Cilium to the
// echo pods within the Cilium / K8s cluster.
func FromCIDRToPod() check.Scenario {
	return &fromCIDRToPod{}
}

// fromCIDRToPod implements a Scenario.
type fromCIDRToPod struct{}

func (f *fromCIDRToPod) Name() string {
	return "from-cidr-to-pod"
}

func (f *fromCIDRToPod) Run(ctx context.Context, t *check.Test) {
	clientPod := t.Context().HostNetNSPodsByNode()[t.NodesWithoutCilium()[0]]
	i := 0

	for _, pod := range t.Context().EchoPods() {
		ep := check.HTTPEndpoint(
			"http-endpoint",
			// scheme://[ip:port]/path
			pod.Scheme()+"://"+net.JoinHostPort(pod.Address(features.IPFamilyAny), strconv.FormatUint(uint64(pod.Port()), 10))+pod.Path(),
		)

		t.NewAction(f, "host-netns-to-pod", &clientPod, pod, features.IPFamilyAny).Run(func(a *check.Action) {
			a.ExecInPod(ctx, t.Context().CurlCommand(ep, features.IPFamilyAny))
		})
		i++
	}
}
