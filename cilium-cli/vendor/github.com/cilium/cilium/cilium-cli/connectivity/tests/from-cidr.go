// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	check2 "github.com/cilium/cilium/cilium-cli/connectivity/check"
	"net"
	"strconv"

	"github.com/cilium/cilium-cli/utils/features"
)

// FromCIDRToPod generates HTTP request from each node without Cilium to the
// echo pods within the Cilium / K8s cluster.
func FromCIDRToPod() check2.Scenario {
	return &fromCIDRToPod{}
}

// fromCIDRToPod implements a Scenario.
type fromCIDRToPod struct{}

func (f *fromCIDRToPod) Name() string {
	return "from-cidr-to-pod"
}

func (f *fromCIDRToPod) Run(ctx context.Context, t *check2.Test) {
	clientPod := t.Context().HostNetNSPodsByNode()[t.NodesWithoutCilium()[0]]
	i := 0

	for _, pod := range t.Context().EchoPods() {
		t.ForEachIPFamily(func(ipFam features.IPFamily) {
			ep := check2.HTTPEndpoint(
				"http-endpoint",
				// scheme://[ip:port]/path
				pod.Scheme()+"://"+net.JoinHostPort(pod.Address(ipFam), strconv.FormatUint(uint64(pod.Port()), 10))+pod.Path(),
			)

			t.NewAction(f, "host-netns-to-pod", &clientPod, pod, ipFam).Run(func(a *check2.Action) {
				a.ExecInPod(ctx, t.Context().CurlCommand(ep, ipFam))
			})
			i++
		})
	}
}
