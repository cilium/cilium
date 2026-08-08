// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"fmt"
	"net"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

const HTTPConnectProxyName = "http-connect-proxy"

// PodToPodConnect tunnels an HTTP request to each echo pod through an HTTP
// proxy. The proxy, rather than Cilium Envoy, terminates CONNECT and establishes
// the upstream connection.
func PodToPodConnect() check.Scenario {
	return &podToPodConnect{
		ScenarioBase: check.NewScenarioBase(),
	}
}

type podToPodConnect struct {
	check.ScenarioBase
}

func (s *podToPodConnect) Name() string {
	return "pod-to-pod-connect"
}

func (s *podToPodConnect) Run(ctx context.Context, t *check.Test) {
	var i int
	ct := t.Context()
	proxyService, err := ct.K8sClient().GetService(ctx, ct.Params().TestNamespace, HTTPConnectProxyName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("failed to get HTTP CONNECT proxy service: %s", err)
		return
	}
	proxy := check.Service{Service: proxyService}
	proxyPods, err := ct.K8sClient().ListPods(ctx, ct.Params().TestNamespace, metav1.ListOptions{
		LabelSelector: "kind=" + HTTPConnectProxyName,
	})
	if err != nil {
		t.Fatalf("failed to list HTTP CONNECT proxy pods: %s", err)
		return
	}
	if len(proxyPods.Items) != 1 {
		t.Fatalf("expected one HTTP CONNECT proxy pod, found %d", len(proxyPods.Items))
		return
	}
	proxyPod := check.Pod{Pod: &proxyPods.Items[0]}

	for _, client := range ct.ClientPods() {
		if !client.HasLabel("other", "client") {
			continue
		}
		for _, echo := range ct.EchoPods() {
			t.ForEachIPFamily(func(ipFam features.IPFamily) {
				t.NewAction(s, fmt.Sprintf("curl-%s-%d", ipFam, i), &client, proxy, ipFam).Run(func(a *check.Action) {
					proxyURL := fmt.Sprintf("%s://%s", proxy.Scheme(), net.JoinHostPort(proxy.Address(ipFam), fmt.Sprint(proxy.Port())))
					a.ExecInPod(ctx, a.CurlCommand(echo, "--proxytunnel", "-x", proxyURL))

					a.ValidateFlows(ctx, client, a.GetEgressRequirements(check.FlowParameters{
						AltDstIP: proxyPod.Address(ipFam),
					}))
				})
			})

			i++
		}
	}
}
