// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"fmt"
	"strings"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

// pathMTU implements a Scenario.
type pathMTU struct {
	check.ScenarioBase
	name string
}

func PathMTU() check.Scenario {
	return &pathMTU{
		ScenarioBase: check.NewScenarioBase(),
	}
}

func (s *pathMTU) Name() string {
	return "pmtu"
}

const (
	scapyImport = "from scapy.all import *"
)

func (s *pathMTU) Run(_ context.Context, t *check.Test) {
	t.NewAction(s, "action-1", nil, nil, features.IPFamilyAny).Run(func(a *check.Action) {
		var i int
		ct := t.Context()

		for _, client := range ct.ClientPods() {
			t.ForEachIPFamily(func(ipFam features.IPFamily) {
				switch ipFam {
				case features.IPFamilyV6:

					extEndpoint := t.Context().Params().ExternalPMTUEndpointIPv6
					ep := check.ICMPEndpoint("ext0", extEndpoint)
					t.NewAction(s, fmt.Sprintf("ping-%s-%d", ipFam, i), &client, ep, ipFam).Run(func(a *check.Action) {
						sout, serr, err := client.K8sClient.ExecInPodWithStderr(
							context.Background(),
							client.Pod.Namespace,
							client.Pod.Name,
							client.Labels()["name"],
							[]string{
								"python",
								"-c",
								scapyImport + fmt.Sprintf("; resp = sr1(IPv6(dst='%s', src=get_if_addr6('eth0'))/TCP(dport=1234)/('*' * 1400), timeout=5); print(resp)", extEndpoint),
							},
						)
						if err != nil {
							t.Logf("failed to get expected pmtu response: stdout=%q stderr=%q", sout.String(), serr.String())
							t.Failf("could not get expected pmtu response: %s", err)
						}

						if !strings.Contains(sout.String(), "ICMPv6PacketTooBig") {
							t.Logf("did not get pmtu fragment needed response: stdout=%q stderr=%q", sout.String(), serr.String())
							t.Fail("expected to see pmtu response")
						}
					})
				case features.IPFamilyV4:
					extEndpoint := t.Context().Params().ExternalPMTUEndpointIPv4
					ep := check.ICMPEndpoint("ext0", extEndpoint)
					t.NewAction(s, fmt.Sprintf("ping-%s-%d", ipFam, i), &client, ep, ipFam).Run(func(a *check.Action) {
						sout, serr, err := client.K8sClient.ExecInPodWithStderr(
							context.Background(),
							client.Pod.Namespace,
							client.Pod.Name,
							client.Labels()["name"],
							[]string{
								"python",
								"-c",
								scapyImport + fmt.Sprintf("; resp = sr1(IP(dst='%s', src=get_if_addr('eth0'), flags='DF',frag=0)/TCP(dport=1234)/('*' * 1400), timeout=5); print(resp)", extEndpoint),
							},
						)
						if err != nil {
							t.Logf("failed to get expected pmtu response: stdout=%q stderr=%q", sout.String(), serr.String())
							t.Failf("could not get expected pmtu response: %s", err)
						}

						if !strings.Contains(sout.String(), "fragmentation-needed") {
							t.Logf("did not get pmtu fragment needed response: stdout=%q stderr=%q", sout.String(), serr.String())
							t.Fail("expected to see pmtu response")
						}
					})
				}
			})

			i++
		}
	})

}
