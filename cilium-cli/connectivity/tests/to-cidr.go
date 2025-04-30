// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

// PodToCIDR sends an HTTPS request from each client Pod
// to ExternalIP and ExternalOtherIP
func PodToCIDR(opts ...RetryOption) check.Scenario {
	cond := &retryCondition{}
	for _, op := range opts {
		op(cond)
	}
	return &podToCIDR{
		ScenarioBase: check.NewScenarioBase(),
		rc:           cond,
	}
}

// podToCIDR implements a Scenario.
type podToCIDR struct {
	check.ScenarioBase

	rc *retryCondition
}

func (s *podToCIDR) Name() string {
	return "pod-to-cidr"
}

func (s *podToCIDR) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()

	var externalIPs []string
	if ct.Features[features.IPv4].Enabled {
		externalIPs = append(externalIPs, ct.Params().ExternalIPv4, ct.Params().ExternalOtherIPv4)
	}
	if ct.Features[features.IPv6].Enabled && ct.Params().ExternalTargetIPv6Capable {
		externalIPs = append(externalIPs, ct.Params().ExternalIPv6, ct.Params().ExternalOtherIPv6)
	}

	for _, ip := range externalIPs {
		ep := check.HTTPEndpoint(ipToName(ip), ipToURL(ip))

		var i int
		for _, src := range ct.ClientPods() {
			t.NewAction(s, fmt.Sprintf("%s-%d", ep.Name(), i), &src, ep, features.GetIPFamily(ip)).Run(func(a *check.Action) {
				opts := s.rc.CurlOptions(ep, features.GetIPFamily(ip), src, ct.Params())
				a.ExecInPod(ctx, a.CurlCommand(ep, opts...))

				a.ValidateFlows(ctx, src, a.GetEgressRequirements(check.FlowParameters{
					RSTAllowed: true,
				}))
			})
			i++
		}
	}
}

func ipToName(ip string) string {
	ipWithoutSep := strings.ReplaceAll(ip, ".", "")          // IPv4 separator
	ipWithoutSep = strings.ReplaceAll(ipWithoutSep, ":", "") // IPv6 separator
	return fmt.Sprintf("external-%s", ipWithoutSep)
}

func ipToURL(ipString string) string {
	if ip, err := netip.ParseAddr(ipString); err == nil && ip.Is6() {
		ipString = fmt.Sprintf("[%s]", ipString) // Avoid parsing IPv6 last ":" as port
	}
	return "https://" + ipString
}
