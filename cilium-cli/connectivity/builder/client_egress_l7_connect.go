// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"context"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type clientEgressL7Connect struct{}

func (t clientEgressL7Connect) build(ct *check.ConnectivityTest, templates map[string]string) {
	// The upstream HTTP proxy terminates CONNECT. Cilium enforces policy on the
	// handshake, then passes the upgraded connection through as raw TCP.
	newTest("client-egress-l7-http-connect", ct).
		WithCiliumVersion(">=1.21.0").
		WithFeatureRequirements(features.RequireEnabled(features.L7Proxy)).
		WithResources(templates["clientEgressL7HTTPConnectPolicyYAML"]).
		WithSetupFunc(func(ctx context.Context, _ *check.Test, ct *check.ConnectivityTest) error {
			if err := check.WaitForDeployment(ctx, ct, ct.K8sClient(), ct.Params().TestNamespace, tests.HTTPConnectProxyName); err != nil {
				return err
			}

			service, err := check.WaitForServiceRetrieval(ctx, ct, ct.K8sClient(), ct.Params().TestNamespace, tests.HTTPConnectProxyName)
			if err != nil {
				return err
			}

			clientNodes := make(map[string]struct{})
			for _, client := range ct.ClientPods() {
				clientNodes[client.NodeName()] = struct{}{}
			}

			for _, agent := range ct.CiliumPods() {
				if _, ok := clientNodes[agent.NodeName()]; !ok {
					continue
				}
				if err := check.WaitForServiceEndpoints(ctx, ct, agent, service, 1, ct.Features.IPFamilies()); err != nil {
					return err
				}
			}

			return nil
		}).
		WithScenarios(tests.PodToPodConnect(
			tests.WithRetryCondition(tests.WithRetryAll()),
		)).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Source().HasLabel("other", "client") &&
				a.Destination().HasLabel("kind", tests.HTTPConnectProxyName) &&
				a.Destination().Port() == 8080 {
				egress = check.ResultOK
				egress.HTTP = check.HTTP{
					Method: "CONNECT",
				}
				return egress, check.ResultNone
			}
			return check.ResultDefaultDenyEgressDrop, check.ResultNone
		})
}
