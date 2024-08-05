// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
	"github.com/cilium/cilium/pkg/versioncheck"
)

var (
	//go:embed manifests/local-redirect-policy.yaml
	localRedirectPolicyYAML string
)

type localRedirectPolicy struct{}

func (t localRedirectPolicy) build(ct *check.ConnectivityTest, _ map[string]string) {
	lrpFrontendIP := "169.254.169.254"
	lrpFrontendIPSkipRedirect := "169.254.169.255"
	newTest("local-redirect-policy", ct).
		WithCondition(func() bool {
			return versioncheck.MustCompile(">=1.16.0")(ct.CiliumVersion)
		}).
		WithCondition(func() bool {
			// Disable until https://github.com/cilium/cilium-cli/issues/2733 is fixed.
			return false
		}).
		WithCiliumLocalRedirectPolicy(check.CiliumLocalRedirectPolicyParams{
			Policy:                  localRedirectPolicyYAML,
			Name:                    "lrp-address-matcher",
			FrontendIP:              lrpFrontendIP,
			SkipRedirectFromBackend: false,
		}).
		WithCiliumLocalRedirectPolicy(check.CiliumLocalRedirectPolicyParams{
			Policy:                  localRedirectPolicyYAML,
			Name:                    "lrp-address-matcher-skip-redirect-from-backend",
			FrontendIP:              lrpFrontendIPSkipRedirect,
			SkipRedirectFromBackend: true,
		}).
		WithFeatureRequirements(features.RequireEnabled(features.LocalRedirectPolicy)).
		WithFeatureRequirements(features.RequireEnabled(features.KPRSocketLB)).
		WithScenarios(
			tests.LRP(false),
			tests.LRP(true),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Scenario().Name() == "lrp-skip-redirect-from-backend" {
				if a.Source().HasLabel("lrp", "backend") &&
					a.Destination().Address(features.IPFamilyV4) == lrpFrontendIPSkipRedirect {
					return check.ResultCurlTimeout, check.ResultNone
				}
				return check.ResultOK, check.ResultNone
			}
			return check.ResultOK, check.ResultNone
		})
}
