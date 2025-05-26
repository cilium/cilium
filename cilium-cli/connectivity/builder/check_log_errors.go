// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

type checkLogErrors struct{}

func (t checkLogErrors) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("check-log-errors", ct).
		WithSysdumpPolicy(check.SysdumpPolicyOnce).
		WithScenarios(tests.NoErrorsInLogs(ct.CiliumVersion, ct.Params().LogCheckLevels, ct.Params().ExternalTarget,
			ct.Params().ExternalOtherTarget))
}
