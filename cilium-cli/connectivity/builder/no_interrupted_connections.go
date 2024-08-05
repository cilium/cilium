// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"context"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

type noInterruptedConnections struct{}

func (t noInterruptedConnections) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("no-interrupted-connections", ct).
		WithCondition(func() bool { return ct.Params().IncludeConnDisruptTest }).
		WithScenarios(tests.NoInterruptedConnections()).
		WithFinalizer(func(ctx context.Context) error {
			// Delete the test-conn-disrupt pods immediately after the test run
			// has finished to reduce CPU consumption (the pods generate a lot
			// of traffic, and in most CI jobs Cilium runs with monitor
			// aggregation disabled).
			if !ct.Params().ConnDisruptTestSetup {
				for _, client := range ct.Clients() {
					if err := ct.DeleteConnDisruptTestDeployment(ctx, client); err != nil {
						return err
					}
				}
			}
			return nil
		})
}
