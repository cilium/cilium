// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hooks

import (
	"context"
	"fmt"

	"github.com/cilium/cilium-cli/cli"
	"github.com/cilium/cilium-cli/connectivity/check"
)

const (
	testNoPolicies = "no-policies"
)

type ExtraTestsHooks struct {
	cli.NopHooks
}

func (eh *ExtraTestsHooks) AddConnectivityTests(ct *check.ConnectivityTest) error {
	test, err := ct.GetTest(testNoPolicies)
	if err != nil {
		return fmt.Errorf("failed to get test %s: %w", testNoPolicies, err)
	}
	test.WithScenarios(ExtendedTestScenario())
	return nil
}

func ExtendedTestScenario() check.Scenario {
	return &extendedTestScenario{}
}

type extendedTestScenario struct{}

func (e *extendedTestScenario) Name() string {
	return "extended-test-scenario"
}

func (e *extendedTestScenario) Run(ctx context.Context, t *check.Test) {
	t.Log("Hello, World!")
}
