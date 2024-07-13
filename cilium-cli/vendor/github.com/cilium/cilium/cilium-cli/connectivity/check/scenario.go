// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"context"

	"github.com/cilium/cilium-cli/utils/features"
)

// Scenario is implemented by all test scenarios like pod-to-pod, pod-to-world, etc.
type Scenario interface {
	// Name returns the name of the Scenario.
	Name() string

	// Run is invoked by the testing framework to execute the Scenario.
	Run(ctx context.Context, t *Test)
}

// ConditionalScenario is a test scenario which requires certain feature
// requirements to be enabled. If the requirements are not met, the test
// scenario is skipped
type ConditionalScenario interface {
	Scenario
	Requirements() []features.Requirement
}
