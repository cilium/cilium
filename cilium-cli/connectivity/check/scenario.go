// SPDX-License-Identifier: Apache-2.0
// Copyright 2020-2021 Authors of Cilium

package check

import "context"

// Scenario is implemented by all test scenarios like pod-to-pod, pod-to-world, etc.
type Scenario interface {
	// Name returns the name of the Scenario.
	Name() string

	// Run is invoked by the testing framework to execute the Scenario.
	Run(ctx context.Context, t *Test)
}
