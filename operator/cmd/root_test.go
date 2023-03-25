// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/goleak"
)

// TestOperatorHive verifies that the Operator hive can be instantiated with
// default configuration and thus the Operator hive can be inspected with
// the hive commands and documentation can be generated from it.
func TestOperatorHive(t *testing.T) {
	defer goleak.VerifyNone(t,
		// Ignore all the currently running goroutines spawned
		// by prior tests or by package init() functions (like the
		// client-go logger).
		goleak.IgnoreCurrent(),
	)

	err := operatorHive.Populate()
	assert.NoError(t, err, "Populate()")
}
