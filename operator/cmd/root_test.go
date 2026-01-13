// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/testutils"
)

// TestOperatorHive verifies that the Operator hive can be instantiated with
// default configuration and thus the Operator hive can be inspected with
// the hive commands and documentation can be generated from it.
func TestOperatorHive(t *testing.T) {
	defer testutils.GoleakVerifyNone(t,
		// Ignore all the currently running goroutines spawned
		// by prior tests or by package init() functions (like the
		// client-go logger).
		testutils.GoleakIgnoreCurrent(),
	)

	err := hive.New(Operator()).Populate(hivetest.Logger(t))
	assert.NoError(t, err, "Populate()")
}
