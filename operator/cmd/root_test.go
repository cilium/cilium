// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestOperatorHive verifies that the Operator hive can be instantiated with
// default configuration and thus the Operator hive can be inspected with
// the hive commands and documentation can be generated from it.
func TestOperatorHive(t *testing.T) {
	err := operatorHive.Populate()
	assert.NoError(t, err, "Populate()")
}
