// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/metrics"
)

// TestAgentCell verifies that the Agent hive can be instantiated with
// default configuration and thus the Agent hive can be inspected with
// the hive commands and documentation can be generated from it.
func TestAgentCell(t *testing.T) {
	defer metrics.ResetMetrics()

	err := hive.New(Agent).Populate()
	assert.NoError(t, err, "Populate()")

}
