// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/goleak"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/metrics"
)

var goleakOptions = []goleak.Option{
	// Ignore all the currently running goroutines spawned
	// by prior tests or by package init() functions (like the
	// client-go logger).
	goleak.IgnoreCurrent(),
	// Ignore goroutines started by the policy trifecta, see [newPolicyTrifecta].
	goleak.IgnoreTopFunction("github.com/cilium/cilium/pkg/identity/cache.(*identityWatcher).watch.func1"),
	goleak.IgnoreTopFunction("github.com/cilium/cilium/pkg/trigger.(*Trigger).waiter"),
}

// TestAgentCell verifies that the Agent hive can be instantiated with
// default configuration and thus the Agent hive can be inspected with
// the hive commands and documentation can be generated from it.
func TestAgentCell(t *testing.T) {
	defer goleak.VerifyNone(t, goleakOptions...)
	defer metrics.ResetMetrics()

	logging.SetLogLevelToDebug()
	err := hive.New(Agent).Populate()
	assert.NoError(t, err, "Populate()")
}
