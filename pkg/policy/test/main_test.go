// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package test

import (
	"os"
	"testing"

	"github.com/cilium/cilium/pkg/option"
)

// TestMain sets option.Config once, since the parallel tests' hives read it.
// The identity change grace period is 0 so relabeled endpoints switch right
// away.
func TestMain(m *testing.M) {
	option.Config.IdentityAllocationMode = option.IdentityAllocationModeCRD
	option.Config.IdentityChangeGracePeriod = 0
	os.Exit(m.Run())
}
