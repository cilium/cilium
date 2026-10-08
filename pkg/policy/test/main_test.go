// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package test

import (
	"os"
	"testing"

	"github.com/cilium/cilium/pkg/option"
)

// TestMain sets the identity allocation mode once before any test runs. The
// script tests run in parallel and their hives read the global option.Config,
// so setting it here rather than in each fixture keeps parallel fixtures from
// racing on the write.
func TestMain(m *testing.M) {
	option.Config.IdentityAllocationMode = option.IdentityAllocationModeCRD
	os.Exit(m.Run())
}
