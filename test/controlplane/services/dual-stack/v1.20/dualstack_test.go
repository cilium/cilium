// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1_20

import (
	"testing"

	dualstack "github.com/cilium/cilium/test/controlplane/services/dual-stack"
)

func TestDualStack1_20(t *testing.T) {
	dualstack.RunDualStackTestWithVersion(t, "1.20")
}
