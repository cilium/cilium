// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1_22

import (
	"testing"

	dualstack "github.com/cilium/cilium/test/controlplane/services/dual-stack"
)

func TestDualStack1_22(t *testing.T) {
	dualstack.RunDualStackTestWithVersion(t, "1.22")
}
