// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package probes

import (
	"testing"

	"github.com/cilium/cilium/pkg/testutils"
)

func TestManagedNeighbors(t *testing.T) {
	testutils.PrivilegedTest(t)
	testutils.SkipOnOldKernel(t, "5.16", "NTF_EXT_MANAGED")

	if err := HaveManagedNeighbors(); err != nil {
		t.Fatal(err)
	}
}
