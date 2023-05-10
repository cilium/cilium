// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package probes

import (
	"testing"

	"github.com/cilium/cilium/pkg/testutils"
)

func TestAttachCgroup(t *testing.T) {
	testutils.PrivilegedTest(t)

	// Cgroup attachment expected to succeed in all testing environments.
	if err := HaveAttachCgroup(); err != nil {
		t.Fatal(err)
	}
}
