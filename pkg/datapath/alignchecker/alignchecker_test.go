// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package alignchecker

import (
	"testing"

	"github.com/cilium/cilium/pkg/testutils"
)

func TestCheckStructAlignments(t *testing.T) {
	f := "../../../bpf/bpf_alignchecker.o"
	testutils.SkipIfFileMissing(t, f)
	if err := CheckStructAlignments(f); err != nil {
		t.Fatal(err)
	}
}
