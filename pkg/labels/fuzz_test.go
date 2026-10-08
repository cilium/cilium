// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package labels

import "testing"

func FuzzNewLabels(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		label := NewLabel("test", "label", "1")
		_ = label.UnmarshalJSON(data)
	})
}
