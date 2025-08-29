// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package labels

import "testing"

func FuzzLabelsParse(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Parse(string(data))
	})
}
