// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package matchpattern

import "testing"

func FuzzMatchpatternValidate(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Validate(string(data))
	})
}

func FuzzMatchpatternValidateWithoutCache(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ValidateWithoutCache(string(data))
	})
}
