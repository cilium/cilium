// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package matchpattern

func FuzzMatchpatternValidate(data []byte) int {
	_, _ = Validate(string(data))
	return 1
}

func FuzzMatchpatternValidateWithoutCache(data []byte) int {
	_, _ = ValidateWithoutCache(string(data))
	return 1
}
