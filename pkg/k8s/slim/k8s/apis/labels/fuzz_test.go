// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package labels

func FuzzLabelsParse(data []byte) int {
	_, _ = Parse(string(data))
	return 1
}
