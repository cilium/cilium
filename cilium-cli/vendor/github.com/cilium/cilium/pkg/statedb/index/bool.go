// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package index

var (
	trueKey  = []byte{'T'}
	falseKey = []byte{'F'}
)

func Bool(b bool) Key {
	if b {
		return trueKey
	}
	return falseKey
}
