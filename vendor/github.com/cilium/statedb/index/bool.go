// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package index

import "strconv"

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

func BoolString(s string) (Key, error) {
	b, err := strconv.ParseBool(s)
	return Bool(b), err
}
