// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package index

import "fmt"

func String(s string) []byte {
	return []byte(s)
}

func Stringer(s fmt.Stringer) []byte {
	return []byte(s.String())
}

func StringSlice(ss []string) KeySet {
	ks := KeySet{}
	for _, s := range ss {
		ks.Append(String(s))
	}
	return ks
}

func StringerSlice[T fmt.Stringer](ss []T) KeySet {
	ks := KeySet{}
	for _, s := range ss {
		ks.Append(Stringer(s))
	}
	return ks
}
