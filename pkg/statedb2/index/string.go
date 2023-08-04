// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package index

func String(s string) []byte {
	return []byte(s)
}

func StringSlice(ss []string) KeySet {
	ks := KeySet{}
	for _, s := range ss {
		ks.Append(String(s))
	}
	return ks
}
