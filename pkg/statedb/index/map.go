// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package index

func StringMap[V any](m map[string]V) KeySet {
	ks := KeySet{}
	for k := range m {
		ks.Append(String(k))
	}
	return ks
}
