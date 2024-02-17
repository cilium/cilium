// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package index

func StringMap[V any](m map[string]V) KeySet {
	keys := make([]Key, 0, len(m))
	for k := range m {
		keys = append(keys, String(k))
	}
	return NewKeySet(keys...)
}

func StringStringMap(m map[string]string) KeySet {
	keys := make([]Key, 0, len(m))
	for k, v := range m {
		keys = append(keys, String(k+"="+v))
	}
	return NewKeySet(keys...)
}
