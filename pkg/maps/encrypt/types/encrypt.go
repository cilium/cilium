// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package types

type EncryptKey struct {
	Key uint32 `align:"ctx"`
}

type EncryptValue struct {
	EncryptKeyID uint8
}
