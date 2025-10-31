// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package encrypt

type EncryptMap interface {
	Update(key EncryptKey, val EncryptValue) error
	Lookup(key EncryptKey) (EncryptValue, error)
	UnpinIfExists() error
}
