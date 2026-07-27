// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/pkg/maps/encrypt"
)

type EncryptKey = encrypt.EncryptKey
type EncryptValue = encrypt.EncryptValue

type fakeEncryptMap struct {
	Entries map[EncryptKey]EncryptValue
}

func NewFakeEncryptMap() *fakeEncryptMap {
	return &fakeEncryptMap{
		Entries: map[EncryptKey]EncryptValue{},
	}
}

func (f fakeEncryptMap) Lookup(key EncryptKey) (EncryptValue, error) {
	value, exists := f.Entries[key]
	if exists {
		return value, nil
	}
	return value, ebpf.ErrKeyNotExist
}

func (f fakeEncryptMap) Update(key EncryptKey, value EncryptValue) error {
	f.Entries[key] = value
	return nil
}

func (f fakeEncryptMap) UnpinIfExists() error {
	return nil
}
