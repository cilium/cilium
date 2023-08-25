// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/pkg/datapath/linux/utime"
	"github.com/cilium/cilium/pkg/maps/authmap"
)

type AuthKey = authmap.AuthKey
type AuthInfo = authmap.AuthInfo

type fakeAuthMap struct {
	Entries map[AuthKey]AuthInfo
}

func NewFakeAuthMap() *fakeAuthMap {
	return &fakeAuthMap{
		Entries: map[AuthKey]AuthInfo{},
	}
}

func (f fakeAuthMap) Lookup(key AuthKey) (AuthInfo, error) {
	info, exists := f.Entries[key]
	if exists {
		return info, nil
	}
	return info, ebpf.ErrKeyNotExist
}

func (f fakeAuthMap) Update(key AuthKey, expiration utime.UTime) error {
	f.Entries[key] = AuthInfo{Expiration: expiration}
	return nil
}

func (f fakeAuthMap) Delete(key AuthKey) error {
	delete(f.Entries, key)
	return nil
}

func (f fakeAuthMap) IterateWithCallback(cb authmap.IterateCallback) error {
	for key, info := range f.Entries {
		cb(&key, &info)
	}
	return nil
}
