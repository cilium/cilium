// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"github.com/cilium/cilium/pkg/datapath/linux/utime"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/maps/authmap"
	"github.com/cilium/cilium/pkg/policy"
)

type fakeAuthMap struct {
	Entries map[authmap.AuthKey]authmap.AuthInfo
}

func NewFakeAuthMap() *fakeAuthMap {
	return &fakeAuthMap{
		Entries: map[authmap.AuthKey]authmap.AuthInfo{},
	}
}

func (f fakeAuthMap) Lookup(localIdentity identity.NumericIdentity, remoteIdentity identity.NumericIdentity, remoteNodeID uint16, authType policy.AuthType) (*authmap.AuthInfo, error) {
	key := &authmap.AuthKey{
		LocalIdentity:  localIdentity.Uint32(),
		RemoteIdentity: remoteIdentity.Uint32(),
		RemoteNodeID:   remoteNodeID,
		AuthType:       authType.Uint8(),
	}

	info := f.Entries[*key]
	return &info, nil
}

func (f fakeAuthMap) Update(localIdentity identity.NumericIdentity, remoteIdentity identity.NumericIdentity, remoteNodeID uint16, authType policy.AuthType, expiration utime.UTime) error {
	key := &authmap.AuthKey{
		LocalIdentity:  localIdentity.Uint32(),
		RemoteIdentity: remoteIdentity.Uint32(),
		RemoteNodeID:   remoteNodeID,
		AuthType:       authType.Uint8(),
	}
	value := &authmap.AuthInfo{
		Expiration: expiration,
	}

	f.Entries[*key] = *value

	return nil
}

func (f fakeAuthMap) Delete(localIdentity identity.NumericIdentity, remoteIdentity identity.NumericIdentity, remoteNodeID uint16, authType policy.AuthType) error {
	key := &authmap.AuthKey{
		LocalIdentity:  localIdentity.Uint32(),
		RemoteIdentity: remoteIdentity.Uint32(),
		RemoteNodeID:   remoteNodeID,
		AuthType:       authType.Uint8(),
	}
	delete(f.Entries, *key)

	return nil
}

func (f fakeAuthMap) IterateWithCallback(cb authmap.IterateCallback) error {
	for key, info := range f.Entries {
		cb(&key, &info)
	}
	return nil
}
