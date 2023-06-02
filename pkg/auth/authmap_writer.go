// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"fmt"

	"github.com/cilium/cilium/pkg/datapath/linux/utime"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/maps/authmap"
	"github.com/cilium/cilium/pkg/policy"
)

type authMapWriter struct {
	authMap authmap.Map
}

func newAuthMapWriter(authMap authmap.Map) *authMapWriter {
	return &authMapWriter{
		authMap: authMap,
	}
}

func (r *authMapWriter) All() (map[authKey]authInfo, error) {
	result := map[authKey]authInfo{}

	if err := r.authMap.IterateWithCallback(func(key *authmap.AuthKey, info *authmap.AuthInfo) {
		result[authKey{
			localIdentity:  identity.NumericIdentity(key.LocalIdentity),
			remoteIdentity: identity.NumericIdentity(key.RemoteIdentity),
			remoteNodeID:   key.RemoteNodeID,
			authType:       policy.AuthType(key.AuthType),
		}] = authInfo{
			expiration: info.Expiration.Time(),
		}
	}); err != nil {
		return nil, fmt.Errorf("failed to get all entries from auth map: %w", err)
	}

	return result, nil
}

func (r *authMapWriter) Get(key authKey) (authInfo, error) {
	lookup, err := r.authMap.Lookup(authmap.AuthKey{
		LocalIdentity:  key.localIdentity.Uint32(),
		RemoteIdentity: key.remoteIdentity.Uint32(),
		RemoteNodeID:   key.remoteNodeID,
		AuthType:       key.authType.Uint8(),
	})
	if err != nil {
		return authInfo{}, fmt.Errorf("failed to lookup authkey: %w", err)
	}
	return authInfo{
		expiration: lookup.Expiration.Time(),
	}, nil
}

func (r *authMapWriter) Update(key authKey, info authInfo) error {
	return r.authMap.Update(authmap.AuthKey{
		LocalIdentity:  key.localIdentity.Uint32(),
		RemoteIdentity: key.remoteIdentity.Uint32(),
		RemoteNodeID:   key.remoteNodeID,
		AuthType:       key.authType.Uint8(),
	}, utime.TimeToUTime(info.expiration))
}

func (r *authMapWriter) Delete(key authKey) error {
	if err := r.authMap.Delete(authmap.AuthKey{
		LocalIdentity:  key.localIdentity.Uint32(),
		RemoteIdentity: key.remoteIdentity.Uint32(),
		RemoteNodeID:   key.remoteNodeID,
		AuthType:       key.authType.Uint8(),
	}); err != nil {
		return fmt.Errorf("failed to delete entry from auth map: %w", err)
	}

	return nil
}
