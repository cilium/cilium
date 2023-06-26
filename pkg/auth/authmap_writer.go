// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/datapath/linux/utime"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/maps/authmap"
	"github.com/cilium/cilium/pkg/policy"
)

type authMapWriter struct {
	logger  logrus.FieldLogger
	authMap authmap.Map
}

func newAuthMapWriter(logger logrus.FieldLogger, authMap authmap.Map) *authMapWriter {
	return &authMapWriter{
		logger:  logger,
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

func (r *authMapWriter) DeleteIf(predicate func(key authKey, info authInfo) bool) error {
	all, err := r.All()
	if err != nil {
		return fmt.Errorf("failed to get all entries: %w", err)
	}
	for k, v := range all {
		if predicate(k, v) {
			if err := r.Delete(k); err != nil {
				if errors.Is(err, ebpf.ErrKeyNotExist) {
					r.logger.
						WithField("key", k).
						Debug("Failed to delete already deleted auth entry")
					continue
				}
				return fmt.Errorf("failed to delete auth entry from map: %w", err)
			}
		}
	}

	return nil
}

func (r *authMapWriter) MaxEntries() uint32 {
	return r.authMap.MaxEntries()
}
