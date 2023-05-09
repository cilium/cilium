// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"time"

	"github.com/cilium/cilium/pkg/datapath/linux/utime"
	"github.com/cilium/cilium/pkg/maps/authmap"
)

type authMapAuthenticator struct {
	authMap authmap.Map
}

func newAuthMapAuthenticator(authMap authmap.Map) datapathAuthenticator {
	return &authMapAuthenticator{
		authMap: authMap,
	}
}

func (r *authMapAuthenticator) markAuthenticated(key AuthKey, expiration time.Time) error {
	return r.authMap.Update(authmap.AuthKey(key), utime.TimeToUTime(expiration))
}

func (r *authMapAuthenticator) checkAuthenticated(key AuthKey) bool {
	info, err := r.authMap.Lookup(authmap.AuthKey(key))
	return err == nil && info.Expiration.Time().After(time.Now())
}
