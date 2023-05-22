// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
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

func (r *authMapAuthenticator) markAuthenticated(result *authResult) error {
	return r.authMap.Update(result.localIdentity, result.remoteIdentity,
		result.remoteNodeID, result.authType, utime.TimeToUTime(result.expirationTime))
}
