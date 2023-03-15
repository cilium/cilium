// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"github.com/cilium/cilium/pkg/datapath/linux/utime"
	"github.com/cilium/cilium/pkg/maps/authmap"
	"github.com/cilium/cilium/pkg/option"
)

type authMapAuthenticator struct {
	authMap *authmap.Map
}

func newAuthMapAuthenticator() datapathAuthenticator {
	// Make sure authmap is initialized. This will fail in non-privileged unit tests,
	// but as we are not exercising this authenticator in nonprivileged unit tests yet,
	// we'll just ignore the error for now.
	authmap.InitAuthMap(option.Config.AuthMapEntries)

	return &authMapAuthenticator{
		authMap: authmap.AuthMap(),
	}
}

func (r *authMapAuthenticator) markAuthenticated(result *authResult) error {
	return r.authMap.Update(result.localIdentity, result.remoteIdentity,
		result.remoteNodeID, result.authType, utime.TimeToUTime(result.expirationTime))
}
