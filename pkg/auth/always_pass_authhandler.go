// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"time"

	"github.com/cilium/cilium/pkg/auth/certs"
	"github.com/cilium/cilium/pkg/policy"
)

// alwaysPassAuthHandler implements an authHandler by just authenticate every request
// This is only for testing purpose.
type alwaysPassAuthHandler struct {
}

func (r *alwaysPassAuthHandler) authenticate(authReq *authRequest) (*authResponse, error) {
	// Authentication trivially done
	log.Debugf("auth: Successfully authenticated request")

	return &authResponse{
		expirationTime: time.Now().Add(1 * time.Minute),
	}, nil
}

func (r *alwaysPassAuthHandler) authType() policy.AuthType {
	// return a dummy auth type as this auth type is used only for testing
	return policy.AuthType(100)
}

func (r *alwaysPassAuthHandler) subscribeToRotatedIdentities() <-chan certs.CertificateRotationEvent {
	return nil
}
