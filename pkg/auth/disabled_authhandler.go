// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"time"

	"github.com/cilium/cilium/pkg/auth/certs"
	"github.com/cilium/cilium/pkg/policy"
)

// disabledAuthHandler implements an authHandler for auth type disable by just authenticate every request.
type disabledAuthHandler struct {
}

func (r *disabledAuthHandler) authenticate(authReq *authRequest) (*authResponse, error) {
	// Authentication trivially done
	log.Debugf("auth: Successfully authenticated request")

	return &authResponse{
		expirationTime: time.Now().Add(1 * time.Minute),
	}, nil
}

func (r *disabledAuthHandler) authType() policy.AuthType {
	return policy.AuthTypeDisabled
}

func (r *disabledAuthHandler) subscribeToRotatedIdentities() <-chan certs.CertificateRotationEvent {
	return nil
}
