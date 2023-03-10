// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"time"

	"github.com/cilium/cilium/pkg/auth/certs"
	"github.com/cilium/cilium/pkg/policy"
)

// nullAuthHandler implements an authHandler for auth type null by just authenticate every request.
type nullAuthHandler struct {
}

func (r *nullAuthHandler) authenticate(authReq *authRequest) (*authResponse, error) {
	// Authentication trivially done
	log.Debugf("auth: Successfully authenticated request")

	return &authResponse{
		expirationTime: time.Now().Add(1 * time.Minute),
	}, nil
}

func (r *nullAuthHandler) authType() policy.AuthType {
	return policy.AuthTypeNull
}

func (r *nullAuthHandler) subscribeToRotatedIdentities() <-chan certs.CertificateRotationEvent {
	return nil
}
