// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"errors"

	"github.com/cilium/cilium/pkg/auth/certs"
	"github.com/cilium/cilium/pkg/policy"
)

func newAlwaysFailAuthHandler() authHandlerResult {
	return authHandlerResult{
		AuthHandler: &alwaysFailAuthHandler{},
	}
}

// alwaysFailAuthHandler implements an authHandler for auth type always-fail to deny every request.
type alwaysFailAuthHandler struct {
}

func (r *alwaysFailAuthHandler) authenticate(authReq *authRequest) (*authResponse, error) {
	return nil, errors.New("authenticating failed by the always-fail auth handler")
}

func (r *alwaysFailAuthHandler) authType() policy.AuthType {
	return policy.AuthTypeAlwaysFail
}

func (r *alwaysFailAuthHandler) subscribeToRotatedIdentities() <-chan certs.CertificateRotationEvent {
	return nil
}
