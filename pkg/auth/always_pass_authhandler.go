// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/auth/certs"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/time"
)

// alwaysPassAuthHandler implements an authHandler by just authenticate every request
// This is only for testing purpose.
type alwaysPassAuthHandler struct {
	logger logrus.FieldLogger
}

func newAlwaysPassAuthHandler(logger logrus.FieldLogger) *alwaysPassAuthHandler {
	return &alwaysPassAuthHandler{
		logger: logger,
	}
}

func (r *alwaysPassAuthHandler) authenticate(authReq *authRequest) (*authResponse, error) {
	// Authentication trivially done
	r.logger.Debug("Successfully authenticated request")

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

func (r *alwaysPassAuthHandler) certProviderStatus() *models.Status {
	return nil // reporting no status as we have no cert provider
}
