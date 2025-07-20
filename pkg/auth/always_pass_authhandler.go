// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"log/slog"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/auth/certs"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/time"
)

// alwaysPassAuthHandler implements an authHandler by just authenticate every request
// This is only for testing purpose.
type alwaysPassAuthHandler struct {
	logger *slog.Logger
}

func newAlwaysPassAuthHandler(logger *slog.Logger) *alwaysPassAuthHandler {
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

func (r *alwaysPassAuthHandler) authType() policyTypes.AuthType {
	// return a dummy auth type as this auth type is used only for testing
	return policyTypes.AuthType(100)
}

func (r *alwaysPassAuthHandler) subscribeToRotatedIdentities() <-chan certs.CertificateRotationEvent {
	return nil
}

func (r *alwaysPassAuthHandler) certProviderStatus() *models.Status {
	return nil // reporting no status as we have no cert provider
}
