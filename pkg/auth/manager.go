// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/auth/certs"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/maps/authmap"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/time"
)

// signalAuthKey used in the signalmap. Must reflect struct auth_key in the datapath
type signalAuthKey authmap.AuthKey

// low-cardinality stringer for metrics
func (key signalAuthKey) String() string {
	return policy.AuthType(key.AuthType).String()
}

type AuthManager struct {
	logger                logrus.FieldLogger
	nodeIDHandler         types.NodeIDHandler
	authHandlers          map[policy.AuthType]authHandler
	authmap               authMapCacher
	authSignalBackoffTime time.Duration

	mutex                    lock.Mutex
	pending                  map[authKey]struct{}
	handleAuthenticationFunc func(a *AuthManager, k authKey, reAuth bool)
}

// authHandler is responsible to handle authentication for a specific auth type
type authHandler interface {
	authenticate(*authRequest) (*authResponse, error)
	authType() policy.AuthType
	subscribeToRotatedIdentities() <-chan certs.CertificateRotationEvent
	certProviderStatus() *models.Status
}

type authRequest struct {
	localIdentity  identity.NumericIdentity
	remoteIdentity identity.NumericIdentity
	remoteNodeIP   string
}

type authResponse struct {
	expirationTime time.Time
}

func newAuthManager(logger logrus.FieldLogger, authHandlers []authHandler, authmap authMapCacher, nodeIDHandler types.NodeIDHandler, authSignalBackoffTime time.Duration) (*AuthManager, error) {
	ahs := map[policy.AuthType]authHandler{}
	for _, ah := range authHandlers {
		if ah == nil {
			continue
		}
		if _, ok := ahs[ah.authType()]; ok {
			return nil, fmt.Errorf("multiple handlers for auth type: %s", ah.authType())
		}
		ahs[ah.authType()] = ah
	}

	return &AuthManager{
		logger:                   logger,
		authHandlers:             ahs,
		authmap:                  authmap,
		nodeIDHandler:            nodeIDHandler,
		pending:                  make(map[authKey]struct{}),
		handleAuthenticationFunc: handleAuthentication,
		authSignalBackoffTime:    authSignalBackoffTime,
	}, nil
}

// handleAuthRequest receives auth required signals and spawns a new go routine for each authentication request.
func (a *AuthManager) handleAuthRequest(_ context.Context, key signalAuthKey) error {
	k := authKey{
		localIdentity:  identity.NumericIdentity(key.LocalIdentity),
		remoteIdentity: identity.NumericIdentity(key.RemoteIdentity),
		remoteNodeID:   key.RemoteNodeID,
		authType:       policy.AuthType(key.AuthType),
	}

	if k.localIdentity.IsReservedIdentity() || k.remoteIdentity.IsReservedIdentity() {
		a.logger.
			WithField("key", k).
			Info("Reserved identity, skipping authentication as reserved identities are not compatible with authentication")
		return nil
	}

	a.logger.
		WithField("key", k).
		Debug("Handle authentication request")

	a.handleAuthenticationFunc(a, k, false)

	return nil
}

func (a *AuthManager) handleCertificateRotationEvent(_ context.Context, event certs.CertificateRotationEvent) error {
	a.logger.
		WithField("identity", event.Identity).
		Debug("Handle certificate rotation event")

	all, err := a.authmap.All()
	if err != nil {
		return fmt.Errorf("failed to get all auth map entries: %w", err)
	}

	for k := range all {
		if k.localIdentity == event.Identity || k.remoteIdentity == event.Identity {
			if event.Deleted {
				a.logger.
					WithField("key", k).
					Debug("Certificate delete event: deleting auth map entry")
				if err := a.authmap.Delete(k); err != nil {
					return fmt.Errorf("failed to delete auth map entry: %w", err)
				}
			} else {
				a.handleAuthenticationFunc(a, k, true)
			}
		}
	}

	return nil
}

func handleAuthentication(a *AuthManager, k authKey, reAuth bool) {
	if !a.markPendingAuth(k) {
		a.logger.
			WithField("key", k).
			Debug("Pending authentication, skipping authentication")
		return
	}

	go func(key authKey) {
		defer a.clearPendingAuth(key)

		if !reAuth {
			// Check if the auth is actually required, as we might have
			// updated the authmap since the datapath issued the auth
			// required signal.
			// If the entry was cached more than authSignalBackoffTime
			// it will authenticate again, this is to make sure that
			// we re-authenticate if the authmap was updated by an
			// external source.
			if i, err := a.authmap.GetCacheInfo(key); err == nil && i.expiration.After(time.Now()) && time.Now().Before(i.storedAt.Add(a.authSignalBackoffTime)) {
				a.logger.
					WithField("key", key).
					WithField("storedAt", i.storedAt).
					Debugf("Already authenticated in the past %s, skipping authentication", a.authSignalBackoffTime.String())
				return
			}
		}

		if err := a.authenticate(key); err != nil {
			a.logger.
				WithError(err).
				WithField("key", key).
				Warning("Failed to authenticate request")
		}
	}(k)
}

// markPendingAuth checks if there is a pending authentication for the given key.
// If an auth is already pending returns false, otherwise marks the key as pending
// and returns true.
func (a *AuthManager) markPendingAuth(key authKey) bool {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if _, exists := a.pending[key]; exists {
		// Auth for this key is already pending
		return false
	}
	a.pending[key] = struct{}{}
	return true
}

// clearPendingAuth marks the pending authentication as finished.
func (a *AuthManager) clearPendingAuth(key authKey) {
	a.logger.
		WithField("key", key).
		Debug("Clearing pending authentication")

	a.mutex.Lock()
	defer a.mutex.Unlock()
	delete(a.pending, key)
}

func (a *AuthManager) authenticate(key authKey) error {
	a.logger.
		WithField("key", key).
		Debug("Policy is requiring authentication")

	// Authenticate according to the requested auth type
	h, ok := a.authHandlers[key.authType]
	if !ok {
		return fmt.Errorf("unknown requested auth type: %s", key.authType)
	}

	nodeIP := a.nodeIDHandler.GetNodeIP(key.remoteNodeID)
	if nodeIP == "" {
		return fmt.Errorf("remote node IP not available for node ID %d", key.remoteNodeID)
	}

	authReq := &authRequest{
		localIdentity:  key.localIdentity,
		remoteIdentity: key.remoteIdentity,
		remoteNodeIP:   nodeIP,
	}

	authResp, err := h.authenticate(authReq)
	if err != nil {
		return fmt.Errorf("failed to authenticate with auth type %s: %w", key.authType, err)
	}

	if err = a.updateAuthMap(key, authResp.expirationTime); err != nil {
		return fmt.Errorf("failed to update BPF map in datapath: %w", err)
	}

	a.logger.
		WithField("key", key).
		WithField("remote_node_ip", nodeIP).
		Debug("Successfully authenticated")

	return nil
}

func (a *AuthManager) updateAuthMap(key authKey, expirationTime time.Time) error {
	val := authInfo{
		expiration: expirationTime,
	}

	if err := a.authmap.Update(key, val); err != nil {
		return fmt.Errorf("failed to write auth information to BPF map: %w", err)
	}

	return nil
}

func (a *AuthManager) CertProviderStatus() *models.Status {
	for _, h := range a.authHandlers {
		status := h.certProviderStatus()
		if status != nil {
			// for now we only can have one cert provider
			// once this changes we need to merge the statuses
			return status
		}
	}

	// if none was found auth is disabled
	return &models.Status{
		State: models.StatusStateDisabled,
	}
}
