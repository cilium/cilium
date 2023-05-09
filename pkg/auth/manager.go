// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/auth/certs"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/maps/authmap"
	"github.com/cilium/cilium/pkg/policy"
)

// AuthKey used in the signalmap. Must reflect struct auth_key in the datapath
type AuthKey authmap.AuthKey

// low-cardinality stringer for metrics
func (key AuthKey) String() string {
	return policy.AuthType(key.AuthType).String()
}

type authManager struct {
	signalChannel         <-chan AuthKey
	ipCache               ipCache
	authHandlers          map[policy.AuthType]authHandler
	datapathAuthenticator datapathAuthenticator

	mutex   lock.Mutex
	pending map[AuthKey]struct{}
}

// ipCache is the set of interactions the auth manager performs with the IPCache
type ipCache interface {
	GetNodeIP(uint16) string
}

// authHandler is responsible to handle authentication for a specific auth type
type authHandler interface {
	authenticate(*authRequest) (*authResponse, error)
	authType() policy.AuthType
	subscribeToRotatedIdentities() <-chan certs.CertificateRotationEvent
}

type authRequest struct {
	localIdentity  identity.NumericIdentity
	remoteIdentity identity.NumericIdentity
	remoteNodeIP   string
}

type authResponse struct {
	expirationTime time.Time
}

// datapathAuthenticator is responsible to write auth information back to a BPF map
// Using AuthKey as an argument as the key originates from the datapath,
// so we do not need to pack/unpack it here.
type datapathAuthenticator interface {
	markAuthenticated(AuthKey, time.Time) error
	checkAuthenticated(AuthKey) bool
}

func newAuthManager(signalChannel <-chan AuthKey, authHandlers []authHandler, dpAuthenticator datapathAuthenticator, ipCache ipCache) (*authManager, error) {
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

	return &authManager{
		signalChannel:         signalChannel,
		authHandlers:          ahs,
		datapathAuthenticator: dpAuthenticator,
		ipCache:               ipCache,
		pending:               make(map[AuthKey]struct{}),
	}, nil
}

// start receives auth required signals from the signal channel and spawns
// a new go routine for each authentication request
func (a *authManager) start() {
	go func() {
		for key := range a.signalChannel {
			if a.markPendingAuth(key) {
				go func(key AuthKey) {
					defer a.clearPendingAuth(key)

					// Check if the auth is actually required, as we might have
					// updated the authmap since the datapath issued the auth
					// required signal.
					if a.datapathAuthenticator.checkAuthenticated(key) {
						log.Debugf("auth: Already authenticated, skipped authentication for key %v", key)
						return
					}

					if err := a.authenticate(key); err != nil {
						log.WithError(err).Warningf("auth: Failed to authenticate request for key %v", key)
					}
				}(key)
			}
		}
	}()
}

// markPendingAuth checks if there is a pending authentication for the given key.
// If an auth is already pending returns false, otherwise marks the key as pending
// and returns true.
func (a *authManager) markPendingAuth(key AuthKey) bool {
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
func (a *authManager) clearPendingAuth(key AuthKey) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	delete(a.pending, key)
}

func (a *authManager) authenticate(key AuthKey) error {
	authType := policy.AuthType(key.AuthType)

	log.Debugf("auth: policy is requiring authentication type %s between local and remote identities %d<->%d",
		authType, key.LocalIdentity, key.RemoteIdentity)

	// Authenticate according to the requested auth type
	h, ok := a.authHandlers[authType]
	if !ok {
		return fmt.Errorf("unknown requested auth type: %s", authType)
	}

	nodeIP := a.ipCache.GetNodeIP(key.RemoteNodeID)
	if nodeIP == "" {
		return fmt.Errorf("remote node IP not available for node ID %d", key.RemoteNodeID)
	}

	authReq := &authRequest{
		localIdentity:  identity.NumericIdentity(key.LocalIdentity),
		remoteIdentity: identity.NumericIdentity(key.RemoteIdentity),
		remoteNodeIP:   nodeIP,
	}

	authResp, err := h.authenticate(authReq)
	if err != nil {
		return fmt.Errorf("failed to authenticate with auth type %s: %w", authType, err)
	}

	err = a.datapathAuthenticator.markAuthenticated(key, authResp.expirationTime)
	if err != nil {
		return fmt.Errorf("failed to write auth information to BPF map: %w", err)
	}

	log.Debugf("auth: Successfully authenticated for type %s identity %d<->%d, remote host %s",
		authType, key.LocalIdentity, key.RemoteIdentity, nodeIP)

	return nil
}
