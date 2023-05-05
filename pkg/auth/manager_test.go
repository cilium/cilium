// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/auth/certs"
	"github.com/cilium/cilium/pkg/policy"
)

func Test_newAuthManager_clashingAuthHandlers(t *testing.T) {
	authHandlers := []authHandler{
		&nullAuthHandler{},
		&nullAuthHandler{},
	}

	am, err := newAuthManager(nil, authHandlers, nil, nil)
	assert.ErrorContains(t, err, "multiple handlers for auth type: null")
	assert.Nil(t, am)
}

func Test_newAuthManager(t *testing.T) {
	authHandlers := []authHandler{
		&nullAuthHandler{},
		&fakeAuthHandler{},
	}

	am, err := newAuthManager(make(<-chan AuthKey, 100), authHandlers, nil, nil)
	assert.NoError(t, err)
	assert.NotNil(t, am)

	assert.Len(t, am.authHandlers, 2)
}

func Test_authManager_authenticate(t *testing.T) {
	tests := []struct {
		name              string
		args              AuthKey
		wantErr           assert.ErrorAssertionFunc
		wantAuthenticated bool
	}{
		{
			name: "missing handler for auth type",
			args: AuthKey{
				LocalIdentity:  1,
				RemoteIdentity: 2,
				RemoteNodeID:   2,
				AuthType:       0,
			},
			wantErr: assertErrorString("unknown requested auth type: "),
		},
		{
			name: "missing node IP for node ID",
			args: AuthKey{
				LocalIdentity:  1,
				RemoteIdentity: 2,
				RemoteNodeID:   1,
				AuthType:       1,
			},
			wantErr: assertErrorString("remote node IP not available for node ID 1"),
		},
		{
			name: "successful auth",
			args: AuthKey{
				LocalIdentity:  1,
				RemoteIdentity: 2,
				RemoteNodeID:   2,
				AuthType:       1,
			},
			wantErr:           assert.NoError,
			wantAuthenticated: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dpAuth := &fakeDatapathAuthenticator{}
			am, err := newAuthManager(
				make(<-chan AuthKey, 100),
				[]authHandler{&nullAuthHandler{}},
				dpAuth,
				newFakeIPCache(map[uint16]string{
					2: "172.18.0.2",
					3: "172.18.0.3",
				}),
			)
			assert.NoError(t, err)

			err = am.authenticate(tt.args)
			tt.wantErr(t, err)

			assert.Equal(t, tt.wantAuthenticated, dpAuth.authenticated)
		})
	}
}

// Fake IPCache
type fakeIPCache struct {
	nodeIdMappings map[uint16]string
}

func newFakeIPCache(mappings map[uint16]string) *fakeIPCache {
	return &fakeIPCache{
		nodeIdMappings: mappings,
	}
}

func (r *fakeIPCache) GetNodeIP(id uint16) string {
	return r.nodeIdMappings[id]
}

// Fake AuthHandler

type fakeAuthHandler struct {
}

func (r *fakeAuthHandler) authenticate(authReq *authRequest) (*authResponse, error) {

	return &authResponse{}, nil
}

func (r *fakeAuthHandler) authType() policy.AuthType {
	return policy.AuthType(255)
}

func (r *fakeAuthHandler) subscribeToRotatedIdentities() <-chan certs.CertificateRotationEvent {
	return nil
}

// Fake DatapathAuthenticator
type fakeDatapathAuthenticator struct {
	authenticated bool
}

func (r *fakeDatapathAuthenticator) markAuthenticated(key AuthKey, expiration time.Time) error {
	r.authenticated = true
	return nil
}

func (r *fakeDatapathAuthenticator) checkAuthenticated(AuthKey) bool {
	return false
}

func assertErrorString(errString string) assert.ErrorAssertionFunc {
	return func(t assert.TestingT, err error, msgAndArgs ...interface{}) bool {
		return assert.EqualError(t, err, errString, msgAndArgs)
	}
}
