// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"errors"
	"testing"

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

	am, err := newAuthManager(make(<-chan signalAuthKey, 100), authHandlers, nil, nil)
	assert.NoError(t, err)
	assert.NotNil(t, am)

	assert.Len(t, am.authHandlers, 2)
}

func Test_authManager_authenticate(t *testing.T) {
	tests := []struct {
		name              string
		args              authKey
		wantErr           assert.ErrorAssertionFunc
		wantAuthenticated bool
		wantEntries       int
	}{
		{
			name: "missing handler for auth type",
			args: authKey{
				localIdentity:  1,
				remoteIdentity: 2,
				remoteNodeID:   2,
				authType:       0,
			},
			wantErr:     assertErrorString("unknown requested auth type: "),
			wantEntries: 0,
		},
		{
			name: "missing node IP for node ID",
			args: authKey{
				localIdentity:  1,
				remoteIdentity: 2,
				remoteNodeID:   1,
				authType:       1,
			},
			wantErr:     assertErrorString("remote node IP not available for node ID 1"),
			wantEntries: 0,
		},
		{
			name: "successful auth",
			args: authKey{
				localIdentity:  1,
				remoteIdentity: 2,
				remoteNodeID:   2,
				authType:       1,
			},
			wantErr:     assert.NoError,
			wantEntries: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authMap := &fakeAuthMap{
				entries: map[authKey]authInfo{},
			}
			am, err := newAuthManager(
				make(<-chan signalAuthKey, 100),
				[]authHandler{&nullAuthHandler{}},
				authMap,
				newFakeIPCache(map[uint16]string{
					2: "172.18.0.2",
					3: "172.18.0.3",
				}),
			)

			assert.NoError(t, err)

			err = am.authenticate(tt.args)
			tt.wantErr(t, err)

			assert.Len(t, authMap.entries, tt.wantEntries)
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

// Fake AuthMap
type fakeAuthMap struct {
	entries map[authKey]authInfo
}

func (r *fakeAuthMap) Delete(key authKey) error {
	delete(r.entries, key)
	return nil
}

func (r *fakeAuthMap) All() (map[authKey]authInfo, error) {
	return r.entries, nil
}

func (r *fakeAuthMap) Get(key authKey) (authInfo, error) {
	v, ok := r.entries[key]
	if !ok {
		return authInfo{}, errors.New("authinfo not available")
	}

	return v, nil
}

func (r *fakeAuthMap) Update(key authKey, info authInfo) error {
	r.entries[authKey{
		localIdentity:  key.localIdentity,
		remoteIdentity: key.remoteIdentity,
		remoteNodeID:   key.remoteNodeID,
		authType:       key.authType,
	}] = authInfo{expiration: info.expiration}
	return nil
}

func assertErrorString(errString string) assert.ErrorAssertionFunc {
	return func(t assert.TestingT, err error, msgAndArgs ...interface{}) bool {
		return assert.EqualError(t, err, errString, msgAndArgs)
	}
}
