// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"context"
	"errors"
	"maps"
	"net"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/auth/certs"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/policy"
)

func Test_newAuthManager_clashingAuthHandlers(t *testing.T) {
	authHandlers := []authHandler{
		&alwaysFailAuthHandler{},
		&alwaysFailAuthHandler{},
	}

	am, err := newAuthManager(logrus.New(), authHandlers, nil, nil, time.Second)
	assert.ErrorContains(t, err, "multiple handlers for auth type: test-always-fail")
	assert.Nil(t, am)
}

func Test_newAuthManager(t *testing.T) {
	authHandlers := []authHandler{
		newAlwaysPassAuthHandler(logrus.New()),
		&fakeAuthHandler{},
	}

	am, err := newAuthManager(logrus.New(), authHandlers, nil, nil, time.Second)
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
				localIdentity:  1000,
				remoteIdentity: 2000,
				remoteNodeID:   2,
				authType:       1,
			},
			wantErr:     assertErrorString("unknown requested auth type: spire"),
			wantEntries: 0,
		},
		{
			name: "missing node IP for node ID",
			args: authKey{
				localIdentity:  1000,
				remoteIdentity: 2000,
				remoteNodeID:   1,
				authType:       2,
			},
			wantErr:     assertErrorString("remote node IP not available for node ID 1"),
			wantEntries: 0,
		},
		{
			name: "successful auth",
			args: authKey{
				localIdentity:  1000,
				remoteIdentity: 2000,
				remoteNodeID:   2,
				authType:       100,
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
				logrus.New(),
				[]authHandler{&alwaysFailAuthHandler{}, newAlwaysPassAuthHandler(logrus.New())},
				authMap,
				newFakeNodeIDHandler(map[uint16]string{
					2: "172.18.0.2",
					3: "172.18.0.3",
				}),
				time.Second,
			)

			assert.NoError(t, err)

			err = am.authenticate(tt.args)
			tt.wantErr(t, err)

			assert.Len(t, authMap.entries, tt.wantEntries)
		})
	}
}

func Test_authManager_handleAuthRequest(t *testing.T) {
	authHandlers := []authHandler{newAlwaysPassAuthHandler(logrus.New())}

	am, err := newAuthManager(logrus.New(), authHandlers, nil, nil, time.Second)
	assert.NoError(t, err)
	assert.NotNil(t, am)

	handleAuthCalled := false
	am.handleAuthenticationFunc = func(_ *AuthManager, k authKey, reAuth bool) {
		handleAuthCalled = true
		assert.False(t, reAuth)
		assert.Equal(t, authKey{localIdentity: 1000, remoteIdentity: 2000, remoteNodeID: 0, authType: 100}, k)
	}

	err = am.handleAuthRequest(context.Background(), signalAuthKey{LocalIdentity: 1000, RemoteIdentity: 2000, RemoteNodeID: 0, AuthType: 100, Pad: 0})
	assert.NoError(t, err)
	assert.True(t, handleAuthCalled)
}

func Test_authManager_handleAuthRequest_reservedRemoteIdentity(t *testing.T) {
	authHandlers := []authHandler{newAlwaysPassAuthHandler(logrus.New())}

	am, err := newAuthManager(logrus.New(), authHandlers, nil, nil, time.Second)
	assert.NoError(t, err)
	assert.NotNil(t, am)

	handleAuthCalled := false
	am.handleAuthenticationFunc = func(_ *AuthManager, k authKey, reAuth bool) {
		handleAuthCalled = true
	}

	err = am.handleAuthRequest(context.Background(), signalAuthKey{LocalIdentity: 100, RemoteIdentity: identity.ReservedIdentityWorldIPv6.Uint32(), RemoteNodeID: 0, AuthType: 100, Pad: 0})
	assert.NoError(t, err)
	assert.False(t, handleAuthCalled)
}

func Test_authManager_handleAuthRequest_reservedLocalIdentity(t *testing.T) {
	authHandlers := []authHandler{newAlwaysPassAuthHandler(logrus.New())}

	am, err := newAuthManager(logrus.New(), authHandlers, nil, nil, time.Second)
	assert.NoError(t, err)
	assert.NotNil(t, am)

	handleAuthCalled := false
	am.handleAuthenticationFunc = func(_ *AuthManager, k authKey, reAuth bool) {
		handleAuthCalled = true
	}

	err = am.handleAuthRequest(context.Background(), signalAuthKey{LocalIdentity: identity.ReservedIdentityWorldIPv6.Uint32(), RemoteIdentity: 100, RemoteNodeID: 0, AuthType: 100, Pad: 0})
	assert.NoError(t, err)
	assert.False(t, handleAuthCalled)
}

func Test_authManager_handleCertificateRotationEvent_Error(t *testing.T) {
	authHandlers := []authHandler{newAlwaysPassAuthHandler(logrus.New())}
	aMap := &fakeAuthMap{
		failGet: true,
	}

	am, err := newAuthManager(logrus.New(), authHandlers, aMap, nil, time.Second)
	assert.NoError(t, err)
	assert.NotNil(t, am)

	err = am.handleCertificateRotationEvent(context.Background(), certs.CertificateRotationEvent{Identity: identity.NumericIdentity(10)})
	assert.ErrorContains(t, err, "failed to get all auth map entries: failed to list entries")
}

func Test_authManager_handleCertificateRotationEvent(t *testing.T) {
	authHandlers := []authHandler{newAlwaysPassAuthHandler(logrus.New())}
	aMap := &fakeAuthMap{
		entries: map[authKey]authInfo{
			{localIdentity: 1000, remoteIdentity: 2000, remoteNodeID: 1, authType: 100}: {expiration: time.Now()},
			{localIdentity: 2000, remoteIdentity: 3000, remoteNodeID: 1, authType: 100}: {expiration: time.Now()},
			{localIdentity: 3000, remoteIdentity: 4000, remoteNodeID: 1, authType: 100}: {expiration: time.Now()},
		},
	}

	am, err := newAuthManager(logrus.New(), authHandlers, aMap, nil, time.Second)
	assert.NoError(t, err)
	assert.NotNil(t, am)

	handleAuthCalled := false
	am.handleAuthenticationFunc = func(_ *AuthManager, k authKey, reAuth bool) {
		handleAuthCalled = true
		assert.True(t, reAuth)
		assert.True(t, k.localIdentity == 2000 || k.remoteIdentity == 2000)
	}

	err = am.handleCertificateRotationEvent(context.Background(), certs.CertificateRotationEvent{Identity: identity.NumericIdentity(2000)})
	assert.NoError(t, err)
	assert.True(t, handleAuthCalled)
}

func Test_authManager_handleCertificateDeletionEvent(t *testing.T) {
	authHandlers := []authHandler{newAlwaysPassAuthHandler(logrus.New())}
	aMap := &fakeAuthMap{
		entries: map[authKey]authInfo{
			{localIdentity: 1000, remoteIdentity: 2000, remoteNodeID: 1000, authType: 100}: {expiration: time.Now()},
			{localIdentity: 2000, remoteIdentity: 3000, remoteNodeID: 1000, authType: 100}: {expiration: time.Now()},
			{localIdentity: 3000, remoteIdentity: 4000, remoteNodeID: 1000, authType: 100}: {expiration: time.Now()},
		},
	}

	am, err := newAuthManager(logrus.New(), authHandlers, aMap, nil, time.Second)
	assert.NoError(t, err)
	assert.NotNil(t, am)

	err = am.handleCertificateRotationEvent(context.Background(), certs.CertificateRotationEvent{
		Identity: identity.NumericIdentity(2000),
		Deleted:  true,
	})
	assert.NoError(t, err)
	assert.Len(t, aMap.entries, 1)
}

// Fake NodeIDHandler
type fakeNodeIDHandler struct {
	nodeIdMappings map[uint16]string
}

func (r *fakeNodeIDHandler) DumpNodeIDs() []*models.NodeID {
	return []*models.NodeID{}
}

func (r *fakeNodeIDHandler) RestoreNodeIDs() {
}

func newFakeNodeIDHandler(mappings map[uint16]string) *fakeNodeIDHandler {
	return &fakeNodeIDHandler{
		nodeIdMappings: mappings,
	}
}

func (r *fakeNodeIDHandler) GetNodeIP(id uint16) string {
	return r.nodeIdMappings[id]
}

func (r *fakeNodeIDHandler) GetNodeID(nodeIP net.IP) (uint16, bool) {
	for id, ip := range r.nodeIdMappings {
		if ip == nodeIP.String() {
			return id, true
		}
	}

	return 0, false
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

func (r *fakeAuthHandler) certProviderStatus() *models.Status {
	return nil
}

// Fake AuthMap
type fakeAuthMap struct {
	entries    map[authKey]authInfo
	failDelete bool
	failGet    bool
}

func (r *fakeAuthMap) Delete(key authKey) error {
	if r.failDelete {
		return errors.New("failed to delete entry")
	}

	if _, ok := r.entries[key]; !ok {
		return ebpf.ErrKeyNotExist
	}

	delete(r.entries, key)
	return nil
}

func (r *fakeAuthMap) DeleteIf(predicate func(key authKey, info authInfo) bool) error {
	if r.failDelete {
		return errors.New("failed to delete entry")
	}

	maps.DeleteFunc(r.entries, predicate)

	return nil
}

func (r *fakeAuthMap) All() (map[authKey]authInfo, error) {
	if r.failGet {
		return nil, errors.New("failed to list entries")
	}

	return r.entries, nil
}

func (r *fakeAuthMap) GetCacheInfo(key authKey) (authInfoCache, error) {
	v, err := r.Get(key)

	return authInfoCache{
		authInfo: v,
	}, err
}

func (r *fakeAuthMap) Get(key authKey) (authInfo, error) {
	if r.failGet {
		return authInfo{}, errors.New("failed to get entry")
	}

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

func (r *fakeAuthMap) MaxEntries() uint32 {
	return 1 << 8
}

func assertErrorString(errString string) assert.ErrorAssertionFunc {
	return func(t assert.TestingT, err error, msgAndArgs ...interface{}) bool {
		return assert.EqualError(t, err, errString, msgAndArgs)
	}
}
