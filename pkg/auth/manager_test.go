// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"net"
	"testing"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/monitor"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/policy"

	"github.com/stretchr/testify/assert"
)

func Test_newAuthManager_clashingAuthHandlers(t *testing.T) {
	authHandlers := []authHandler{
		&nullAuthHandler{},
		&nullAuthHandler{},
	}

	am, err := newAuthManager(authHandlers, nil, nil)
	assert.ErrorContains(t, err, "multiple handlers for auth type: null")
	assert.Nil(t, am)
}

func Test_newAuthManager(t *testing.T) {
	authHandlers := []authHandler{
		&nullAuthHandler{},
		&fakeAuthHandler{},
	}

	am, err := newAuthManager(authHandlers, nil, nil)
	assert.NoError(t, err)
	assert.NotNil(t, am)

	assert.Len(t, am.authHandlers, 2)
}

func Test_authManager_authRequired(t *testing.T) {
	type args struct {
		dn *monitor.DropNotify
		ci *monitor.ConnectionInfo
	}
	tests := []struct {
		name              string
		args              args
		wantErr           assert.ErrorAssertionFunc
		wantAuthenticated bool
	}{
		{
			name: "missing handler for auth type",
			args: args{
				dn: testDropNotify(0),
				ci: testConnInfo("10.244.1.1", "10.244.2.1"),
			},
			wantErr: assertErrorString("unknown requested auth type: none"),
		},
		{
			name: "missing node IP for source IP",
			args: args{
				dn: testDropNotify(1),
				ci: testConnInfo("10.244.1.2", "10.244.2.1"),
			},
			wantErr: assertErrorString("failed to gather auth request information: failed to get host IP of connection source IP 10.244.1.2"),
		},
		{
			name: "missing node IP for destination IP",
			args: args{
				dn: testDropNotify(1),
				ci: testConnInfo("10.244.1.1", "10.244.2.2"),
			},
			wantErr: assertErrorString("failed to gather auth request information: failed to get host IP of connection destination IP 10.244.2.2"),
		},
		{
			name: "successful auth",
			args: args{
				dn: testDropNotify(1),
				ci: testConnInfo("10.244.1.1", "10.244.2.1"),
			},
			wantErr:           assert.NoError,
			wantAuthenticated: true,
		},
		{
			name: "successful auth with lookup of cilium host IP v4 with /32 when getting host IP",
			args: args{
				dn: testDropNotify(1),
				ci: testConnInfo("10.244.1.170", "10.244.2.1"),
			},
			wantErr:           assert.NoError,
			wantAuthenticated: true,
		},
		{
			name: "successful auth with lookup of cilium host IP v6 with /128 when getting host IP",
			args: args{
				dn: testDropNotify(1),
				ci: testConnInfo("ff00::101", "10.244.2.1"),
			},
			wantErr:           assert.NoError,
			wantAuthenticated: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dpAuth := &fakeDatapathAuthenticator{}
			am, err := newAuthManager(
				[]authHandler{&nullAuthHandler{}},
				dpAuth,
				newFakeIPCache(map[string]string{
					"10.244.1.1":      "172.18.0.2",
					"10.244.2.1":      "172.18.0.3",
					"10.244.1.170/32": "172.18.0.3",
					"ff00::101/128":   "172.18.0.3",
				}),
			)
			assert.NoError(t, err)

			err = am.authRequired(tt.args.dn, tt.args.ci)
			tt.wantErr(t, err)

			assert.Equal(t, tt.wantAuthenticated, dpAuth.authenticated)
		})
	}
}

// Fake IPCache
type fakeIPCache struct {
	ipHostMappings map[string]net.IP
}

func newFakeIPCache(mappings map[string]string) *fakeIPCache {
	m := map[string]net.IP{}
	for ip, hostIP := range mappings {
		m[ip] = net.ParseIP(hostIP)
	}

	return &fakeIPCache{
		ipHostMappings: m,
	}
}

func (r *fakeIPCache) GetHostIP(ip string) net.IP {
	return r.ipHostMappings[ip]
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

// Fake DatapathAuthenticator
type fakeDatapathAuthenticator struct {
	authenticated bool
}

func (r *fakeDatapathAuthenticator) markAuthenticated(dn *monitor.DropNotify, ci *monitor.ConnectionInfo, resp *authResponse) error {
	r.authenticated = true
	return nil
}
func testConnInfo(srcIP string, dstIP string) *monitor.ConnectionInfo {
	return &monitor.ConnectionInfo{
		SrcIP: net.ParseIP(srcIP),
		DstIP: net.ParseIP(dstIP),
	}
}

func testDropNotify(authType int8) *monitor.DropNotify {
	return &monitor.DropNotify{
		Type:     monitorAPI.MessageTypeDrop,
		SubType:  uint8(flow.DropReason_AUTH_REQUIRED),
		Source:   1,
		SrcLabel: 1,
		DstLabel: 2,
		DstID:    2,
		ExtError: authType, // Auth Type
	}
}

func assertErrorString(errString string) assert.ErrorAssertionFunc {
	return func(t assert.TestingT, err error, msgAndArgs ...interface{}) bool {
		return assert.EqualError(t, err, errString, msgAndArgs)
	}
}
