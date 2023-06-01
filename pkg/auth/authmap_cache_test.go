// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/policy"
)

func Test_authMapCache_restoreCache(t *testing.T) {
	am := authMapCache{
		authmap: &fakeAuthMap{
			entries: map[authKey]authInfo{
				{
					localIdentity:  1,
					remoteIdentity: 2,
					remoteNodeID:   10,
					authType:       policy.AuthTypeDisabled,
				}: {
					expiration: time.Now().Add(10 * time.Minute),
				},
			},
		},
		cacheEntries: map[authKey]authInfo{},
	}

	err := am.restoreCache()
	assert.NoError(t, err)

	assert.Len(t, am.cacheEntries, 1)

	val, err := am.Get(authKey{
		localIdentity:  1,
		remoteIdentity: 2,
		remoteNodeID:   10,
		authType:       policy.AuthTypeDisabled,
	})
	assert.NoError(t, err)
	assert.NotNil(t, val)
}

func Test_authMapCache_allReturnsCopy(t *testing.T) {
	am := authMapCache{
		authmap: &fakeAuthMap{
			entries: map[authKey]authInfo{},
		},
		cacheEntries: map[authKey]authInfo{
			{
				localIdentity:  1,
				remoteIdentity: 2,
				remoteNodeID:   10,
				authType:       policy.AuthTypeDisabled,
			}: {
				expiration: time.Now().Add(10 * time.Minute),
			},
		},
	}

	all, err := am.All()
	assert.NoError(t, err)
	assert.Len(t, all, 1)

	all[authKey{
		localIdentity:  10,
		remoteIdentity: 20,
		remoteNodeID:   100,
		authType:       policy.AuthTypeDisabled,
	}] = authInfo{
		expiration: time.Now().Add(10 * time.Minute),
	}
	assert.Len(t, all, 2)
	assert.Len(t, am.cacheEntries, 1)
}
