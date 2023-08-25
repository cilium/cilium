// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/policy"
)

func Test_authMapCache_restoreCache(t *testing.T) {
	am := authMapCache{
		logger: logrus.New(),
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
		logger: logrus.New(),
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

func Test_authMapCache_Delete(t *testing.T) {
	fakeMap := &fakeAuthMap{
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
	}
	am := authMapCache{
		logger:  logrus.New(),
		authmap: fakeMap,
		cacheEntries: map[authKey]authInfo{
			{
				localIdentity:  1,
				remoteIdentity: 2,
				remoteNodeID:   10,
				authType:       policy.AuthTypeDisabled,
			}: {
				expiration: time.Now().Add(10 * time.Minute),
			},
			{
				localIdentity:  3,
				remoteIdentity: 2,
				remoteNodeID:   10,
				authType:       policy.AuthTypeDisabled,
			}: {
				expiration: time.Now().Add(10 * time.Minute),
			},
			{
				localIdentity:  4,
				remoteIdentity: 2,
				remoteNodeID:   10,
				authType:       policy.AuthTypeDisabled,
			}: {
				expiration: time.Now().Add(10 * time.Minute),
			},
		},
	}

	assert.Len(t, am.cacheEntries, 3)

	err := am.Delete(authKey{
		localIdentity:  1,
		remoteIdentity: 2,
		remoteNodeID:   10,
		authType:       policy.AuthTypeDisabled,
	})
	assert.NoError(t, err)
	assert.Len(t, am.cacheEntries, 2)

	err = am.Delete(authKey{
		localIdentity:  3,
		remoteIdentity: 2,
		remoteNodeID:   10,
		authType:       policy.AuthTypeDisabled,
	})
	assert.NoError(t, err)
	assert.Len(t, am.cacheEntries, 1) // Delete from cache

	fakeMap.failDelete = true
	err = am.Delete(authKey{
		localIdentity:  4,
		remoteIdentity: 2,
		remoteNodeID:   10,
		authType:       policy.AuthTypeDisabled,
	})
	assert.ErrorContains(t, err, "failed to delete auth entry from map: failed to delete entry")
	assert.Len(t, am.cacheEntries, 1) // Technical error -> keep in cache
}

func Test_authMapCache_DeleteIf(t *testing.T) {
	fakeMap := &fakeAuthMap{
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
	}
	am := authMapCache{
		logger:  logrus.New(),
		authmap: fakeMap,
		cacheEntries: map[authKey]authInfo{
			{
				localIdentity:  1,
				remoteIdentity: 2,
				remoteNodeID:   10,
				authType:       policy.AuthTypeDisabled,
			}: {
				expiration: time.Now().Add(10 * time.Minute),
			},
			{
				localIdentity:  3,
				remoteIdentity: 2,
				remoteNodeID:   10,
				authType:       policy.AuthTypeDisabled,
			}: {
				expiration: time.Now().Add(10 * time.Minute),
			},
			{
				localIdentity:  4,
				remoteIdentity: 2,
				remoteNodeID:   10,
				authType:       policy.AuthTypeDisabled,
			}: {
				expiration: time.Now().Add(10 * time.Minute),
			},
		},
	}

	assert.Len(t, am.cacheEntries, 3)

	err := am.DeleteIf(func(key authKey, info authInfo) bool {
		return key.localIdentity == 1 || key.localIdentity == 3
	})
	assert.NoError(t, err)
	assert.Len(t, am.cacheEntries, 1)

	fakeMap.failDelete = true
	err = am.DeleteIf(func(key authKey, info authInfo) bool {
		return key.localIdentity == 4
	})
	assert.ErrorContains(t, err, "failed to delete auth entry from map: failed to delete entry")
	assert.Len(t, am.cacheEntries, 1)
}
