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
					authType:       policy.AuthTypeNull,
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
}
