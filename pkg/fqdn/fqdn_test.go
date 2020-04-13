// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package fqdn

import (
	"testing"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/testutils/allocator"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	kvstore.SetupDummy("etcd")
	identity.InitWellKnownIdentities()
	<-identityAllocator.InitIdentityAllocator(nil, nil)
	ipcache.IdentityAllocator = identityAllocator
	TestingT(t)
}

type FQDNTestSuite struct {
	identityAllocator *cache.CachingIdentityAllocator
	repo              *policy.Repository
}

var (
	identityAllocator = cache.NewCachingIdentityAllocator(&allocator.IdentityAllocatorOwnerMock{})
	repo              = policy.NewPolicyRepository(identityAllocator.GetIdentityCache(), nil)
	_                 = Suite(&FQDNTestSuite{
		identityAllocator: identityAllocator,
		repo:              repo,
	})
)
