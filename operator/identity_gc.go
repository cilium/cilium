// Copyright 2018-2019 Authors of Cilium
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

package main

import (
	"time"

	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/identity/cache"
	kvstoreallocator "github.com/cilium/cilium/pkg/kvstore/allocator"
)

var (
	// identityGCInterval is the interval in which allocator identities are
	// attempted to be expired from the kvstore
	identityGCInterval time.Duration
)

func startIdentityGC() {
	log.Infof("Starting security identity garbage collector with %s interval...", identityGCInterval)
	backend, err := kvstoreallocator.NewKVStoreBackend(cache.IdentitiesPath, "", nil)
	if err != nil {
		log.WithError(err).Fatal("Unable to initialize kvstore backend for identity allocation")
	}
	a := allocator.NewAllocatorForGC(backend)

	keysToDelete := map[string]uint64{}
	go func() {
		for {
			keysToDelete2, err := a.RunGC(keysToDelete)
			if err != nil {
				log.WithError(err).Warning("Unable to run security identity garbage collector")
			} else {
				keysToDelete = keysToDelete2
			}

			<-time.After(identityGCInterval)
		}
	}()
}
