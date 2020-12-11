// Copyright 2018-2020 Authors of Cilium
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

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/kvstore"
	kvstoreallocator "github.com/cilium/cilium/pkg/kvstore/allocator"

	"github.com/sirupsen/logrus"
)

func startKvstoreIdentityGC() {
	log.Infof("Starting kvstore identity garbage collector with %s interval...", operatorOption.Config.IdentityGCInterval)
	backend, err := kvstoreallocator.NewKVStoreBackend(cache.IdentitiesPath, "", nil, kvstore.Client())
	if err != nil {
		log.WithError(err).Fatal("Unable to initialize kvstore backend for identity allocation")
	}
	a := allocator.NewAllocatorForGC(backend)

	keysToDelete := map[string]uint64{}
	go func() {
		for {
			keysToDelete2, err := a.RunGC(identityRateLimiter, keysToDelete)
			if err != nil {
				log.WithError(err).Warning("Unable to run security identity garbage collector")
			} else {
				keysToDelete = keysToDelete2
			}
			<-time.After(operatorOption.Config.IdentityGCInterval)
			log.WithFields(logrus.Fields{
				"identities-to-delete": keysToDelete,
			}).Debug("Will delete identities if they are still unused")
		}
	}()
}
