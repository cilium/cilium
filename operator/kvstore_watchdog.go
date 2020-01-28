// Copyright 2020 Authors of Cilium
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
	"context"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/kvstore"
	kvstoreallocator "github.com/cilium/cilium/pkg/kvstore/allocator"
)

// keyPathFromLockPath returns the path of the given key that contains a lease
// prefixed to its path.
func keyPathFromLockPath(k string) string {
	// vendor/go.etcd.io/etcd/clientv3/concurrency/mutex.go:L46
	i := strings.LastIndexByte(k, '/')
	if i >= 0 {
		return k[:i]
	}
	return k
}

// getOldestLeases returns the value that has the smaller revision for each
// 'path'. A 'path' shares the same common prefix for different locks.
func getOldestLeases(m map[string]kvstore.Value) map[string]kvstore.Value {
	oldestLeases := map[string]kvstore.Value{}
	oldestPaths := map[string]kvstore.Value{}
	for k, v := range m {
		commonPath := keyPathFromLockPath(k)
		oldestLease, ok := oldestPaths[commonPath]
		if !ok || v.ModRevision < oldestLease.ModRevision {
			oldestPaths[commonPath] = v
			oldestLeases[k] = v
		}
	}
	return oldestLeases
}

func startKvstoreWatchdog() {
	log.Infof("Starting kvstore watchdog with %s interval...", defaults.LockLeaseTTL)
	backend, err := kvstoreallocator.NewKVStoreBackend(cache.IdentitiesPath, "", nil)
	if err != nil {
		log.WithError(err).Fatal("Unable to initialize kvstore backend for identity garbage collection")
	}
	a := allocator.NewAllocatorForGC(backend)

	keysToDelete := map[string]kvstore.Value{}
	go func() {
		for {
			keysToDelete = getOldestLeases(keysToDelete)
			ctx, cancel := context.WithTimeout(context.Background(), defaults.LockLeaseTTL)
			keysToDelete2, err := a.RunLocksGC(ctx, keysToDelete)
			if err != nil {
				log.WithError(err).Warning("Unable to run security identity garbage collector")
			} else {
				keysToDelete = keysToDelete2
			}
			cancel()

			<-time.After(defaults.LockLeaseTTL)
		}
	}()
}
