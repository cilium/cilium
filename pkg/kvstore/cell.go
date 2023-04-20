// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

import (
	"errors"
	"sync"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/promise"
)

// GlobalUserMgmtClientPromiseCell provides a promise returning the global kvstore client to perform users
// management operations, once it has been initialized. Note: client initialization must be handled separately.
var GlobalUserMgmtClientPromiseCell = cell.Module(
	"global-kvstore-users-client",
	"Global KVStore Users Management Client Promise",

	cell.Provide(func(lc hive.Lifecycle) promise.Promise[BackendOperationsUserMgmt] {
		resolver, promise := promise.New[BackendOperationsUserMgmt]()
		stop := make(chan struct{})
		var wg sync.WaitGroup

		lc.Append(hive.Hook{
			OnStart: func(hive.HookContext) error {
				wg.Add(1)
				go func() {
					select {
					case <-defaultClientSet:
						resolver.Resolve(defaultClient)
					case <-stop:
						resolver.Reject(errors.New("stopping"))
					}

					wg.Done()
				}()
				return nil
			},
			OnStop: func(hive.HookContext) error {
				close(stop)
				wg.Wait()
				return nil
			},
		})

		return promise
	}),
)
