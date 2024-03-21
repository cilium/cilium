// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hybrid

import (
	"context"
	"strconv"

	"github.com/cilium/cilium/pkg/allocator"
	idcache "github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/identity/key"
	"github.com/cilium/cilium/pkg/idpool"
	capi_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/stream"
)

type observer struct {
	// Identity changes are observable.
	stream.Observable[idcache.IdentityChange]

	stopChan chan struct{}
	mu       lock.RWMutex

	cache allocator.IDMap

	changeSrc         stream.Observable[allocator.AllocatorChange]
	emitChange        func(allocator.AllocatorChange)
	completeChangeSrc func(error)
}

func NewIDObserver(ctx context.Context, stopChan chan struct{}, cids resource.Resource[*capi_v2.CiliumIdentity]) *observer {
	o := &observer{
		stopChan: stopChan,
		cache:    make(allocator.IDMap),
	}
	o.changeSrc, o.emitChange, o.completeChangeSrc = stream.Multicast[allocator.AllocatorChange]()

	cidStore, err := cids.Store(ctx)
	if err != nil {
		log.Fatalf("CID store not initialized: %v", err)
		return nil
	}

	for _, cid := range cidStore.List() {
		cidNum, err := strconv.Atoi(cid.Name)
		if err != nil {
			log.Warnf("identity observer sync: %v", err)
			continue
		}

		o.cache[idpool.ID(cidNum)] = key.KeyFunc(cid.SecurityLabels)
	}

	return o
}

func (o *observer) getEvent(cid *capi_v2.CiliumIdentity, kind allocator.AllocatorChangeKind) {
	cidNum, err := strconv.Atoi(cid.Name)
	if err != nil {
		log.Warnf("identity observer upsert event: %v", err)
		return
	}

	id := idpool.ID(cidNum)
	k := key.KeyFunc(cid.SecurityLabels)
	o.emitChange(allocator.AllocatorChange{Kind: kind, ID: id, Key: k})
}

// Observe the allocator changes. Conforms to stream.Observable.
// Replays the current state of the cache when subscribing.
func (o *observer) Observe(ctx context.Context, next func(allocator.AllocatorChange), complete func(error)) {
	// This short-lived go routine serves the purpose of replaying the current state of the cache before starting
	// to observe the actual source changeSrc. ChangeSrc is backed by a stream.FuncObservable, that will start its own
	// go routine. Therefore, the current go routine will stop and free the lock on the mutex after the registration.
	go func() {
		// Wait until initial listing has completed before
		// replaying the state.
		select {
		case <-o.stopChan:
		case <-ctx.Done():
			complete(ctx.Err())
			return
		}

		o.mu.RLock()
		defer o.mu.RUnlock()

		for id, key := range o.cache {
			next(allocator.AllocatorChange{Kind: allocator.AllocatorChangeUpsert, ID: id, Key: key})
		}

		// Emit a sync event to inform the subscriber that it has received a consistent
		// initial state.
		next(allocator.AllocatorChange{Kind: allocator.AllocatorChangeSync})

		// And subscribe to new events. Since we held the read-lock there won't be any
		// missed or duplicate events.
		o.changeSrc.Observe(ctx, next, complete)
	}()
}
