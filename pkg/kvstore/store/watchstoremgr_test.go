// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/kvstore"
)

func TestWatchStoreManager(t *testing.T) {
	runnable := func(mgr func() WatchStoreManager) func(t *testing.T) {
		return func(t *testing.T) {
			ch := make(chan *KVPair, 3)
			run := func(ctx context.Context, str string) {
				ch <- NewKVPair(str, "")
				<-ctx.Done()
			}

			mgr := mgr()
			mgr.Register("bar", func(ctx context.Context) { run(ctx, "bar") })
			mgr.Register("bax", func(ctx context.Context) { run(ctx, "baz") })
			mgr.Register("qux", func(ctx context.Context) { run(ctx, "qux") })

			ctx, cancel := context.WithCancel(context.Background())
			completed := make(chan struct{})
			go func() {
				mgr.Run(ctx)
				close(completed)
			}()

			defer func() {
				cancel()

				select {
				case <-completed:
				case <-time.After(100 * time.Millisecond):
					require.Fail(t, "Manager didn't stop properly after closing the context")
				}
			}()

			var started []string
			started = append(started, eventually(ch).Key)
			started = append(started, eventually(ch).Key)
			started = append(started, eventually(ch).Key)

			require.ElementsMatch(t, started, []string{"bar", "baz", "qux"})
		}
	}

	t.Run("sync", runnable(func() WatchStoreManager {
		backend := NewFakeLWBackend(t, kvstore.SyncedPrefix+"/foo/", []kvstore.KeyValueEvent{
			{Typ: kvstore.EventTypeListDone},
			{Typ: kvstore.EventTypeCreate, Key: "not-registered"},
			{Typ: kvstore.EventTypeCreate, Key: "bar"},
			{Typ: kvstore.EventTypeCreate, Key: "bax"},
			{Typ: kvstore.EventTypeCreate, Key: "qux"},
		})

		return NewWatchStoreManagerSync(backend, "foo")
	}))

	t.Run("immediate", runnable(func() WatchStoreManager {
		return NewWatchStoreManagerImmediate("foo")
	}))
}

func TestWatchStoreManagerPanic(t *testing.T) {
	runnable := func(mgr func() WatchStoreManager) func(t *testing.T) {
		return func(t *testing.T) {
			mgr := mgr()

			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			mgr.Run(ctx)

			require.Panics(t, func() { mgr.Register("foo", func(ctx context.Context) {}) },
				"mgr.Register should panic after Run was called")
			require.Panics(t, func() { mgr.Run(ctx) }, "mgr.Run should panic when already started")
		}
	}

	t.Run("sync", runnable(func() WatchStoreManager {
		backend := NewFakeLWBackend(t, kvstore.SyncedPrefix+"/foo/", nil)
		return NewWatchStoreManagerSync(backend, "foo")
	}))

	t.Run("immediate", runnable(func() WatchStoreManager {
		return NewWatchStoreManagerImmediate("foo")
	}))
}
