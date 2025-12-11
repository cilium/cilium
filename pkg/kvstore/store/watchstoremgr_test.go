// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package store

import (
	"context"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/cilium/hive/hivetest"
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

	f, _ := GetFactory(t)
	t.Run("sync", runnable(func() WatchStoreManager {
		backend := NewFakeLWBackend(t, kvstore.SyncedPrefix+"/foo/", []kvstore.KeyValueEvent{
			{Typ: kvstore.EventTypeListDone},
			{Typ: kvstore.EventTypeCreate, Key: "not-registered"},
			{Typ: kvstore.EventTypeCreate, Key: "bar"},
			{Typ: kvstore.EventTypeCreate, Key: "bax"},
			{Typ: kvstore.EventTypeCreate, Key: "qux"},
		})

		return f.NewWatchStoreManager(backend, "foo")
	}))

	t.Run("immediate", runnable(func() WatchStoreManager {
		return NewWatchStoreManagerImmediate(hivetest.Logger(t))
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
	f, _ := GetFactory(t)
	t.Run("sync", runnable(func() WatchStoreManager {
		backend := NewFakeLWBackend(t, kvstore.SyncedPrefix+"/foo/", nil)
		return f.NewWatchStoreManager(backend, "foo")
	}))

	t.Run("immediate", runnable(func() WatchStoreManager {
		return NewWatchStoreManagerImmediate(hivetest.Logger(t))
	}))
}

func TestWatchStoreManagerEmpty(t *testing.T) {
	runnable := func(mgr func() WatchStoreManager) func(t *testing.T) {
		return func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var (
					mgr    = mgr()
					exited atomic.Bool
				)

				ctx, cancel := context.WithCancel(context.Background())

				go func() {
					mgr.Run(ctx)
					exited.Store(true)
				}()

				synctest.Wait()
				require.False(t, exited.Load(), "mgr.Run should not exit before the context is canceled")

				cancel()

				synctest.Wait()
				require.True(t, exited.Load(), "mgr.Run should exit once the context is canceled")
			})
		}
	}

	t.Run("sync", runnable(func() WatchStoreManager {
		f, _ := GetFactory(t)
		backend := NewFakeLWBackend(t, kvstore.SyncedPrefix+"/foo/", nil)
		return f.NewWatchStoreManager(backend, "foo")
	}))

	t.Run("immediate", runnable(func() WatchStoreManager {
		return NewWatchStoreManagerImmediate(hivetest.Logger(t))
	}))

}
