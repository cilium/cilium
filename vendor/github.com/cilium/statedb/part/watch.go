// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package part

import (
	"sync/atomic"
	"unsafe"
)

// atomicWatchPointer atomically stores a channel without allocating a wrapper
// object around it. Go channel values are pointers to runtime.hchan. Keeping
// that pointer in an atomic.Pointer ensures the garbage collector sees it and
// applies the write barrier. An atomicWatchPointer also acts as the logical
// identity shared by lazyWatchChannels that represent the same watch.
type atomicWatchPointer struct {
	pointer atomic.Pointer[struct{}]
}

func (p *atomicWatchPointer) load() chan struct{} {
	return ptrToWatch(p.pointer.Load())
}

func (p *atomicWatchPointer) compareAndSwap(old, new chan struct{}) bool {
	return p.pointer.CompareAndSwap(watchToPtr(old), watchToPtr(new))
}

func (p *atomicWatchPointer) swap(new chan struct{}) chan struct{} {
	return ptrToWatch(p.pointer.Swap(watchToPtr(new)))
}

func watchToPtr(ch chan struct{}) *struct{} {
	return *(**struct{})(unsafe.Pointer(&ch))
}

func ptrToWatch(ptr *struct{}) chan struct{} {
	return *(*chan struct{})(unsafe.Pointer(&ptr))
}

// lazyWatchChannel is embedded in each node. A nil identity is an enabled
// watch that has not been observed yet. This avoids allocating an
// atomicWatchPointer for nodes that are only accessed through non-watching
// operations. Multiple physical nodes may share the same identity when an ART
// rewrite only changes a compressed prefix and leaves the watched subtree
// unchanged.
type lazyWatchChannel struct {
	identity atomic.Pointer[atomicWatchPointer]
}

// watchTarget identifies the watch selected by a tree lookup without
// materializing a lazy watch identity or channel. Root watches use direct,
// while per-node watches use lazy. At most one of the fields is non-nil.
type watchTarget struct {
	direct *atomicWatchPointer
	lazy   *lazyWatchChannel
}

func (w watchTarget) channel() <-chan struct{} {
	if w.lazy != nil {
		return w.lazy.channel()
	}
	return w.direct.channel()
}

var closedWatchChannel = func() chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}()

var disabledWatchIdentity = &atomicWatchPointer{}

var closedWatchIdentity = func() *atomicWatchPointer {
	w := &atomicWatchPointer{}
	w.pointer.Store(watchToPtr(closedWatchChannel))
	return w
}()

func newWatchIdentity() *atomicWatchPointer {
	return &atomicWatchPointer{}
}

func (w *lazyWatchChannel) enabled() bool {
	return w.identity.Load() != disabledWatchIdentity
}

func (w *lazyWatchChannel) disable() {
	w.identity.Store(disabledWatchIdentity)
}

// loadOrCreate returns the logical watch identity, creating it if needed. An
// identity is also created when two physical nodes need to share it after a
// prefix-preserving rewrite.
func (w *lazyWatchChannel) loadOrCreate() *atomicWatchPointer {
	for {
		identity := w.identity.Load()
		if identity != nil {
			if identity == disabledWatchIdentity {
				return nil
			}
			return identity
		}

		identity = newWatchIdentity()
		if w.identity.CompareAndSwap(nil, identity) {
			return identity
		}
	}
}

func (w *lazyWatchChannel) shareFrom(other *lazyWatchChannel) {
	identity := other.loadOrCreate()
	if identity == nil {
		w.disable()
	} else {
		w.identity.Store(identity)
	}
}

func (w *lazyWatchChannel) channel() <-chan struct{} {
	identity := w.loadOrCreate()
	if identity == nil {
		return nil
	}
	return identity.channel()
}

// close invalidates the lazy channel without missing a concurrent first
// observer. If the identity has already been materialized, retain it so
// physical nodes that share the identity continue to observe the same closed
// state.
func (w *lazyWatchChannel) close() {
	for {
		identity := w.identity.Load()
		switch identity {
		case disabledWatchIdentity, closedWatchIdentity:
			return
		case nil:
			if w.identity.CompareAndSwap(nil, closedWatchIdentity) {
				return
			}
		default:
			identity.close()
			return
		}
	}
}

func (w *lazyWatchChannel) isClosed() bool {
	identity := w.identity.Load()
	return identity == closedWatchIdentity || identity != nil && identity != disabledWatchIdentity && identity.isClosed()
}

// channel returns the stable channel for this watch. It is safe to race with
// close: either the newly installed channel is closed by close, or this returns
// the shared already-closed channel.
func (w *atomicWatchPointer) channel() <-chan struct{} {
	if w == nil {
		return nil
	}
	for {
		if ch := w.load(); ch != nil {
			return ch
		}

		candidate := make(chan struct{})
		if w.compareAndSwap(nil, candidate) {
			return candidate
		}
	}
}

// close closes the watch, including when it races with the first call to
// channel. It is idempotent so a shared atomicWatchPointer is safe to
// encounter more than once while rebuilding a tree.
func (w *atomicWatchPointer) close() {
	if w == nil {
		return
	}
	old := w.swap(closedWatchChannel)
	if old != nil && old != closedWatchChannel {
		close(old)
	}
}

func (w *atomicWatchPointer) isClosed() bool {
	return w != nil && w.load() == closedWatchChannel
}
