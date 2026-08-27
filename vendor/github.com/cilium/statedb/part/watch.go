// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package part

import "sync/atomic"

// watchState is the identity of a logical watch. The channel itself is
// allocated lazily when channel() is first called. A watchState may be shared
// by multiple physical nodes when an ART rewrite only changes a compressed
// prefix and leaves the watched subtree unchanged.
type watchState struct {
	value atomic.Pointer[watchChannel]
}

type watchChannel struct {
	ch chan struct{}
}

var closedWatchChannel = func() *watchChannel {
	w := &watchChannel{ch: make(chan struct{})}
	close(w.ch)
	return w
}()

func newWatchState() *watchState {
	return &watchState{}
}

// channel returns the stable channel for this watch. It is safe to race with
// close: either the newly installed channel is closed by close, or this returns
// the shared already-closed channel.
func (w *watchState) channel() <-chan struct{} {
	if w == nil {
		return nil
	}
	for {
		if value := w.value.Load(); value != nil {
			return value.ch
		}

		candidate := &watchChannel{ch: make(chan struct{})}
		if w.value.CompareAndSwap(nil, candidate) {
			return candidate.ch
		}
	}
}

// close closes the watch, including when it races with the first call to
// channel. It is idempotent so a shared watchState is safe to encounter more
// than once while rebuilding a tree.
func (w *watchState) close() {
	if w == nil {
		return
	}
	old := w.value.Swap(closedWatchChannel)
	if old != nil && old != closedWatchChannel {
		close(old.ch)
	}
}

func (w *watchState) isClosed() bool {
	return w != nil && w.value.Load() == closedWatchChannel
}
