// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resource

import (
	"context"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/stream"

	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
)

type FakeResource[T k8sRuntime.Object] struct {
	// The lock protects against a race with replaying history and subscribing
	// to new events.
	lock.Mutex

	src      stream.Observable[Event[T]]
	emit     func(Event[T])
	complete func(error)

	// history emulates the behavior to emit all latest objects followed by a
	// sync event in resource.
	history []Event[T]
}

func NewFakeResource[T k8sRuntime.Object]() (*FakeResource[T], Resource[T]) {
	m := &FakeResource[T]{}
	m.src, m.emit, m.complete = stream.Multicast[Event[T]]()
	return m, m
}

func (m *FakeResource[T]) EmitSync() {
	m.Lock()
	defer m.Unlock()

	ev := Event[T]{Kind: Sync, Done: func(error) {}}
	m.history = append(m.history, ev)
	m.emit(ev)
}

func (m *FakeResource[T]) EmitUpsert(obj T) {
	m.Lock()
	defer m.Unlock()

	ev := Event[T]{
		Kind:   Upsert,
		Key:    NewKey(obj),
		Object: obj,
		Done:   func(error) {},
	}
	m.history = append(m.history, ev)
	m.emit(ev)
}

func (m *FakeResource[T]) EmitDelete(obj T) {
	m.Lock()
	defer m.Unlock()

	ev := Event[T]{
		Kind:   Delete,
		Key:    NewKey(obj),
		Object: obj,
	}
	m.history = append(m.history, ev)
	m.emit(ev)
}

func (r *FakeResource[T]) Events(ctx context.Context, opts ...EventsOpt) <-chan Event[T] {
	events := make(chan Event[T])
	next := func(ev Event[T]) {
		events <- ev
	}
	go func() {
		r.Lock()
		defer r.Unlock()

		// Replay the history first.
		for _, ev := range r.history {
			next(ev)
		}

		// And then subscribe for new events.
		r.src.Observe(ctx, next, func(error) { close(events) })
	}()
	return events
}

func (m *FakeResource[T]) Store(context.Context) (Store[T], error) {
	panic("FakeResource does not implement Store(). Use a fake client with real resource instead.")
}

var _ Resource[*k8sRuntime.Unknown] = &FakeResource[*k8sRuntime.Unknown]{}
