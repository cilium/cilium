package subscribe

import (
	"context"

	"github.com/cilium/cilium/pkg/stream"
)

// Subscription provide an interface to send and subscribe to events of type T.
//
// Subscriber can cancel their passed context to stop receiving events.
// Send is used to send events to all subscribers.
// Complete denotes the end of subscription to all subscribers.
type Subscription[T any] interface {
	Subscribe(ctx context.Context) Subscriber[T]
	Send(ev T)
	Complete()
}

func InitSubscription[T any]() Subscription[T] {
	m := manager[T]{}
	m.observe, m.emit, m.complete = stream.Multicast[T]()

	return &m
}

type Subscriber[T any] struct {
	events <-chan T
}

type manager[T any] struct {
	subscribers []Subscriber[T]
	emit        func(T)
	complete    func(err error)
	observe     stream.Observable[T]
}

func (m *manager[T]) Subscribe(ctx context.Context) Subscriber[T] {
	ch := stream.ToChannel(ctx, m.observe, stream.WithBufferSize(10))
	sub := Subscriber[T]{events: ch}
	m.subscribers = append(m.subscribers, sub)

	return sub
}

func (m *manager[T]) Send(ev T) {
	m.emit(ev)
}

func (m *manager[T]) Complete() {
	m.complete(nil)
}
