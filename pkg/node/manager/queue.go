// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import "github.com/cilium/cilium/pkg/lock"

type queue[T any] struct {
	mx    lock.RWMutex
	items []*T
}

func (q *queue[T]) push(t *T) {
	q.mx.Lock()
	defer q.mx.Unlock()

	q.items = append(q.items, t)
}

func (q *queue[T]) isEmpty() bool {
	q.mx.RLock()
	defer q.mx.RUnlock()

	return len(q.items) == 0
}

func (q *queue[T]) pop() *T {
	if q.isEmpty() {
		return nil
	}

	q.mx.Lock()
	defer q.mx.Unlock()
	t := q.items[0]
	q.items = q.items[1:]

	return t
}
