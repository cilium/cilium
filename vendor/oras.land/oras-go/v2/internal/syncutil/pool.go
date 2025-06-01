/*
Copyright The ORAS Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package syncutil

import "sync"

// poolItem represents an item in Pool.
type poolItem[T any] struct {
	value    T
	refCount int
}

// Pool is a scalable pool with items identified by keys.
type Pool[T any] struct {
	// New optionally specifies a function to generate a value when Get would
	// otherwise return nil.
	// It may not be changed concurrently with calls to Get.
	New func() T

	lock  sync.Mutex
	items map[any]*poolItem[T]
}

// Get gets the value identified by key.
// The caller should invoke the returned function after using the returned item.
func (p *Pool[T]) Get(key any) (*T, func()) {
	p.lock.Lock()
	defer p.lock.Unlock()

	item, ok := p.items[key]
	if !ok {
		if p.items == nil {
			p.items = make(map[any]*poolItem[T])
		}
		item = &poolItem[T]{}
		if p.New != nil {
			item.value = p.New()
		}
		p.items[key] = item
	}
	item.refCount++

	return &item.value, func() {
		p.lock.Lock()
		defer p.lock.Unlock()
		item.refCount--
		if item.refCount <= 0 {
			delete(p.items, key)
		}
	}
}
