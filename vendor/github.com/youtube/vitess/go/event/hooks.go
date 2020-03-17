// Copyright 2012, Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package event

import (
	"sync"
)

// Hooks holds a list of parameter-less functions to call whenever the set is
// triggered with Fire().
type Hooks struct {
	funcs []func()
	mu    sync.Mutex
}

// Add appends the given function to the list to be triggered.
func (h *Hooks) Add(f func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.funcs = append(h.funcs, f)
}

// Fire calls all the functions in a given Hooks list. It launches a goroutine
// for each function and then waits for all of them to finish before returning.
// Concurrent calls to Fire() are serialized.
func (h *Hooks) Fire() {
	h.mu.Lock()
	defer h.mu.Unlock()

	wg := sync.WaitGroup{}

	for _, f := range h.funcs {
		wg.Add(1)
		go func(f func()) {
			f()
			wg.Done()
		}(f)
	}
	wg.Wait()
}
