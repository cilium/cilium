// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package runner

import (
	"errors"
	"sync"
)

// MultiError can be used to run multiple goroutines that
// might return an error, wait for all the goroutines and
// return joined errors as a single one.
type MultiError struct {
	wg   sync.WaitGroup
	lock sync.Mutex
	err  error
}

// Go runs a function in a separate goroutine.
func (m *MultiError) Go(fn func() error) {
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		if err := fn(); err != nil {
			m.lock.Lock()
			m.err = errors.Join(m.err, err)
			m.lock.Unlock()
		}
	}()
}

// Wait waits for all the goroutines to finish and returns
// joined errors as a single one.
func (m *MultiError) Wait() error {
	m.wg.Wait()
	return m.err
}
