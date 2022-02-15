// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cleanup

import (
	"sync"
)

// DeferTerminationCleanupFunction will execute the given function `f` when the
// channel `ch` is closed.
// The given waitGroup will be added with a delta +1 and once the function
// `f` returns from its execution that same waitGroup will signalize function
// `f` is completed.
func DeferTerminationCleanupFunction(wg *sync.WaitGroup, ch <-chan struct{}, f func()) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ch
		f()
	}()
}
