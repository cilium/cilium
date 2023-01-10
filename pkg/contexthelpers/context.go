// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package contexthelpers

import (
	"context"
	"time"
)

type SuccessChan chan bool

// NewConditionalTimeoutContext returns a context which is cancelled when
// success is not reported within the specified timeout
func NewConditionalTimeoutContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc, SuccessChan) {
	ch := make(SuccessChan, 1)
	c, cancel := context.WithCancel(ctx)

	go func() {
		select {
		case success := <-ch:
			if !success {
				cancel()
				return
			}
		case <-time.After(timeout):
			cancel()
		}
	}()

	return c, cancel, ch
}
