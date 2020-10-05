// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
