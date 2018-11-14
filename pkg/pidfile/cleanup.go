// Copyright 2018 Authors of Cilium
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

package pidfile

import (
	"sync"
)

// HandleCleanup will execute the given function `f` when the channel `ch` is closed.
// The given waitGroup will be added with a delta +1 and once the function
// `f` returns from its execution that same waitGroup will signalize function
// `f` is completed.
func HandleCleanup(wg *sync.WaitGroup, ch <-chan struct{}, f func()) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ch
		f()
	}()
}
