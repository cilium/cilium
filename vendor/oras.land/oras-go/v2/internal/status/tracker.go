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

package status

import (
	"sync"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/internal/descriptor"
)

// Tracker tracks content status described by a descriptor.
type Tracker struct {
	status sync.Map // map[descriptor.Descriptor]chan struct{}
}

// NewTracker creates a new content status tracker.
func NewTracker() *Tracker {
	return &Tracker{}
}

// TryCommit tries to commit the work for the target descriptor.
// Returns true if committed. A channel is also returned for sending
// notifications. Once the work is done, the channel should be closed.
// Returns false if the work is done or still in progress.
func (t *Tracker) TryCommit(target ocispec.Descriptor) (chan struct{}, bool) {
	key := descriptor.FromOCI(target)
	status, exists := t.status.LoadOrStore(key, make(chan struct{}))
	return status.(chan struct{}), !exists
}
