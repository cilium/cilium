/*
Copyright 2019 Authors of Cilium
Copyright 2014-2019 The Kubernetes Authors.

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

package uuid

import (
	"github.com/cilium/cilium/pkg/lock"

	"github.com/pborman/uuid"
	"k8s.io/apimachinery/pkg/types"
)

var uuidLock lock.Mutex
var lastUUID uuid.UUID

// A UUID is a 128 bit (16 byte) Universal Unique IDentifier as defined in RFC
// 4122.
type UUID struct {
	uuid.UUID
}

// ToUID converts the UUID into a k8s UID.
func (u UUID) ToUID() types.UID {
	return types.UID(u.String())
}

// Parse decodes the specified uuid into a UUID or returns nil.
func Parse(uid string) UUID {
	return UUID{uuid.Parse(uid)}
}

// ParseUID decodes uid into a UUID or returns nil.
func ParseUID(uid types.UID) UUID {
	return Parse(string(uid))
}

// NewUUID returns a new UUID
func NewUUID() UUID {
	uuidLock.Lock()
	defer uuidLock.Unlock()
	result := uuid.NewUUID()
	// The UUID package is naive and can generate identical UUIDs if the
	// time interval is quick enough.
	// The UUID uses 100 ns increments so it's short enough to actively
	// wait for a new value.
	for uuid.Equal(lastUUID, result) == true {
		result = uuid.NewUUID()
	}
	lastUUID = result
	return UUID{result}
}
