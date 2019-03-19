// Copyright 2019 Authors of Cilium
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

package policy

import (
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/lock"
)

// IDSet is a wrapper type around a set of unsigned 16-bit integers, with
// a mutex for protecting access.
type IDSet struct {
	Mutex lock.RWMutex
	IDs   map[uint16]struct{}
}

// NewIDSet returns a new instance of an IDSet.
func NewIDSet() *IDSet {
	return &IDSet{
		IDs: map[uint16]struct{}{},
	}
}

// Endpoint refers to any structure which has the following properties:
// * a node-local ID stored as a uint16
// * a security identity
// * a means of incrementing its policy revision
type Endpoint interface {
	GetID16() uint16
	GetSecurityIdentity() *identity.Identity
	PolicyRevisionBumpEvent(rev uint64)
}
