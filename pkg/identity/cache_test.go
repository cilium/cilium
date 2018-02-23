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

package identity

import (
	"github.com/cilium/cilium/pkg/labels"

	. "gopkg.in/check.v1"
)

func (s *IdentityTestSuite) TestLookupReservedIdentity(c *C) {
	hostID := GetReservedID("host")
	c.Assert(LookupIdentityByID(hostID), Not(IsNil))

	identity := LookupIdentity(labels.NewLabelsFromModel([]string{"reserved:host"}))
	c.Assert(identity, Not(IsNil))
	c.Assert(identity.ID, Equals, hostID)

	worldID := GetReservedID("world")
	c.Assert(LookupIdentityByID(worldID), Not(IsNil))

	identity = LookupIdentity(labels.NewLabelsFromModel([]string{"reserved:world"}))
	c.Assert(identity, Not(IsNil))
	c.Assert(identity.ID, Equals, worldID)
}
