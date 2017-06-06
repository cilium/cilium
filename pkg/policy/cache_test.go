// Copyright 2016-2017 Authors of Cilium
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
	. "gopkg.in/check.v1"
)

func (s *PolicyTestSuite) TestConsumablesInANotInB(c *C) {
	a := map[NumericIdentity][]NumericIdentity{
		NumericIdentity(3): {NumericIdentity(1), NumericIdentity(2), NumericIdentity(4)},
		NumericIdentity(4): {NumericIdentity(2), NumericIdentity(1)},
	}
	b := map[NumericIdentity][]NumericIdentity{
		NumericIdentity(1): {NumericIdentity(5), NumericIdentity(1), NumericIdentity(7)},
		NumericIdentity(3): {NumericIdentity(1), NumericIdentity(2), NumericIdentity(5)},
	}
	wanted := map[NumericIdentity][]NumericIdentity{
		NumericIdentity(3): {NumericIdentity(4)},
		NumericIdentity(4): {NumericIdentity(1), NumericIdentity(2)},
	}
	received := ConsumablesInANotInB(a, b)

	// reflect.DeepEqual doesn't work for unsorted arrays so we need
	// to check both maps manually.
	c.Assert(len(received), Equals, len(wanted))
	for rcvConsumer, rcvConsumables := range received {
		c.Assert(len(rcvConsumables), Equals, len(wanted[rcvConsumer]))
		for _, rcvConsumable := range rcvConsumables {
			found := false
			for _, wantConsumable := range wanted[rcvConsumer] {
				if rcvConsumable == wantConsumable {
					found = true
					break
				}
			}
			c.Assert(found, Equals, true)
		}
	}
}
