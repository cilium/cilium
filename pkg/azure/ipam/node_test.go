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

// +build !privileged_tests

package ipam

import (
	"github.com/cilium/cilium/pkg/azure/types"
	"gopkg.in/check.v1"
)

func (e *IPAMSuite) TestGetMaximumAllocatableIPv4(c *check.C) {
	n := &Node{}
	c.Assert(n.GetMaximumAllocatableIPv4(), check.Equals, types.InterfaceAddressLimit)
}
