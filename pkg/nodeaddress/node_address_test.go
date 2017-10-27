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

package nodeaddress

import (
	"net"

	. "gopkg.in/check.v1"
)

func (s *NodeAddressSuite) TestMaskCheck(c *C) {
	InitDefaultPrefix("")
	SetIPv4ClusterCidrMaskSize(24)

	_, cidr, _ := net.ParseCIDR("1.1.1.1/16")
	SetIPv4AllocRange(cidr)

	// must fail, cluster /24 > per node alloc prefix /16
	c.Assert(ValidatePostInit(), Not(IsNil))

	SetInternalIPv4(cidr.IP)

	// OK, cluster /16 == per node alloc prefix /16
	SetIPv4ClusterCidrMaskSize(16)
	c.Assert(ValidatePostInit(), IsNil)

	// OK, cluster /8 < per node alloc prefix /16
	SetIPv4ClusterCidrMaskSize(8)
	c.Assert(ValidatePostInit(), IsNil)

	c.Assert(IsHostIPv4(GetInternalIPv4()), Equals, true)
	c.Assert(IsHostIPv4(GetExternalIPv4()), Equals, true)
	c.Assert(IsHostIPv6(GetIPv6()), Equals, true)
}
