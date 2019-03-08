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

// +build !privileged_tests

package types

import (
	"net"

	"github.com/cilium/cilium/pkg/checker"

	"gopkg.in/check.v1"
)

var testIPv6Address IPv6 = [16]byte{240, 13, 0, 0, 0, 0, 0, 0, 172, 16, 0, 20, 0, 0, 0, 1}

type IPv6Suite struct{}

var _ = check.Suite(&IPv6Suite{})

func (s *IPv6Suite) TestIP(c *check.C) {
	var expectedAddress net.IP
	expectedAddress = []byte{240, 13, 0, 0, 0, 0, 0, 0, 172, 16, 0, 20, 0, 0, 0, 1}

	result := testIPv6Address.IP()
	c.Assert(result, checker.DeepEquals, expectedAddress)

	result = testIPv6Address.DuplicateIP()
	c.Assert(result, checker.DeepEquals, expectedAddress)

}

func (s *IPv6Suite) TestString(c *check.C) {
	expectedStr := "f00d::ac10:14:0:1"
	result := testIPv6Address.String()

	c.Assert(result, check.Equals, expectedStr)
}
