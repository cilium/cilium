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
	"testing"

	"github.com/cilium/cilium/pkg/checker"

	"gopkg.in/check.v1"
)

var testIPv4Address IPv4 = [4]byte{10, 0, 0, 2}

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	check.TestingT(t)
}

type IPv4Suite struct{}

var _ = check.Suite(&IPv4Suite{})

func (s *IPv4Suite) TestIP(c *check.C) {
	var expectedAddress net.IP
	expectedAddress = []byte{10, 0, 0, 2}

	result := testIPv4Address.IP()
	c.Assert(result, checker.DeepEquals, expectedAddress)

	result = testIPv4Address.DuplicateIP()
	c.Assert(result, checker.DeepEquals, expectedAddress)
}

func (s *IPv4Suite) TestString(c *check.C) {
	expectedStr := "10.0.0.2"
	result := testIPv4Address.String()

	c.Assert(result, check.Equals, expectedStr)
}
