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

// +build !privileged_tests

package dnsproxy

import (
	"strconv"

	. "gopkg.in/check.v1"
)

type DNSProxyHelperTestSuite struct{}

var _ = Suite(&DNSProxyHelperTestSuite{})

// TestParsePortString tests that ParsePortString parses port strings.
func (s *DNSProxyHelperTestSuite) TestParsePortString(c *C) {
	for i := 0; i < 65536; i++ {
		portStr := strconv.Itoa(i)
		port, err := parsePortString(portStr)
		c.Assert(err, IsNil, Commentf("ParsePortString marked a valid port(%s) as invalid", portStr))
		c.Assert(port, Equals, uint16(i), Commentf("ParsePortString parsed a port string(%s) incorrectly", portStr))
	}

	for _, reject := range []string{
		"-1",
		"65536",
		"1000000",
	} {
		_, err := parsePortString(reject)
		c.Assert(err, NotNil, Commentf("ParsePortString marked an invalid port as valid"))
	}
}
