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

package labels

import (
	"github.com/cilium/cilium/pkg/checker"

	. "gopkg.in/check.v1"
)

var _ = Suite(&LabelsSuite{})

func (s *LabelsSuite) TestIPStringToLabel(c *C) {
	ipToLabels := map[string]string{
		"0.0.0.0/0":    "cidr:0.0.0.0/0",
		"192.0.2.3":    "cidr:192.0.2.3/32",
		"192.0.2.3/32": "cidr:192.0.2.3/32",
		"192.0.2.3/24": "cidr:192.0.2.0/24",
		"192.0.2.0/24": "cidr:192.0.2.0/24",
		"::/0":         "cidr:0--0/0",
		"fdff::ff":     "cidr:fdff--ff/128",
	}
	for ip, labelStr := range ipToLabels {
		c.Assert(IPStringToLabel(ip).String(), checker.DeepEquals, labelStr)
	}
}
