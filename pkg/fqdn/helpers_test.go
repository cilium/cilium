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

package fqdn

import (
	"github.com/cilium/cilium/pkg/checker"
	. "gopkg.in/check.v1"
)

func (ds *DNSCacheTestSuite) TestKeepUniqueNames(c *C) {
	testData := []struct {
		argument []string
		expected []string
	}{
		{[]string{"a", "b", "c"}, []string{"a", "b", "c"}},
		{[]string{"a", "b", "a", "c"}, []string{"a", "b", "c"}},
		{[]string{""}, []string{""}},
		{[]string{}, []string{}},
	}

	for _, item := range testData {
		val := KeepUniqueNames(item.argument)
		c.Assert(val, checker.DeepEquals, item.expected)
	}
}
