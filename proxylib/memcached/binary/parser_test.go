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

package binary

import (
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type BinaryMemcachedTestSuite struct{}

var _ = Suite(&BinaryMemcachedTestSuite{})

func (k *BinaryMemcachedTestSuite) TestMemcacheGetKey(c *C) {
	packet := []byte{
		0x80, 0, 0, 0x5,
		0, 0, 0, 0,
		0, 0, 0, 0x5,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		'T', 'e', 's', 't',
		'1',
	}

	key := getMemcacheKey(packet, 0, 5)

	c.Assert(string(key), Equals, "Test1")

	packet = []byte{
		0x80, 0, 0, 0x5,
		0x4, 0, 0, 0,
		0, 0, 0, 0x5,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		'e', 'x', 't', 'r',
		'T', 'e', 's', 't',
		'1',
	}

	key = getMemcacheKey(packet, 4, 5)

	c.Assert(string(key), Equals, "Test1")

	packet = []byte{
		0x80, 0x8, 0, 0x0,
		0x4, 0, 0, 0,
		0, 0, 0, 0x4,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0x1c, 0x20,
	}

	key = getMemcacheKey(packet, 4, 0)

	c.Assert(string(key), Equals, "")
}
