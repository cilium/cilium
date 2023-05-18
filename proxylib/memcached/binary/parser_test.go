// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package binary

import (
	"testing"

	. "github.com/cilium/checkmate"
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
