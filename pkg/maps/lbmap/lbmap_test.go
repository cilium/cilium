// Copyright 2018-2019 Authors of Cilium
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

package lbmap

import (
	"net"
	"testing"

	"github.com/cilium/cilium/pkg/u8proto"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type LBMapTestSuite struct{}

var _ = Suite(&LBMapTestSuite{})

func (b *LBMapTestSuite) TestBackendAddrID(c *C) {
	b4, err := NewBackend4Value(net.ParseIP("1.1.1.1"), 80, u8proto.ANY)
	c.Assert(err, IsNil)
	v4 := NewService4Value(0, net.ParseIP("1.1.1.1"), 80, 0, 0)
	c.Assert(b4.BackendAddrID(), Equals, v4.BackendAddrID())

	b6, err := NewBackend6Value(net.ParseIP("f00d::0:0"), 80, u8proto.ANY)
	c.Assert(err, IsNil)
	v6 := NewService6Value(0, net.ParseIP("f00d::0:0"), 80, 0, 0)
	c.Assert(b6.BackendAddrID(), Equals, v6.BackendAddrID())

}
