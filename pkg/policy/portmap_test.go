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

package policy

import (
	"github.com/cilium/cilium/pkg/u8proto"

	. "gopkg.in/check.v1"
)

func (ds *PolicyTestSuite) TestPolicyValidateName(c *C) {
	name, err := ValidatePortName("Http")
	c.Assert(err, IsNil)
	c.Assert(name, Equals, "http")

	name, err = ValidatePortName("dns-tcp")
	c.Assert(err, IsNil)
	c.Assert(name, Equals, "dns-tcp")

	_, err = ValidatePortName("-http")
	c.Assert(err, Not(IsNil))

	_, err = ValidatePortName("http-")
	c.Assert(err, Not(IsNil))

	name, err = ValidatePortName("http-80")
	c.Assert(err, IsNil)
	c.Assert(name, Equals, "http-80")

	_, err = ValidatePortName("http--s")
	c.Assert(err, Not(IsNil))
}

func (ds *PolicyTestSuite) TestPolicyNewPortProto(c *C) {
	np, err := newPortProto(80, "tcp")
	c.Assert(err, IsNil)
	c.Assert(np, Equals, PortProto{Port: uint16(80), Proto: uint8(6)})

	_, err = newPortProto(88888, "tcp")
	c.Assert(err, Not(IsNil))
	c.Assert(err.Error(), Equals, "Port number 88888 out of 16-bit range")

	_, err = newPortProto(80, "cccp")
	c.Assert(err, Not(IsNil))
	c.Assert(err.Error(), Equals, "unknown protocol \"cccp\"")

	np, err = newPortProto(88, "")
	c.Assert(err, IsNil)
	c.Assert(np, Equals, PortProto{Port: uint16(88), Proto: uint8(6)})
}

func (ds *PolicyTestSuite) TestPolicyNamedPortMap(c *C) {
	npm := make(NamedPortMap)

	err := npm.AddPort("http", 80, "tcp")
	c.Assert(err, IsNil)
	c.Assert(npm, HasLen, 1)

	err = npm.AddPort("dns", 53, "UDP")
	c.Assert(err, IsNil)
	c.Assert(npm, HasLen, 2)

	err = npm.AddPort("zero", 0, "TCP")
	c.Assert(err, Equals, ErrNamedPortIsZero)
	c.Assert(npm, HasLen, 2)

	proto, err := u8proto.ParseProtocol("UDP")
	c.Assert(err, IsNil)
	c.Assert(uint8(proto), Equals, uint8(17))

	port, err := npm.GetNamedPort("dns", uint8(proto))
	c.Assert(err, IsNil)
	c.Assert(port, Equals, uint16(53))

	port, err = npm.GetNamedPort("dns", uint8(6))
	c.Assert(err, Equals, ErrIncompatibleProtocol)
	c.Assert(port, Equals, uint16(0))

	port, err = npm.GetNamedPort("unknown", uint8(proto))
	c.Assert(err, Equals, ErrUnknownNamedPort)
	c.Assert(port, Equals, uint16(0))
}

func (ds *PolicyTestSuite) TestPolicyPortProtoSet(c *C) {
	a := PortProtoSet{
		PortProto{Port: 80, Proto: 6}:  struct{}{},
		PortProto{Port: 443, Proto: 6}: struct{}{},
		PortProto{Port: 53, Proto: 17}: struct{}{},
	}
	b := PortProtoSet{
		PortProto{Port: 80, Proto: 6}:  struct{}{},
		PortProto{Port: 443, Proto: 6}: struct{}{},
		PortProto{Port: 53, Proto: 6}:  struct{}{},
	}
	c.Assert(a.Equal(a), Equals, true)
	c.Assert(a.Equal(b), Equals, false)
	c.Assert(b.Equal(b), Equals, true)
}

func (ds *PolicyTestSuite) TestPolicyNamedPortMultiMap(c *C) {
	a := NamedPortMultiMap{
		"http": PortProtoSet{
			PortProto{Port: 80, Proto: 6}:   struct{}{},
			PortProto{Port: 8080, Proto: 6}: struct{}{},
		},
		"https": PortProtoSet{
			PortProto{Port: 443, Proto: 6}: struct{}{},
		},
		"zero": PortProtoSet{
			PortProto{Port: 0, Proto: 6}: struct{}{},
		},
		"none": PortProtoSet{},
		"dns": PortProtoSet{
			PortProto{Port: 53, Proto: 17}: struct{}{},
			PortProto{Port: 53, Proto: 6}:  struct{}{},
		},
	}
	b := NamedPortMultiMap{
		"http": PortProtoSet{
			PortProto{Port: 80, Proto: 6}:   struct{}{},
			PortProto{Port: 8080, Proto: 6}: struct{}{},
		},
		"https": PortProtoSet{
			PortProto{Port: 443, Proto: 6}: struct{}{},
		},
		"zero": PortProtoSet{
			PortProto{Port: 0, Proto: 6}: struct{}{},
		},
		"none": PortProtoSet{},
		"dns": PortProtoSet{
			PortProto{Port: 53, Proto: 0}: struct{}{},
		},
	}

	c.Assert(a.Equal(a), Equals, true)
	c.Assert(a.Equal(b), Equals, false)
	c.Assert(b.Equal(b), Equals, true)

	port, err := a.GetNamedPort("http", 6)
	c.Assert(err, Equals, ErrDuplicateNamedPorts)
	c.Assert(port, Equals, uint16(0))

	port, err = a.GetNamedPort("http", 17)
	c.Assert(err, Equals, ErrIncompatibleProtocol)
	c.Assert(port, Equals, uint16(0))

	port, err = a.GetNamedPort("zero", 6)
	c.Assert(err, Equals, ErrNamedPortIsZero)
	c.Assert(port, Equals, uint16(0))

	port, err = a.GetNamedPort("none", 6)
	c.Assert(err, Equals, ErrUnknownNamedPort)
	c.Assert(port, Equals, uint16(0))

	port, err = a.GetNamedPort("unknown", 6)
	c.Assert(err, Equals, ErrUnknownNamedPort)
	c.Assert(port, Equals, uint16(0))

	port, err = NamedPortMultiMap(nil).GetNamedPort("unknown", 6)
	c.Assert(err, Equals, ErrNilMap)
	c.Assert(port, Equals, uint16(0))

	port, err = a.GetNamedPort("https", 6)
	c.Assert(err, IsNil)
	c.Assert(port, Equals, uint16(443))

	port, err = a.GetNamedPort("dns", 6)
	c.Assert(err, IsNil)
	c.Assert(port, Equals, uint16(53))

	port, err = b.GetNamedPort("dns", 6)
	c.Assert(err, IsNil)
	c.Assert(port, Equals, uint16(53))

	port, err = a.GetNamedPort("dns", 17)
	c.Assert(err, IsNil)
	c.Assert(port, Equals, uint16(53))

	port, err = b.GetNamedPort("dns", 17)
	c.Assert(err, IsNil)
	c.Assert(port, Equals, uint16(53))
}
