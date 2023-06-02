// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/u8proto"
)

type PortsTestSuite struct{}

var _ = Suite(&PortsTestSuite{})

func (ds *PortsTestSuite) TestPolicyValidateName(c *C) {
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

func (ds *PortsTestSuite) TestPolicyNewPortProto(c *C) {
	np, err := newPortProto(80, "tcp")
	c.Assert(err, IsNil)
	c.Assert(np, Equals, PortProto{Port: uint16(80), Proto: uint8(6)})

	_, err = newPortProto(88888, "tcp")
	c.Assert(err, Not(IsNil))
	c.Assert(err.Error(), Equals, "Port number 88888 out of 16-bit range")

	_, err = newPortProto(80, "cccp")
	c.Assert(err, Not(IsNil))
	c.Assert(err.Error(), Equals, "unknown protocol 'cccp'")

	np, err = newPortProto(88, "")
	c.Assert(err, IsNil)
	c.Assert(np, Equals, PortProto{Port: uint16(88), Proto: uint8(6)})
}

func (ds *PortsTestSuite) TestPolicyNamedPortMap(c *C) {
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

func (ds *PortsTestSuite) TestPolicyPortProtoSet(c *C) {
	a := PortProtoSet{
		PortProto{Port: 80, Proto: 6}:  1,
		PortProto{Port: 443, Proto: 6}: 1,
		PortProto{Port: 53, Proto: 17}: 1,
	}
	b := PortProtoSet{
		PortProto{Port: 80, Proto: 6}:  1,
		PortProto{Port: 443, Proto: 6}: 1,
		PortProto{Port: 53, Proto: 6}:  1,
	}
	c.Assert(a.Equal(a), Equals, true)
	c.Assert(a.Equal(b), Equals, false)
	c.Assert(b.Equal(b), Equals, true)
}

func (ds *PortsTestSuite) TestPolicyNamedPortMultiMap(c *C) {
	a := &namedPortMultiMap{
		m: map[string]PortProtoSet{
			"http": {
				PortProto{Port: 80, Proto: 6}:   1,
				PortProto{Port: 8080, Proto: 6}: 1,
			},
			"https": {
				PortProto{Port: 443, Proto: 6}: 1,
			},
			"zero": {
				PortProto{Port: 0, Proto: 6}: 1,
			},
			"none": {},
			"dns": {
				PortProto{Port: 53, Proto: 17}: 1,
				PortProto{Port: 53, Proto: 6}:  1,
			},
		},
	}
	b := &namedPortMultiMap{
		m: map[string]PortProtoSet{
			"http": {
				PortProto{Port: 80, Proto: 6}:   1,
				PortProto{Port: 8080, Proto: 6}: 1,
			},
			"https": {
				PortProto{Port: 443, Proto: 6}: 1,
			},
			"zero": {
				PortProto{Port: 0, Proto: 6}: 1,
			},
			"none": {},
			"dns": {
				PortProto{Port: 53, Proto: 0}: 1,
			},
		},
	}

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

	var nilvalued *namedPortMultiMap
	port, err = NamedPortMultiMap(nilvalued).GetNamedPort("unknown", 6)
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

func (ds *PortsTestSuite) TestPolicyNamedPortMultiMapUpdate(c *C) {
	npm := NewNamedPortMultiMap()

	pod1PortsOld := map[string]PortProto{}
	pod1PortsNew := map[string]PortProto{
		"http": {80, uint8(u8proto.TCP)},
	}

	// Insert http=80/TCP from pod1
	changed := npm.Update(pod1PortsOld, pod1PortsNew)
	c.Assert(changed, Equals, true)

	// No changes
	changed = npm.Update(pod1PortsNew, pod1PortsNew)
	c.Assert(changed, Equals, false)

	// Assert http=80/TCP
	port, err := npm.GetNamedPort("http", uint8(u8proto.TCP))
	c.Assert(err, IsNil)
	c.Assert(port, Equals, uint16(80))

	pod2PortsOld := map[string]PortProto{}
	pod2PortsNew := map[string]PortProto{
		"http": {8080, uint8(u8proto.UDP)},
	}

	// Insert http=8080/UDP from pod2, retain http=80/TCP from pod1
	changed = npm.Update(pod2PortsOld, pod2PortsNew)
	c.Assert(changed, Equals, true)

	port, err = npm.GetNamedPort("http", uint8(u8proto.TCP))
	c.Assert(err, IsNil)
	c.Assert(port, Equals, uint16(80))
	port, err = npm.GetNamedPort("http", uint8(u8proto.UDP))
	c.Assert(err, IsNil)
	c.Assert(port, Equals, uint16(8080))

	// Delete http=80/TCP from pod1, retain http=8080/UDP from pod2
	pod1PortsOld = pod1PortsNew
	pod1PortsNew = map[string]PortProto{}

	// Delete http=80/TCP from pod1
	changed = npm.Update(pod1PortsOld, pod1PortsNew)
	c.Assert(changed, Equals, true)

	port, err = npm.GetNamedPort("http", uint8(u8proto.UDP))
	c.Assert(err, IsNil)
	c.Assert(port, Equals, uint16(8080))
}
