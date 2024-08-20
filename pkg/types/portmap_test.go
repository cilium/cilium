// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/u8proto"
)

func TestPolicyValidateName(t *testing.T) {
	name, err := ValidatePortName("Http")
	require.Nil(t, err)
	require.Equal(t, "http", name)

	name, err = ValidatePortName("dns-tcp")
	require.Nil(t, err)
	require.Equal(t, "dns-tcp", name)

	_, err = ValidatePortName("-http")
	require.NotNil(t, err)

	_, err = ValidatePortName("http-")
	require.NotNil(t, err)

	name, err = ValidatePortName("http-80")
	require.Nil(t, err)
	require.Equal(t, "http-80", name)

	_, err = ValidatePortName("http--s")
	require.NotNil(t, err)
}

func TestPolicyNewPortProto(t *testing.T) {
	np, err := newPortProto(80, "tcp")
	require.Nil(t, err)
	require.Equal(t, PortProto{Port: uint16(80), Proto: u8proto.TCP}, np)

	_, err = newPortProto(88888, "tcp")
	require.NotNil(t, err)
	require.Equal(t, "Port number 88888 out of 16-bit range", err.Error())

	_, err = newPortProto(80, "cccp")
	require.NotNil(t, err)
	require.Equal(t, "unknown protocol 'cccp'", err.Error())

	np, err = newPortProto(88, "")
	require.Nil(t, err)
	require.Equal(t, PortProto{Port: uint16(88), Proto: u8proto.TCP}, np)
}

func TestPolicyNamedPortMap(t *testing.T) {
	npm := make(NamedPortMap)

	err := npm.AddPort("http", 80, "tcp")
	require.Nil(t, err)
	require.Len(t, npm, 1)

	err = npm.AddPort("dns", 53, "UDP")
	require.Nil(t, err)
	require.Len(t, npm, 2)

	err = npm.AddPort("zero", 0, "TCP")
	require.Equal(t, ErrNamedPortIsZero, err)
	require.Len(t, npm, 2)

	proto, err := u8proto.ParseProtocol("UDP")
	require.Nil(t, err)
	require.Equal(t, uint8(17), uint8(proto))

	port, err := npm.GetNamedPort("dns", proto)
	require.Nil(t, err)
	require.Equal(t, uint16(53), port)

	port, err = npm.GetNamedPort("dns", u8proto.TCP)
	require.Equal(t, ErrIncompatibleProtocol, err)
	require.Equal(t, uint16(0), port)

	port, err = npm.GetNamedPort("unknown", proto)
	require.Equal(t, ErrUnknownNamedPort, err)
	require.Equal(t, uint16(0), port)
}

func TestPolicyPortProtoSet(t *testing.T) {
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
	require.Equal(t, true, a.Equal(a))
	require.Equal(t, false, a.Equal(b))
	require.Equal(t, true, b.Equal(b))
}

func TestPolicyNamedPortMultiMap(t *testing.T) {
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
	require.Equal(t, ErrDuplicateNamedPorts, err)
	require.Equal(t, uint16(0), port)

	port, err = a.GetNamedPort("http", 17)
	require.Equal(t, ErrIncompatibleProtocol, err)
	require.Equal(t, uint16(0), port)

	port, err = a.GetNamedPort("zero", 6)
	require.Equal(t, ErrNamedPortIsZero, err)
	require.Equal(t, uint16(0), port)

	port, err = a.GetNamedPort("none", 6)
	require.Equal(t, ErrUnknownNamedPort, err)
	require.Equal(t, uint16(0), port)

	port, err = a.GetNamedPort("unknown", 6)
	require.Equal(t, ErrUnknownNamedPort, err)
	require.Equal(t, uint16(0), port)

	var nilvalued *namedPortMultiMap
	port, err = NamedPortMultiMap(nilvalued).GetNamedPort("unknown", 6)
	require.Equal(t, ErrNilMap, err)
	require.Equal(t, uint16(0), port)

	port, err = a.GetNamedPort("https", 6)
	require.Nil(t, err)
	require.Equal(t, uint16(443), port)

	port, err = a.GetNamedPort("dns", 6)
	require.Nil(t, err)
	require.Equal(t, uint16(53), port)

	port, err = b.GetNamedPort("dns", 6)
	require.Nil(t, err)
	require.Equal(t, uint16(53), port)

	port, err = a.GetNamedPort("dns", 17)
	require.Nil(t, err)
	require.Equal(t, uint16(53), port)

	port, err = b.GetNamedPort("dns", 17)
	require.Nil(t, err)
	require.Equal(t, uint16(53), port)
}

func TestPolicyNamedPortMultiMapUpdate(t *testing.T) {
	npm := NewNamedPortMultiMap()

	pod1PortsOld := map[string]PortProto{}
	pod1PortsNew := map[string]PortProto{
		"http": {u8proto.TCP, 80},
	}

	// Insert http=80/TCP from pod1
	changed := npm.Update(pod1PortsOld, pod1PortsNew)
	require.Equal(t, true, changed)

	// No changes
	changed = npm.Update(pod1PortsNew, pod1PortsNew)
	require.Equal(t, false, changed)

	// Assert http=80/TCP
	port, err := npm.GetNamedPort("http", u8proto.TCP)
	require.Nil(t, err)
	require.Equal(t, uint16(80), port)

	pod2PortsOld := map[string]PortProto{}
	pod2PortsNew := map[string]PortProto{
		"http": {u8proto.UDP, 8080},
	}

	// Insert http=8080/UDP from pod2, retain http=80/TCP from pod1
	changed = npm.Update(pod2PortsOld, pod2PortsNew)
	require.Equal(t, true, changed)

	port, err = npm.GetNamedPort("http", u8proto.TCP)
	require.Nil(t, err)
	require.Equal(t, uint16(80), port)
	port, err = npm.GetNamedPort("http", u8proto.UDP)
	require.Nil(t, err)
	require.Equal(t, uint16(8080), port)

	// Delete http=80/TCP from pod1, retain http=8080/UDP from pod2
	pod1PortsOld = pod1PortsNew
	pod1PortsNew = map[string]PortProto{}

	// Delete http=80/TCP from pod1
	changed = npm.Update(pod1PortsOld, pod1PortsNew)
	require.Equal(t, true, changed)

	port, err = npm.GetNamedPort("http", u8proto.UDP)
	require.Nil(t, err)
	require.Equal(t, uint16(8080), port)
}
