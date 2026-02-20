// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/u8proto"
)

func TestPolicyValidateName(t *testing.T) {
	name, err := ValidatePortName("Http")
	require.NoError(t, err)
	require.Equal(t, "http", name)

	name, err = ValidatePortName("dns-tcp")
	require.NoError(t, err)
	require.Equal(t, "dns-tcp", name)

	_, err = ValidatePortName("-http")
	require.Error(t, err)

	_, err = ValidatePortName("http-")
	require.Error(t, err)

	name, err = ValidatePortName("http-80")
	require.NoError(t, err)
	require.Equal(t, "http-80", name)

	_, err = ValidatePortName("http--s")
	require.Error(t, err)
}

func TestPolicyNewPortProto(t *testing.T) {
	np, err := newPortProto(80, "tcp")
	require.NoError(t, err)
	require.Equal(t, PortProto{Port: uint16(80), Proto: u8proto.TCP}, np)

	_, err = newPortProto(88888, "tcp")
	require.Error(t, err)
	require.Equal(t, "Port number 88888 out of 16-bit range", err.Error())

	_, err = newPortProto(80, "cccp")
	require.Error(t, err)
	require.Equal(t, "unknown protocol 'cccp'", err.Error())

	np, err = newPortProto(88, "")
	require.NoError(t, err)
	require.Equal(t, PortProto{Port: uint16(88), Proto: u8proto.TCP}, np)
}

func TestPolicyNamedPortMap(t *testing.T) {
	npm := make(NamedPortMap)

	err := npm.AddPort("http", 80, "tcp")
	require.NoError(t, err)
	require.Len(t, npm, 1)

	err = npm.AddPort("dns", 53, "UDP")
	require.NoError(t, err)
	require.Len(t, npm, 2)

	err = npm.AddPort("zero", 0, "TCP")
	require.Equal(t, ErrNamedPortIsZero, err)
	require.Len(t, npm, 2)

	proto, err := u8proto.ParseProtocol("UDP")
	require.NoError(t, err)
	require.Equal(t, uint8(17), uint8(proto))

	port, err := npm.GetNamedPort("dns", proto)
	require.NoError(t, err)
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
		PortProto{Port: 80, Proto: u8proto.TCP}:  {identity.NumericIdentity(0): {}},
		PortProto{Port: 443, Proto: u8proto.TCP}: {identity.NumericIdentity(0): {}},
		PortProto{Port: 53, Proto: u8proto.UDP}:  {identity.NumericIdentity(0): {}},
	}
	b := PortProtoSet{
		PortProto{Port: 80, Proto: u8proto.TCP}:  {identity.NumericIdentity(0): {}},
		PortProto{Port: 443, Proto: u8proto.TCP}: {identity.NumericIdentity(0): {}},
		PortProto{Port: 53, Proto: u8proto.TCP}:  {identity.NumericIdentity(0): {}},
	}
	require.True(t, a.Equal(a))
	require.False(t, a.Equal(b))
	require.True(t, b.Equal(b))
}

func TestPolicyNamedPortMultiMap(t *testing.T) {
	id0 := map[identity.NumericIdentity]struct{}{identity.NumericIdentity(0): {}}
	id1 := map[identity.NumericIdentity]struct{}{identity.NumericIdentity(1): {}}
	a := &namedPortMultiMap{
		m: map[string]PortProtoSet{
			"http": {
				PortProto{Port: 80, Proto: u8proto.TCP}:   {identity.NumericIdentity(0): {}},
				PortProto{Port: 8080, Proto: u8proto.TCP}: {identity.NumericIdentity(1): {}},
			},
			"https": {
				PortProto{Port: 443, Proto: u8proto.TCP}: {identity.NumericIdentity(0): {}},
			},
			"zero": {
				PortProto{Port: 0, Proto: u8proto.TCP}: {identity.NumericIdentity(0): {}},
			},
			"none": {},
			"dns": {
				PortProto{Port: 53, Proto: u8proto.UDP}: {identity.NumericIdentity(0): {}},
				PortProto{Port: 53, Proto: u8proto.TCP}: {identity.NumericIdentity(0): {}},
			},
		},
	}
	b := &namedPortMultiMap{
		m: map[string]PortProtoSet{
			"http": {
				PortProto{Port: 80, Proto: u8proto.TCP}:   {identity.NumericIdentity(0): {}},
				PortProto{Port: 8080, Proto: u8proto.TCP}: {identity.NumericIdentity(1): {}},
			},
			"https": {
				PortProto{Port: 443, Proto: u8proto.TCP}: {identity.NumericIdentity(0): {}},
			},
			"zero": {
				PortProto{Port: 0, Proto: u8proto.TCP}: {identity.NumericIdentity(0): {}},
			},
			"none": {},
			"dns": {
				PortProto{Port: 53, Proto: 0}: {identity.NumericIdentity(0): {}},
			},
		},
	}

	port, err := a.GetNamedPort("http", u8proto.TCP, map[identity.NumericIdentity]struct{}{identity.NumericIdentity(0): {}, identity.NumericIdentity(1): {}})
	require.Equal(t, ErrDuplicateNamedPorts, err)
	require.Equal(t, uint16(0), port)

	port, err = a.GetNamedPort("http", u8proto.UDP, id1)
	require.Equal(t, ErrIncompatibleProtocol, err)
	require.Equal(t, uint16(0), port)

	port, err = a.GetNamedPort("zero", u8proto.TCP, id0)
	require.Equal(t, ErrNamedPortIsZero, err)
	require.Equal(t, uint16(0), port)

	port, err = a.GetNamedPort("none", u8proto.TCP, id0)
	require.Equal(t, ErrUnknownNamedPort, err)
	require.Equal(t, uint16(0), port)

	port, err = a.GetNamedPort("unknown", u8proto.TCP, id0)
	require.Equal(t, ErrUnknownNamedPort, err)
	require.Equal(t, uint16(0), port)

	var nilvalued *namedPortMultiMap
	port, err = NamedPortMultiMap(nilvalued).GetNamedPort("unknown", u8proto.TCP, id0)
	require.Equal(t, ErrNilMap, err)
	require.Equal(t, uint16(0), port)

	port, err = a.GetNamedPort("https", u8proto.TCP, id0)
	require.NoError(t, err)
	require.Equal(t, uint16(443), port)

	port, err = a.GetNamedPort("dns", u8proto.TCP, id0)
	require.NoError(t, err)
	require.Equal(t, uint16(53), port)

	port, err = b.GetNamedPort("dns", u8proto.TCP, id0)
	require.NoError(t, err)
	require.Equal(t, uint16(53), port)

	port, err = a.GetNamedPort("dns", u8proto.UDP, id0)
	require.NoError(t, err)
	require.Equal(t, uint16(53), port)

	port, err = b.GetNamedPort("dns", u8proto.UDP, id0)
	require.NoError(t, err)
	require.Equal(t, uint16(53), port)
}

func TestPolicyNamedPortMultiMapUpdate(t *testing.T) {
	npm := NewNamedPortMultiMap()
	id1 := map[identity.NumericIdentity]struct{}{identity.NumericIdentity(1): {}}
	id2 := map[identity.NumericIdentity]struct{}{identity.NumericIdentity(2): {}}

	pod1PortsOld := map[string]PortProto{}
	pod1PortsNew := map[string]PortProto{
		"http": {u8proto.TCP, 80},
	}

	// Insert http=80/TCP from pod1
	changed := npm.Update(identity.NumericIdentity(1), pod1PortsOld, pod1PortsNew)
	require.True(t, changed)

	// No changes
	changed = npm.Update(identity.NumericIdentity(1), pod1PortsNew, pod1PortsNew)
	require.False(t, changed)

	// Assert http=80/TCP
	port, err := npm.GetNamedPort("http", u8proto.TCP, id1)
	require.NoError(t, err)
	require.Equal(t, uint16(80), port)

	pod2PortsOld := map[string]PortProto{}
	pod2PortsNew := map[string]PortProto{
		"http": {u8proto.UDP, 8080},
	}

	// Insert http=8080/UDP from pod2, retain http=80/TCP from pod1
	changed = npm.Update(identity.NumericIdentity(2), pod2PortsOld, pod2PortsNew)
	require.True(t, changed)

	port, err = npm.GetNamedPort("http", u8proto.TCP, id1)
	require.NoError(t, err)
	require.Equal(t, uint16(80), port)
	port, err = npm.GetNamedPort("http", u8proto.UDP, id2)
	require.NoError(t, err)
	require.Equal(t, uint16(8080), port)

	// Delete http=80/TCP from pod1, retain http=8080/UDP from pod2
	pod1PortsOld = pod1PortsNew
	pod1PortsNew = map[string]PortProto{}

	// Delete http=80/TCP from pod1
	changed = npm.Update(identity.NumericIdentity(1), pod1PortsOld, pod1PortsNew)
	require.True(t, changed)

	port, err = npm.GetNamedPort("http", u8proto.UDP, id2)
	require.NoError(t, err)
	require.Equal(t, uint16(8080), port)
}
