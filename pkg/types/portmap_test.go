// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"slices"
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
		PortProto{Port: 80, Proto: u8proto.TCP}:  {identity.NumericIdentity(0): 1},
		PortProto{Port: 443, Proto: u8proto.TCP}: {identity.NumericIdentity(0): 1},
		PortProto{Port: 53, Proto: u8proto.UDP}:  {identity.NumericIdentity(0): 1},
	}
	b := PortProtoSet{
		PortProto{Port: 80, Proto: u8proto.TCP}:  {identity.NumericIdentity(0): 1},
		PortProto{Port: 443, Proto: u8proto.TCP}: {identity.NumericIdentity(0): 1},
		PortProto{Port: 53, Proto: u8proto.TCP}:  {identity.NumericIdentity(0): 1},
	}
	require.True(t, a.Equal(a))
	require.False(t, a.Equal(b))
	require.True(t, b.Equal(b))

	// Test reference counting
	pps := make(PortProtoSet)
	pp := PortProto{Port: 80, Proto: u8proto.TCP}
	id1 := identity.NumericIdentity(1)
	id2 := identity.NumericIdentity(2)

	// Add id1
	require.True(t, pps.Add(pp, id1))
	require.Equal(t, 1, pps[pp][id1])
	require.Len(t, pps[pp], 1)

	// Add id1 again (should increment ref count for the same id)
	require.False(t, pps.Add(pp, id1))
	require.Equal(t, 2, pps[pp][id1])
	require.Len(t, pps[pp], 1)

	// Add id2
	require.True(t, pps.Add(pp, id2))
	require.Equal(t, 2, pps[pp][id1])
	require.Equal(t, 1, pps[pp][id2])
	require.Len(t, pps[pp], 2)

	// Remove id1
	require.False(t, pps.Delete(pp, id1))
	require.Equal(t, 1, pps[pp][id1])
	require.Equal(t, 1, pps[pp][id2])
	require.Len(t, pps[pp], 2)

	// Remove id2
	require.True(t, pps.Delete(pp, id2))
	require.Equal(t, 1, pps[pp][id1])
	require.Equal(t, 0, pps[pp][id2])
	require.Len(t, pps[pp], 1)

	// Remove id1 again — last identity, so the PortProto entry is cleaned up
	require.True(t, pps.Delete(pp, id1))
	require.Nil(t, pps[pp]) // entire PortProto entry removed
	require.Empty(t, pps)

	// Test removing non-existent id from existing PortProto
	require.True(t, pps.Add(pp, id1))
	require.True(t, pps.Delete(pp, id2))
	require.Equal(t, 1, pps[pp][id1])
	require.Len(t, pps[pp], 1)

	// Test removing from non-existent PortProto
	pp2 := PortProto{Port: 443, Proto: u8proto.TCP}
	require.False(t, pps.Delete(pp2, id1))
}

func TestPolicyNamedPortMultiMap(t *testing.T) {
	id0 := slices.Values([]identity.NumericIdentity{0})
	id1 := slices.Values([]identity.NumericIdentity{1})
	a := &namedPortMultiMap{
		m: map[string]PortProtoSet{
			"http": {
				PortProto{Port: 80, Proto: u8proto.TCP}:   {identity.NumericIdentity(0): 1},
				PortProto{Port: 8080, Proto: u8proto.TCP}: {identity.NumericIdentity(1): 1},
			},
			"https": {
				PortProto{Port: 443, Proto: u8proto.TCP}: {identity.NumericIdentity(0): 1},
			},
			"zero": {
				PortProto{Port: 0, Proto: u8proto.TCP}: {identity.NumericIdentity(0): 1},
			},
			"none": {},
			"dns": {
				PortProto{Port: 53, Proto: u8proto.UDP}: {identity.NumericIdentity(0): 1},
				PortProto{Port: 53, Proto: u8proto.TCP}: {identity.NumericIdentity(0): 1},
			},
		},
	}
	b := &namedPortMultiMap{
		m: map[string]PortProtoSet{
			"http": {
				PortProto{Port: 80, Proto: u8proto.TCP}:   {identity.NumericIdentity(0): 1},
				PortProto{Port: 8080, Proto: u8proto.TCP}: {identity.NumericIdentity(1): 1},
			},
			"https": {
				PortProto{Port: 443, Proto: u8proto.TCP}: {identity.NumericIdentity(0): 1},
			},
			"zero": {
				PortProto{Port: 0, Proto: u8proto.TCP}: {identity.NumericIdentity(0): 1},
			},
			"none": {},
			"dns": {
				PortProto{Port: 53, Proto: 0}: {identity.NumericIdentity(0): 1},
			},
		},
	}

	port, err := a.GetNamedPort("http", u8proto.TCP, slices.Values([]identity.NumericIdentity{0, 1}))
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
	id1 := slices.Values([]identity.NumericIdentity{1})
	id2 := slices.Values([]identity.NumericIdentity{2})

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
