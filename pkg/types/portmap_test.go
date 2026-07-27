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

func testPortProtoSet(entries map[PortProto]map[identity.NumericIdentity]int) portProtoSet {
	pps := make(portProtoSet)
	for pp, nidCounts := range entries {
		for nid, count := range nidCounts {
			for range count {
				pps.Add(pp, nid)
			}
		}
	}
	return pps
}

func testNamedPortMultiMap(entries map[string]map[PortProto]map[identity.NumericIdentity]int) *namedPortMultiMap {
	npm := &namedPortMultiMap{m: map[string]portProtoSet{}}
	for name, portEntries := range entries {
		pps, ok := npm.m[name]
		if !ok {
			pps = make(portProtoSet)
			npm.m[name] = pps
		}
		for pp, nidCounts := range portEntries {
			for nid, count := range nidCounts {
				for range count {
					pps.Add(pp, nid)
				}
			}
		}
	}
	return npm
}

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

	_, err = newPortProto(80, "ANY")
	require.ErrorIs(t, err, ErrIncompatibleProtocol)

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

	err = npm.AddPort("any", 80, "ANY")
	require.ErrorIs(t, err, ErrIncompatibleProtocol)
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

	port, err = npm.GetNamedPort("dns", u8proto.ANY)
	require.Equal(t, ErrIncompatibleProtocol, err)
	require.Equal(t, uint16(0), port)

	npm["direct-any"] = PortProto{Port: 80, Proto: u8proto.ANY}
	port, err = npm.GetNamedPort("direct-any", u8proto.TCP)
	require.Equal(t, ErrIncompatibleProtocol, err)
	require.Equal(t, uint16(0), port)

	port, err = npm.GetNamedPort("unknown", proto)
	require.Equal(t, ErrUnknownNamedPort, err)
	require.Equal(t, uint16(0), port)
}

func TestPolicyPortProtoSet(t *testing.T) {
	a := testPortProtoSet(map[PortProto]map[identity.NumericIdentity]int{
		{Port: 80, Proto: u8proto.TCP}:  {identity.NumericIdentity(1): 1},
		{Port: 443, Proto: u8proto.TCP}: {identity.NumericIdentity(2): 1},
		{Port: 53, Proto: u8proto.TCP}:  {identity.NumericIdentity(3): 1},
	})
	b := testPortProtoSet(map[PortProto]map[identity.NumericIdentity]int{
		{Port: 80, Proto: u8proto.TCP}:  {identity.NumericIdentity(1): 1},
		{Port: 443, Proto: u8proto.TCP}: {identity.NumericIdentity(2): 1},
		{Port: 54, Proto: u8proto.TCP}:  {identity.NumericIdentity(3): 1},
	})
	require.True(t, a.Equal(a))
	require.False(t, a.Equal(b))
	require.True(t, b.Equal(b))

	// Test reference counting
	pps := make(portProtoSet)
	pp := PortProto{Port: 80, Proto: u8proto.TCP}
	id1 := identity.NumericIdentity(1)
	id2 := identity.NumericIdentity(2)

	// Zero-valued named ports are not stored in the multi-map.
	changed := pps.Add(PortProto{Port: 0, Proto: u8proto.TCP}, id1)
	require.False(t, changed)
	require.Empty(t, pps)

	// Add id1
	changed = pps.Add(pp, id1)
	require.True(t, changed)
	require.Equal(t, namedPortRef{port: pp.Port, refs: 1}, pps[nidProtoKey{nid: id1, proto: pp.Proto}])
	require.Len(t, pps, 1)

	// Add id1 again (should increment ref count for the same id)
	changed = pps.Add(pp, id1)
	require.False(t, changed)
	require.Equal(t, namedPortRef{port: pp.Port, refs: 2}, pps[nidProtoKey{nid: id1, proto: pp.Proto}])
	require.Len(t, pps, 1)

	// Add mismatching id1 port: keep it as a duplicate until one side is removed.
	ppConflict := PortProto{Port: 8080, Proto: u8proto.TCP}
	changed = pps.Add(ppConflict, id1)
	require.True(t, changed)
	ref := pps[nidProtoKey{nid: id1, proto: pp.Proto}]
	require.Equal(t, namedPortRef{port: pp.Port, refs: 2, dupes: &namedPortRef{port: ppConflict.Port, refs: 1}}, ref)
	require.Len(t, pps, 1)

	changed = pps.Add(ppConflict, id1)
	require.False(t, changed)
	ref = pps[nidProtoKey{nid: id1, proto: pp.Proto}]
	require.Equal(t, namedPortRef{port: pp.Port, refs: 2, dupes: &namedPortRef{port: ppConflict.Port, refs: 2}}, ref)
	require.Len(t, pps, 1)

	// Add id2
	changed = pps.Add(pp, id2)
	require.True(t, changed)
	ref = pps[nidProtoKey{nid: id1, proto: pp.Proto}]
	require.Equal(t, namedPortRef{port: pp.Port, refs: 2, dupes: &namedPortRef{port: ppConflict.Port, refs: 2}}, ref)
	require.Equal(t, namedPortRef{port: pp.Port, refs: 1}, pps[nidProtoKey{nid: id2, proto: pp.Proto}])
	require.Len(t, pps, 2)

	// Remove id1
	changed = pps.Delete(pp, id1)
	require.False(t, changed)
	ref = pps[nidProtoKey{nid: id1, proto: pp.Proto}]
	require.Equal(t, namedPortRef{port: pp.Port, refs: 1, dupes: &namedPortRef{port: ppConflict.Port, refs: 2}}, ref)
	require.Equal(t, namedPortRef{port: pp.Port, refs: 1}, pps[nidProtoKey{nid: id2, proto: pp.Proto}])
	require.Len(t, pps, 2)

	// Delete the mismatching id1 port once: the duplicate still has a ref.
	changed = pps.Delete(ppConflict, id1)
	require.False(t, changed)
	ref = pps[nidProtoKey{nid: id1, proto: pp.Proto}]
	require.Equal(t, namedPortRef{port: pp.Port, refs: 1, dupes: &namedPortRef{port: ppConflict.Port, refs: 1}}, ref)
	require.Equal(t, namedPortRef{port: pp.Port, refs: 1}, pps[nidProtoKey{nid: id2, proto: pp.Proto}])
	require.Len(t, pps, 2)

	// Delete the mismatching id1 port again: the duplicate is removed.
	changed = pps.Delete(ppConflict, id1)
	require.True(t, changed)
	require.Equal(t, namedPortRef{port: pp.Port, refs: 1}, pps[nidProtoKey{nid: id1, proto: pp.Proto}])
	require.Equal(t, namedPortRef{port: pp.Port, refs: 1}, pps[nidProtoKey{nid: id2, proto: pp.Proto}])
	require.Len(t, pps, 2)

	// Remove id2
	changed = pps.Delete(pp, id2)
	require.True(t, changed)
	require.Equal(t, namedPortRef{port: pp.Port, refs: 1}, pps[nidProtoKey{nid: id1, proto: pp.Proto}])
	require.NotContains(t, pps, nidProtoKey{nid: id2, proto: pp.Proto})
	require.Len(t, pps, 1)

	// Remove id1 again — last identity, so the PortProtoSet is cleaned up
	changed = pps.Delete(pp, id1)
	require.True(t, changed)
	require.Empty(t, pps)

	// Test removing non-existent id from existing PortProto
	changed = pps.Add(pp, id1)
	require.True(t, changed)
	changed = pps.Delete(pp, id2)
	require.False(t, changed)
	require.Equal(t, namedPortRef{port: pp.Port, refs: 1}, pps[nidProtoKey{nid: id1, proto: pp.Proto}])
	require.Len(t, pps, 1)

	// Test removing from non-existent PortProto
	pp2 := PortProto{Port: 443, Proto: u8proto.UDP}
	changed = pps.Delete(pp2, id1)
	require.False(t, changed)
}

func TestPolicyNamedPortMultiMap(t *testing.T) {
	id0 := slices.Values([]identity.NumericIdentity{0})
	id1 := slices.Values([]identity.NumericIdentity{1})
	id2 := slices.Values([]identity.NumericIdentity{2})
	a := testNamedPortMultiMap(map[string]map[PortProto]map[identity.NumericIdentity]int{
		"http": {
			PortProto{Port: 80, Proto: u8proto.TCP}:   {identity.NumericIdentity(1): 1},
			PortProto{Port: 8080, Proto: u8proto.TCP}: {identity.NumericIdentity(2): 1},
		},
		"https": {
			PortProto{Port: 443, Proto: u8proto.TCP}: {identity.NumericIdentity(1): 1},
		},
		"none": {},
		"dns": {
			PortProto{Port: 53, Proto: u8proto.UDP}: {identity.NumericIdentity(1): 1},
			PortProto{Port: 53, Proto: u8proto.TCP}: {identity.NumericIdentity(1): 1},
		},
	})
	b := testNamedPortMultiMap(map[string]map[PortProto]map[identity.NumericIdentity]int{
		"http": {
			PortProto{Port: 80, Proto: u8proto.TCP}:   {identity.NumericIdentity(1): 1},
			PortProto{Port: 8080, Proto: u8proto.TCP}: {identity.NumericIdentity(2): 1},
		},
		"https": {
			PortProto{Port: 443, Proto: u8proto.TCP}: {identity.NumericIdentity(1): 1},
		},
		"none": {},
		"dns": {
			PortProto{Port: 53, Proto: u8proto.TCP}: {identity.NumericIdentity(1): 1},
		},
	})

	port, err := a.GetNamedPort("http", u8proto.TCP, slices.Values([]identity.NumericIdentity{1, 2}))
	require.Equal(t, ErrDuplicateNamedPorts, err)
	require.Equal(t, uint16(0), port)

	port, err = a.GetNamedPort("http", u8proto.UDP, id1)
	require.Equal(t, ErrUnknownNamedPort, err)
	require.Equal(t, uint16(0), port)

	port, err = a.GetNamedPort("http", u8proto.ANY, id1)
	require.Equal(t, ErrIncompatibleProtocol, err)
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

	port, err = a.GetNamedPort("https", u8proto.TCP, id1)
	require.NoError(t, err)
	require.Equal(t, uint16(443), port)

	port, err = a.GetNamedPort("dns", u8proto.TCP, id1)
	require.NoError(t, err)
	require.Equal(t, uint16(53), port)

	port, err = b.GetNamedPort("dns", u8proto.TCP, id1)
	require.NoError(t, err)
	require.Equal(t, uint16(53), port)

	port, err = a.GetNamedPort("dns", u8proto.UDP, id1)
	require.NoError(t, err)
	require.Equal(t, uint16(53), port)

	port, err = b.GetNamedPort("dns", u8proto.UDP, id1)
	require.Equal(t, ErrUnknownNamedPort, err)
	require.Equal(t, uint16(0), port)

	port, err = a.GetNamedPort("http", u8proto.TCP, id2)
	require.NoError(t, err)
	require.Equal(t, uint16(8080), port)
}

func TestPolicyNamedPortMultiMapGetNamedPortIgnoresMissingNumericIdentity(t *testing.T) {
	nid1 := identity.NumericIdentity(1)
	npm := testNamedPortMultiMap(map[string]map[PortProto]map[identity.NumericIdentity]int{
		"http": {
			PortProto{Port: 80, Proto: u8proto.TCP}: {nid1: 1},
		},
	})

	port, err := npm.GetNamedPort("http", u8proto.TCP, slices.Values([]identity.NumericIdentity{nid1, 42}))
	require.NoError(t, err)
	require.Equal(t, uint16(80), port)
}

func TestPolicyNamedPortMultiMapGetNamedPortWildcardIdentity(t *testing.T) {
	nid0 := identity.NumericIdentity(0)
	nid1 := identity.NumericIdentity(1)
	nid2 := identity.NumericIdentity(2)
	nid3 := identity.NumericIdentity(3)
	npm := testNamedPortMultiMap(map[string]map[PortProto]map[identity.NumericIdentity]int{
		"http": {
			PortProto{Port: 80, Proto: u8proto.TCP}: {nid1: 1, nid2: 1},
		},
		"multi": {
			PortProto{Port: 80, Proto: u8proto.TCP}:   {nid1: 1},
			PortProto{Port: 8080, Proto: u8proto.TCP}: {nid2: 1},
		},
		"proto": {
			PortProto{Port: 53, Proto: u8proto.TCP}:   {nid1: 1},
			PortProto{Port: 53, Proto: u8proto.UDP}:   {nid2: 1},
			PortProto{Port: 5353, Proto: u8proto.UDP}: {nid3: 1},
		},
	})

	port, err := npm.GetNamedPort("http", u8proto.TCP, slices.Values([]identity.NumericIdentity{nid0}))
	require.Equal(t, ErrUnknownNamedPort, err)
	require.Equal(t, uint16(0), port)

	port, err = npm.GetNamedPort("multi", u8proto.TCP, slices.Values([]identity.NumericIdentity{nid0}))
	require.Equal(t, ErrUnknownNamedPort, err)
	require.Equal(t, uint16(0), port)

	port, err = npm.GetNamedPort("proto", u8proto.TCP, slices.Values([]identity.NumericIdentity{nid0}))
	require.Equal(t, ErrUnknownNamedPort, err)
	require.Equal(t, uint16(0), port)

	port, err = npm.GetNamedPort("proto", u8proto.UDP, slices.Values([]identity.NumericIdentity{nid0}))
	require.Equal(t, ErrUnknownNamedPort, err)
	require.Equal(t, uint16(0), port)

	port, err = npm.GetNamedPort("http", u8proto.TCP, slices.Values([]identity.NumericIdentity{nid0, nid1}))
	require.NoError(t, err)
	require.Equal(t, uint16(80), port)

	port, err = npm.GetNamedPort("multi", u8proto.TCP, slices.Values([]identity.NumericIdentity{nid1, nid2}))
	require.Equal(t, ErrDuplicateNamedPorts, err)
	require.Equal(t, uint16(0), port)
}

func getNamedPorts(npm NamedPortMultiMap, name string, proto u8proto.U8proto, nid identity.NumericIdentity) []uint16 {
	var result []uint16
	for resultNID, port := range npm.GetNamedPorts(name, proto, slices.Values([]identity.NumericIdentity{nid})) {
		if resultNID == nid {
			result = append(result, port)
		}
	}
	return result
}

func TestPolicyNamedPortMultiMapGetNamedPorts(t *testing.T) {
	nid1 := identity.NumericIdentity(1)
	nid2 := identity.NumericIdentity(2)
	a := testNamedPortMultiMap(map[string]map[PortProto]map[identity.NumericIdentity]int{
		"http": {
			PortProto{Port: 80, Proto: u8proto.TCP}:   {nid1: 1},
			PortProto{Port: 8080, Proto: u8proto.TCP}: {nid2: 1},
		},
		"web": {
			PortProto{Port: 80, Proto: u8proto.TCP}: {nid1: 1},
		},
		"https": {
			PortProto{Port: 443, Proto: u8proto.TCP}: {nid1: 1},
		},
		"none": {},
		"dns": {
			PortProto{Port: 53, Proto: u8proto.UDP}: {nid1: 1},
			PortProto{Port: 53, Proto: u8proto.TCP}: {nid1: 1},
		},
	})
	b := testNamedPortMultiMap(map[string]map[PortProto]map[identity.NumericIdentity]int{
		"http": {
			PortProto{Port: 80, Proto: u8proto.TCP}:   {nid1: 1},
			PortProto{Port: 8080, Proto: u8proto.TCP}: {nid2: 1},
		},
		"https": {
			PortProto{Port: 443, Proto: u8proto.TCP}: {nid1: 1},
		},
		"none": {},
		"dns": {
			PortProto{Port: 53, Proto: u8proto.TCP}: {nid1: 1},
		},
	})

	ports := getNamedPorts(a, "http", u8proto.TCP, nid1)
	require.Equal(t, []uint16{80}, ports)
	ports = getNamedPorts(a, "http", u8proto.TCP, nid2)
	require.Equal(t, []uint16{8080}, ports)

	portsByNID := map[identity.NumericIdentity][]uint16{}
	for resultNID, resultPort := range a.GetNamedPorts("http", u8proto.TCP, slices.Values([]identity.NumericIdentity{nid1, 42, nid2})) {
		portsByNID[resultNID] = append(portsByNID[resultNID], resultPort)
	}
	require.Equal(t, map[identity.NumericIdentity][]uint16{
		nid1: {80},
		nid2: {8080},
	}, portsByNID)

	ports = getNamedPorts(a, "web", u8proto.TCP, nid1)
	require.Equal(t, []uint16{80}, ports)

	ports = getNamedPorts(a, "http", u8proto.UDP, nid2)
	require.Nil(t, ports)

	ports = getNamedPorts(a, "http", u8proto.ANY, nid1)
	require.Nil(t, ports)

	ports = getNamedPorts(a, "none", u8proto.TCP, nid1)
	require.Nil(t, ports)

	ports = getNamedPorts(a, "unknown", u8proto.TCP, nid1)
	require.Nil(t, ports)

	var nilvalued *namedPortMultiMap
	ports = getNamedPorts(NamedPortMultiMap(nilvalued), "unknown", u8proto.TCP, nid1)
	require.Nil(t, ports)

	ports = getNamedPorts(a, "https", u8proto.TCP, nid1)
	require.Equal(t, []uint16{443}, ports)

	ports = getNamedPorts(a, "dns", u8proto.TCP, nid1)
	require.Equal(t, []uint16{53}, ports)

	ports = getNamedPorts(b, "dns", u8proto.TCP, nid1)
	require.Equal(t, []uint16{53}, ports)

	ports = getNamedPorts(a, "dns", u8proto.UDP, nid1)
	require.Equal(t, []uint16{53}, ports)

	ports = getNamedPorts(b, "dns", u8proto.UDP, nid1)
	require.Nil(t, ports)
}

func TestPolicyNamedPortMultiMapGetNamedPortsWildcardIdentity(t *testing.T) {
	nid0 := identity.NumericIdentity(0)
	nid1 := identity.NumericIdentity(1)
	nid2 := identity.NumericIdentity(2)
	nid3 := identity.NumericIdentity(3)
	npm := testNamedPortMultiMap(map[string]map[PortProto]map[identity.NumericIdentity]int{
		"http": {
			PortProto{Port: 80, Proto: u8proto.TCP}:   {nid1: 1, nid3: 1},
			PortProto{Port: 8080, Proto: u8proto.TCP}: {nid2: 1},
			PortProto{Port: 53, Proto: u8proto.UDP}:   {nid2: 1},
		},
		"same": {
			PortProto{Port: 443, Proto: u8proto.TCP}: {nid1: 1, nid2: 1},
		},
	})

	ports := getNamedPorts(npm, "http", u8proto.TCP, nid0)
	require.Nil(t, ports)
	ports = getNamedPorts(npm, "http", u8proto.UDP, nid0)
	require.Nil(t, ports)
	ports = getNamedPorts(npm, "same", u8proto.TCP, nid0)
	require.Nil(t, ports)

	portsByNID := map[identity.NumericIdentity][]uint16{}
	for resultNID, resultPort := range npm.GetNamedPorts("http", u8proto.TCP, slices.Values([]identity.NumericIdentity{nid0, nid1})) {
		portsByNID[resultNID] = append(portsByNID[resultNID], resultPort)
	}
	require.Equal(t, map[identity.NumericIdentity][]uint16{
		nid1: {80},
	}, portsByNID)
}

func TestPolicyNamedPortMultiMapUpdate(t *testing.T) {
	npm := NewNamedPortMultiMap()
	nid1 := identity.NumericIdentity(1)
	nid2 := identity.NumericIdentity(2)
	nids1 := slices.Values([]identity.NumericIdentity{nid1})
	nids2 := slices.Values([]identity.NumericIdentity{nid2})

	zeroPortsOld := map[string]PortProto{}
	zeroPortsNew := map[string]PortProto{
		"zero": {u8proto.TCP, 0},
	}
	changed := npm.Update(nid1, zeroPortsOld, zeroPortsNew)
	require.False(t, changed)
	require.Equal(t, 0, npm.Len())

	anyPortsNew := map[string]PortProto{
		"any": {u8proto.ANY, 80},
	}
	changed = npm.Update(nid1, nil, anyPortsNew)
	require.False(t, changed)
	require.Equal(t, 0, npm.Len())

	// Insert http=80/TCP from pod1 with nid1
	pod1PortsOld := map[string]PortProto{}
	pod1PortsNew := map[string]PortProto{
		"http": {u8proto.TCP, 80},
	}
	changed = npm.Update(nid1, pod1PortsOld, pod1PortsNew)
	require.True(t, changed)

	// No changes
	changed = npm.Update(nid1, pod1PortsNew, pod1PortsNew)
	require.False(t, changed)

	// Assert http=80/TCP
	port, err := npm.GetNamedPort("http", u8proto.TCP, nids1)
	require.NoError(t, err)
	require.Equal(t, uint16(80), port)

	// Insert http=8080/UDP from pod2 with nid2
	pod2PortsOld := map[string]PortProto{}
	pod2PortsNew := map[string]PortProto{
		"http": {u8proto.UDP, 8080},
	}
	changed = npm.Update(nid2, pod2PortsOld, pod2PortsNew)
	require.True(t, changed)

	port, err = npm.GetNamedPort("http", u8proto.TCP, nids1)
	require.NoError(t, err)
	require.Equal(t, uint16(80), port)
	port, err = npm.GetNamedPort("http", u8proto.UDP, nids2)
	require.NoError(t, err)
	require.Equal(t, uint16(8080), port)

	// Delete http=80/TCP from pod1, retain http=8080/UDP from pod2
	pod1PortsOld = pod1PortsNew
	pod1PortsNew = map[string]PortProto{}

	// Delete http=80/TCP from pod1
	changed = npm.Update(nid1, pod1PortsOld, pod1PortsNew)
	require.True(t, changed)

	port, err = npm.GetNamedPort("http", u8proto.UDP, nids2)
	require.NoError(t, err)
	require.Equal(t, uint16(8080), port)
}

func TestPolicyNamedPortMultiMapGetNamedPortsUpdate(t *testing.T) {
	npm := NewNamedPortMultiMap()
	nid1 := identity.NumericIdentity(1)
	nid2 := identity.NumericIdentity(2)

	// Insert http=80/TCP from pod1 with nid1
	pod1PortsOld := map[string]PortProto{}
	pod1PortsNew := map[string]PortProto{
		"http": {u8proto.TCP, 80},
	}
	changed := npm.Update(nid1, pod1PortsOld, pod1PortsNew)
	require.True(t, changed)

	// No changes
	changed = npm.Update(nid1, pod1PortsNew, pod1PortsNew)
	require.False(t, changed)

	// Assert http=80/TCP
	ports := getNamedPorts(npm, "http", u8proto.TCP, nid1)
	require.Equal(t, []uint16{80}, ports)

	// Insert 9090 from a peer with the same numeric identity. This is a
	// duplicate until one of the mappings is removed.
	peerPortsOld := map[string]PortProto{}
	peerPortsNew := map[string]PortProto{
		"http": {u8proto.TCP, 9090},
	}
	changed = npm.Update(nid1, peerPortsOld, peerPortsNew)
	require.True(t, changed)

	port, err := npm.GetNamedPort("http", u8proto.TCP, slices.Values([]identity.NumericIdentity{nid1}))
	require.Equal(t, ErrDuplicateNamedPorts, err)
	require.Equal(t, uint16(0), port)

	ports = getNamedPorts(npm, "http", u8proto.TCP, nid1)
	require.Nil(t, ports)

	// Insert http=8080/UDP from pod2 with nid2
	pod2PortsOld := map[string]PortProto{}
	pod2PortsNew := map[string]PortProto{
		"http": {u8proto.UDP, 8080},
	}
	changed = npm.Update(nid2, pod2PortsOld, pod2PortsNew)
	require.True(t, changed)

	ports = getNamedPorts(npm, "http", u8proto.TCP, nid1)
	require.Nil(t, ports)
	ports = getNamedPorts(npm, "http", u8proto.UDP, nid2)
	require.Equal(t, []uint16{8080}, ports)

	// Delete http=80/TCP from pod1
	pod1PortsOld = pod1PortsNew
	pod1PortsNew = map[string]PortProto{}
	changed = npm.Update(nid1, pod1PortsOld, pod1PortsNew)
	require.True(t, changed)

	ports = getNamedPorts(npm, "http", u8proto.UDP, nid2)
	require.Equal(t, []uint16{8080}, ports)
	ports = getNamedPorts(npm, "http", u8proto.TCP, nid1)
	require.Equal(t, []uint16{9090}, ports)

	changed = npm.Update(nid1, peerPortsNew, nil)
	require.True(t, changed)
}
