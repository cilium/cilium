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
	require.Equal(t, ErrUnknownNamedPort, err)
	require.Equal(t, uint16(0), port)

	port, err = a.GetNamedPort("zero", u8proto.TCP, id0)
	require.Equal(t, ErrUnknownNamedPort, err)
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

func TestPolicyNamedPortMultiMapGetNamedPortIgnoresMissingNumericIdentity(t *testing.T) {
	nid1 := identity.NumericIdentity(1)
	npm := &namedPortMultiMap{
		m: map[string]PortProtoSet{
			"http": {
				PortProto{Port: 80, Proto: u8proto.TCP}: {nid1: 1},
			},
		},
	}

	port, err := npm.GetNamedPort("http", u8proto.TCP, slices.Values([]identity.NumericIdentity{nid1, 42}))
	require.NoError(t, err)
	require.Equal(t, uint16(80), port)
}

func TestPolicyNamedPortMultiMapGetNamedPortWildcardIdentity(t *testing.T) {
	nid0 := identity.NumericIdentity(0)
	nid1 := identity.NumericIdentity(1)
	nid2 := identity.NumericIdentity(2)
	npm := &namedPortMultiMap{
		m: map[string]PortProtoSet{
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
				PortProto{Port: 5353, Proto: u8proto.UDP}: {nid2: 1},
			},
			"zero": {
				PortProto{Port: 0, Proto: u8proto.TCP}: {nid1: 1},
			},
		},
	}

	port, err := npm.GetNamedPort("http", u8proto.TCP, slices.Values([]identity.NumericIdentity{nid0}))
	require.NoError(t, err)
	require.Equal(t, uint16(80), port)

	port, err = npm.GetNamedPort("multi", u8proto.TCP, slices.Values([]identity.NumericIdentity{nid0}))
	require.Equal(t, ErrDuplicateNamedPorts, err)
	require.Equal(t, uint16(0), port)

	port, err = npm.GetNamedPort("proto", u8proto.TCP, slices.Values([]identity.NumericIdentity{nid0}))
	require.NoError(t, err)
	require.Equal(t, uint16(53), port)

	port, err = npm.GetNamedPort("proto", u8proto.UDP, slices.Values([]identity.NumericIdentity{nid0}))
	require.Equal(t, ErrDuplicateNamedPorts, err)
	require.Equal(t, uint16(0), port)

	port, err = npm.GetNamedPort("zero", u8proto.TCP, slices.Values([]identity.NumericIdentity{nid0}))
	require.Equal(t, ErrUnknownNamedPort, err)
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
	a := &namedPortMultiMap{
		m: map[string]PortProtoSet{
			"http": {
				PortProto{Port: 80, Proto: u8proto.TCP}:   {nid1: 1},
				PortProto{Port: 8080, Proto: u8proto.TCP}: {nid2: 1},
			},
			"web": {
				PortProto{Port: 80, Proto: u8proto.TCP}: {nid1: 1},
			},
			"multi": {
				PortProto{Port: 80, Proto: u8proto.TCP}:  {nid1: 1},
				PortProto{Port: 443, Proto: u8proto.TCP}: {nid1: 1},
			},
			"multi2": {
				PortProto{Port: 443, Proto: u8proto.TCP}: {nid1: 1},
				PortProto{Port: 80, Proto: u8proto.TCP}:  {nid1: 1},
			},
			"https": {
				PortProto{Port: 443, Proto: u8proto.TCP}: {nid1: 1},
			},
			"zero": {
				PortProto{Port: 0, Proto: u8proto.TCP}: {nid1: 1},
			},
			"none": {},
			"dns": {
				PortProto{Port: 53, Proto: u8proto.UDP}: {nid1: 1},
				PortProto{Port: 53, Proto: u8proto.TCP}: {nid1: 1},
			},
		},
	}
	b := &namedPortMultiMap{
		m: map[string]PortProtoSet{
			"http": {
				PortProto{Port: 80, Proto: u8proto.TCP}:   {nid1: 1},
				PortProto{Port: 8080, Proto: u8proto.TCP}: {nid2: 1},
			},
			"https": {
				PortProto{Port: 443, Proto: u8proto.TCP}: {nid1: 1},
			},
			"zero": {
				PortProto{Port: 0, Proto: u8proto.TCP}: {nid1: 1},
			},
			"none": {},
			"dns": {
				PortProto{Port: 53, Proto: 0}: {nid1: 1},
			},
		},
	}

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
	cachedByNID, found := a.ports[namedPortCacheKey{name: "http", proto: u8proto.TCP}]
	require.True(t, found)
	cached, found := cachedByNID[42]
	require.True(t, found)
	require.Equal(t, zeroNamedPortSet, cached)

	ports = getNamedPorts(a, "web", u8proto.TCP, nid1)
	require.Equal(t, []uint16{80}, ports)
	require.Equal(t, a.ports[namedPortCacheKey{name: "http", proto: u8proto.TCP}][nid1], a.ports[namedPortCacheKey{name: "web", proto: u8proto.TCP}][nid1])

	ports = getNamedPorts(a, "multi", u8proto.TCP, nid1)
	require.Equal(t, []uint16{80, 443}, ports)
	ports = getNamedPorts(a, "multi2", u8proto.TCP, nid1)
	require.Equal(t, []uint16{80, 443}, ports)
	require.Equal(t, a.ports[namedPortCacheKey{name: "multi", proto: u8proto.TCP}][nid1], a.ports[namedPortCacheKey{name: "multi2", proto: u8proto.TCP}][nid1])

	ports = getNamedPorts(a, "http", u8proto.UDP, nid2)
	require.Nil(t, ports)

	ports = getNamedPorts(a, "zero", u8proto.TCP, nid1)
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
	require.Equal(t, []uint16{53}, ports)
}

func TestPolicyNamedPortMultiMapGetNamedPortsWildcardIdentity(t *testing.T) {
	nid0 := identity.NumericIdentity(0)
	nid1 := identity.NumericIdentity(1)
	nid2 := identity.NumericIdentity(2)
	nid3 := identity.NumericIdentity(3)
	npm := &namedPortMultiMap{
		m: map[string]PortProtoSet{
			"http": {
				PortProto{Port: 80, Proto: u8proto.TCP}:   {nid1: 1, nid3: 1},
				PortProto{Port: 8080, Proto: u8proto.TCP}: {nid2: 1},
				PortProto{Port: 53, Proto: u8proto.UDP}:   {nid2: 1},
				PortProto{Port: 0, Proto: u8proto.TCP}:    {nid1: 1},
			},
			"same": {
				PortProto{Port: 443, Proto: u8proto.TCP}: {nid1: 1, nid2: 1},
			},
		},
	}

	ports := getNamedPorts(npm, "http", u8proto.TCP, nid0)
	require.Equal(t, []uint16{80, 8080}, ports)
	ports = getNamedPorts(npm, "http", u8proto.UDP, nid0)
	require.Equal(t, []uint16{53}, ports)
	ports = getNamedPorts(npm, "same", u8proto.TCP, nid0)
	require.Equal(t, []uint16{443}, ports)

	portsByNID := map[identity.NumericIdentity][]uint16{}
	for resultNID, resultPort := range npm.GetNamedPorts("http", u8proto.TCP, slices.Values([]identity.NumericIdentity{nid0, nid1})) {
		portsByNID[resultNID] = append(portsByNID[resultNID], resultPort)
	}
	require.Equal(t, map[identity.NumericIdentity][]uint16{
		nid0: {80, 8080},
		nid1: {80},
	}, portsByNID)

	cachedByNID, found := npm.ports[namedPortCacheKey{name: "http", proto: u8proto.TCP}]
	require.True(t, found)
	require.NotEqual(t, zeroNamedPortSet, cachedByNID[nid0])
	require.NotEqual(t, zeroNamedPortSet, cachedByNID[nid1])
}

func TestPolicyNamedPortMultiMapGetNamedPortsWildcardIdentityUpdate(t *testing.T) {
	nid0 := identity.NumericIdentity(0)
	nid1 := identity.NumericIdentity(1)
	nid2 := identity.NumericIdentity(2)
	npm := NewNamedPortMultiMap()

	nid1Ports := NamedPortMap{"http": {Proto: u8proto.TCP, Port: 80}}
	nid2Ports := NamedPortMap{"http": {Proto: u8proto.TCP, Port: 8080}}
	require.True(t, npm.Update(nid1, nil, nid1Ports))
	require.True(t, npm.Update(nid2, nil, nid2Ports))

	ports := getNamedPorts(npm, "http", u8proto.TCP, nid0)
	require.Equal(t, []uint16{80, 8080}, ports)

	key := namedPortCacheKey{name: "http", proto: u8proto.TCP}
	cachedByNID, found := npm.ports[key]
	require.True(t, found)
	wildcardPortSet := cachedByNID[nid0]
	require.NotEqual(t, zeroNamedPortSet, wildcardPortSet)

	nid2UpdatedPorts := NamedPortMap{"http": {Proto: u8proto.TCP, Port: 9090}}
	require.True(t, npm.Update(nid2, nid2Ports, nid2UpdatedPorts))
	cachedByNID, found = npm.ports[key]
	if found {
		_, found = cachedByNID[nid0]
		require.False(t, found)
	}

	ports = getNamedPorts(npm, "http", u8proto.TCP, nid0)
	require.Equal(t, []uint16{80, 9090}, ports)
	require.NotEqual(t, wildcardPortSet, npm.ports[key][nid0])
}

func TestPolicyNamedPortMultiMapUpdate(t *testing.T) {
	npm := NewNamedPortMultiMap()
	nid1 := identity.NumericIdentity(1)
	nid2 := identity.NumericIdentity(2)
	nids1 := slices.Values([]identity.NumericIdentity{nid1})
	nids2 := slices.Values([]identity.NumericIdentity{nid2})

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

	// Insert 9090 from a peer with the same numeric identity
	peerPortsOld := map[string]PortProto{}
	peerPortsNew := map[string]PortProto{
		"http": {u8proto.TCP, 9090},
	}
	changed = npm.Update(nid1, peerPortsOld, peerPortsNew)
	require.True(t, changed)

	// Assert both are returned
	ports = getNamedPorts(npm, "http", u8proto.TCP, nid1)
	require.Equal(t, []uint16{80, 9090}, ports)

	// Insert http=8080/UDP from pod2 with nid2
	pod2PortsOld := map[string]PortProto{}
	pod2PortsNew := map[string]PortProto{
		"http": {u8proto.UDP, 8080},
	}
	changed = npm.Update(nid2, pod2PortsOld, pod2PortsNew)
	require.True(t, changed)

	ports = getNamedPorts(npm, "http", u8proto.TCP, nid1)
	require.Equal(t, []uint16{80, 9090}, ports)
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
}
