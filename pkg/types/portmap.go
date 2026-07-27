// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"errors"
	"fmt"
	"iter"
	"slices"
	"strings"

	"github.com/cilium/cilium/pkg/iana"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/u8proto"
)

var (
	ErrNilMap               = errors.New("nil map")
	ErrUnknownNamedPort     = errors.New("unknown named port")
	ErrIncompatibleProtocol = errors.New("incompatible protocol")
	ErrNamedPortIsZero      = errors.New("named port is zero")
	ErrDuplicateNamedPorts  = errors.New("duplicate named ports")
)

// PortProto is a pair of port number and protocol and is used as the
// value type in named port maps.
type PortProto struct {
	Proto u8proto.U8proto // concrete protocol; u8proto.ANY is invalid
	Port  uint16          // non-0
}

// NamedPortMap maps port names to port numbers and protocols.
type NamedPortMap map[string]PortProto

// portProtoSet maps numeric identity and protocol to the resolved port for one
// named port.
type portProtoSet map[nidProtoKey]namedPortRef

type nidProtoKey struct {
	nid   identity.NumericIdentity
	proto u8proto.U8proto
}

type namedPortRef struct {
	port uint16
	refs int

	// dupes links duplicate port definitions for the same name, numeric
	// identity, and protocol. This is expected only while a cluster transitions
	// between identity label schemes during upgrades or downgrades.
	dupes *namedPortRef
}

// Equal returns true if the PortProtoSets are equal.
func (pps portProtoSet) Equal(other portProtoSet) bool {
	if len(pps) != len(other) {
		return false
	}

	for key, ref := range pps {
		otherRef, exists := other[key]
		if !exists || !ref.Equal(otherRef) {
			return false
		}
	}
	return true
}

// Add increments the reference count for the numeric identity associated with the PortProto.
// Returns true if the named port mapping changed for the numeric identity.
func (pps portProtoSet) Add(pp PortProto, nid identity.NumericIdentity) bool {
	if pp.Port == 0 {
		return false
	}
	key := nidProtoKey{nid: nid, proto: pp.Proto}
	ref, ok := pps[key]
	if !ok {
		pps[key] = namedPortRef{port: pp.Port, refs: 1}
		return true
	}
	for cur := &ref; ; cur = cur.dupes {
		if cur.port == pp.Port {
			cur.refs++
			pps[key] = ref // update list head, as it may have changed
			return false
		}
		if cur.dupes == nil {
			cur.dupes = &namedPortRef{port: pp.Port, refs: 1}
			pps[key] = ref // update list head, as it may have changed
			return true
		}
	}
}

// Delete decrements the reference count for the numeric identity associated
// with the PortProto. Returns true if the set of ports for the numeric
// identity changed.
func (pps portProtoSet) Delete(pp PortProto, nid identity.NumericIdentity) bool {
	key := nidProtoKey{nid: nid, proto: pp.Proto}
	ref, ok := pps[key]
	if !ok {
		return false
	}

	var prev *namedPortRef
	for cur := &ref; cur != nil; prev, cur = cur, cur.dupes {
		if cur.port == pp.Port {
			if cur.refs > 1 {
				cur.refs--
				pps[key] = ref // update list head, as it may have changed
				return false
			}
			// refs became zero, unlink
			if prev != nil {
				prev.dupes = cur.dupes
				pps[key] = ref // update list head, as it may have changed
				return true
			}
			if cur.dupes != nil {
				ref = *cur.dupes
				pps[key] = ref // update list head, as it may have changed
				return true
			}
			// can't unlink the head; delete the map entry instead
			delete(pps, key)
			return true
		}
	}
	return false
}

// LookupPort returns the single usable port in the chain, or duplicate=true if
// the chain contains multiple distinct non-zero ports.
func (ref namedPortRef) LookupPort() (port uint16, ok, duplicate bool) {
	for cur := &ref; cur != nil; cur = cur.dupes {
		if port != 0 && port != cur.port {
			return 0, false, true
		}
		port = cur.port
	}
	return port, true, false
}

// Equal reports whether two namedPortRef chains have the same port/refcount
// sequence.
func (ref namedPortRef) Equal(other namedPortRef) bool {
	if ref.port != other.port || ref.refs != other.refs {
		return false
	}
	switch {
	case ref.dupes == nil && other.dupes == nil:
		return true
	case ref.dupes == nil || other.dupes == nil:
		return false
	default:
		return ref.dupes.Equal(*other.dupes)
	}
}

type NidPortSeq iter.Seq2[identity.NumericIdentity, uint16]

func EmptyNidPortSeq(func(identity.NumericIdentity, uint16) bool) {}

// NamedPortMultiMap may have multiple entries for a name if multiple PODs
// define the same name with different values.
type NamedPortMultiMap interface {
	// GetNamedPort returns the port number for the named port, if any. proto
	// must be a concrete protocol; u8proto.ANY does not match named ports.
	GetNamedPort(name string, proto u8proto.U8proto, nids iter.Seq[identity.NumericIdentity]) (uint16, error)

	// GetNamedPorts returns the port numbers for the named port, if any, by
	// numeric identity. proto must be a concrete protocol; u8proto.ANY does
	// not match named ports.
	GetNamedPorts(name string, proto u8proto.U8proto, nids iter.Seq[identity.NumericIdentity]) NidPortSeq

	// Len returns the number of named port/protocol mappings known.
	Len() int
}

func NewNamedPortMultiMap() *namedPortMultiMap {
	return &namedPortMultiMap{
		m: make(map[string]portProtoSet),
	}
}

// Implements NamedPortMultiMap and allows changes through Update. All accesses
// must be protected by its RW mutex.
type namedPortMultiMap struct {
	lock.RWMutex
	m map[string]portProtoSet
}

func (npm *namedPortMultiMap) Len() int {
	npm.RLock()
	defer npm.RUnlock()
	return len(npm.m)
}

// Update applies potential changes in named ports, and returns whether there were any.
func (npm *namedPortMultiMap) Update(nid identity.NumericIdentity, old, new NamedPortMap) (namedPortsChanged bool) {
	npm.Lock()
	defer npm.Unlock()

	// Handle removals: Ports in old but not in new, or changed.
	for name, oldPP := range old {
		newPP, exists := new[name]
		if !exists || oldPP != newPP {
			if pps, ok := npm.m[name]; ok {
				if pps.Delete(oldPP, nid) {
					namedPortsChanged = true
					if len(pps) == 0 {
						delete(npm.m, name)
					}
				}
			}
		}
	}

	// Handle additions: Ports in new but not in old, or changed.
	for name, newPP := range new {
		if newPP.Port == 0 || newPP.Proto == u8proto.ANY {
			continue
		}
		oldPP, exists := old[name]
		if !exists || newPP != oldPP {
			pps, ok := npm.m[name]
			if !ok {
				pps = make(portProtoSet)
				npm.m[name] = pps
			}
			if pps.Add(newPP, nid) {
				namedPortsChanged = true
			}
		}
	}
	return namedPortsChanged
}

// ValidatePortName checks that the port name conforms to the IANA Service Names spec
// and converts the port name to lower case for case-insensitive comparisons.
func ValidatePortName(name string) (string, error) {
	if !iana.IsSvcName(name) { // Port names are formatted as IANA Service Names
		return "", fmt.Errorf("Invalid port name \"%s\", not using as a named port", name)
	}
	return strings.ToLower(name), nil // Normalize for case-insensitive comparison
}

func newPortProto(port int, protocol string) (pp PortProto, err error) {
	var u8p u8proto.U8proto
	if protocol == "" {
		u8p = u8proto.TCP // K8s ContainerPort protocol defaults to TCP
	} else {
		var err error
		u8p, err = u8proto.ParseProtocol(protocol)
		if err != nil {
			return pp, err
		}
	}
	if u8p == u8proto.ANY {
		return pp, ErrIncompatibleProtocol
	}
	if port < 1 || port > 65535 {
		if port == 0 {
			return pp, ErrNamedPortIsZero
		}
		return pp, fmt.Errorf("Port number %d out of 16-bit range", port)
	}
	return PortProto{
		Proto: u8p,
		Port:  uint16(port),
	}, nil
}

// AddPort adds a new PortProto to the NamedPortMap
func (npm NamedPortMap) AddPort(name string, port int, protocol string) error {
	name, err := ValidatePortName(name)
	if err != nil {
		return err
	}
	pp, err := newPortProto(port, protocol)
	if err != nil {
		return err
	}
	npm[name] = pp
	return nil
}

// GetNamedPort returns the port number for the named port, if any. proto must
// be a concrete protocol; u8proto.ANY does not match named ports.
func (npm NamedPortMap) GetNamedPort(name string, proto u8proto.U8proto) (uint16, error) {
	if npm == nil {
		return 0, ErrNilMap
	}
	pp, ok := npm[name]
	if !ok {
		return 0, ErrUnknownNamedPort
	}
	if proto == u8proto.ANY || pp.Proto == u8proto.ANY || proto != pp.Proto {
		return 0, ErrIncompatibleProtocol
	}
	if pp.Port == 0 {
		return 0, ErrNamedPortIsZero
	}
	return pp.Port, nil
}

// GetNamedPort returns the port number for the named port, if any.
// Numeric identities that have no named port mapping are skipped.
// If the numeric identities resolve to different ports, ErrDuplicateNamedPorts is returned.
func (npm *namedPortMultiMap) GetNamedPort(name string, proto u8proto.U8proto, nids iter.Seq[identity.NumericIdentity]) (uint16, error) {
	if npm == nil {
		return 0, ErrNilMap
	}
	npm.RLock()
	defer npm.RUnlock()
	if npm.m == nil {
		return 0, ErrNilMap
	}
	if proto == u8proto.ANY {
		return 0, ErrIncompatibleProtocol
	}
	pps, ok := npm.m[name]
	if !ok {
		// Return an error the caller can filter out as this happens only for egress policy
		// and it is likely the destination POD with the port name is simply not scheduled yet.
		return 0, ErrUnknownNamedPort
	}
	// Find if there is a single port for the given identities.
	var result uint16
	for nid := range nids {
		port, ok, duplicate := pps.lookupNamedPort(proto, nid)
		if duplicate {
			return 0, ErrDuplicateNamedPorts
		}
		if !ok {
			continue
		}
		if result != 0 && result != port {
			return 0, ErrDuplicateNamedPorts
		}
		result = port
	}
	if result == 0 {
		return 0, ErrUnknownNamedPort
	}
	return result, nil
}

// GetNamedPorts returns an iterator to numeric identity / port number pairs for the given
// 'nids'. Numeric identities in "nids" are skipped in the output iterator if there is no named port
// mapping for that specific identity, or if there are more than one port defined for the identity.
// Note that this differs slightly from GetNamedPort that will return a port number if no more than
// one port is defined for all the given identities, even if some of the identities would not have
// any port defined for the name and protocol.
func (npm *namedPortMultiMap) GetNamedPorts(name string, proto u8proto.U8proto, nids iter.Seq[identity.NumericIdentity]) NidPortSeq {
	if npm == nil {
		return EmptyNidPortSeq
	}
	if proto == u8proto.ANY {
		return EmptyNidPortSeq
	}
	npm.RLock()
	defer npm.RUnlock()
	if npm.m == nil {
		return EmptyNidPortSeq
	}
	pps, ok := npm.m[name]
	if !ok {
		return EmptyNidPortSeq
	}
	var resultNIDs []identity.NumericIdentity
	var resultPorts []uint16
	for nid := range nids {
		port, ok, duplicate := pps.lookupNamedPort(proto, nid)
		if !ok || duplicate {
			continue
		}
		resultNIDs = append(resultNIDs, nid)
		resultPorts = append(resultPorts, port)
	}

	return func(yield func(identity.NumericIdentity, uint16) bool) {
		for i, nid := range resultNIDs {
			if !yield(nid, resultPorts[i]) {
				return
			}
		}
	}
}

func (s NidPortSeq) Ports() []uint16 {
	portSet := map[uint16]struct{}{}
	var port uint16
	for _, port = range s {
		portSet[port] = struct{}{}
	}
	if len(portSet) == 0 {
		return nil
	}
	if len(portSet) == 1 {
		return []uint16{port}
	}

	ports := make([]uint16, 0, len(portSet))
	for port := range portSet {
		ports = append(ports, port)
	}
	slices.Sort(ports)
	return ports
}

func (pps portProtoSet) lookupNamedPort(proto u8proto.U8proto, nid identity.NumericIdentity) (port uint16, ok, duplicate bool) {
	if nid == 0 {
		return 0, false, false
	}
	ref, ok := pps[nidProtoKey{nid: nid, proto: proto}]
	if !ok {
		return 0, false, false
	}
	return ref.LookupPort()
}
