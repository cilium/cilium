// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"encoding/binary"
	"errors"
	"fmt"
	"iter"
	"slices"
	"strings"
	"unique"
	"unsafe"

	"github.com/cilium/cilium/pkg/counter"
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
	Proto u8proto.U8proto // 0 for any
	Port  uint16          // non-0
}

// NamedPortMap maps port names to port numbers and protocols.
type NamedPortMap map[string]PortProto

// PortProtoSet maps PortProto to a map of numeric identities to their reference counts.
type PortProtoSet map[PortProto]map[identity.NumericIdentity]int

// Equal returns true if the PortProtoSets are equal.
func (pps PortProtoSet) Equal(other PortProtoSet) bool {
	if len(pps) != len(other) {
		return false
	}

	for pp, epCounts := range pps {
		otherEpCounts, exists := other[pp]
		if !exists || len(epCounts) != len(otherEpCounts) {
			return false
		}
		for nid, count := range epCounts {
			otherCount, epExists := otherEpCounts[nid]
			if !epExists || count != otherCount {
				return false
			}
		}
	}
	return true
}

// Add increments the reference count for the numeric identity associated with the PortProto.
// Returns true if the numeric identity was not previously in the map (count was 0).
func (pps PortProtoSet) Add(pp PortProto, nid identity.NumericIdentity) bool {
	epCounts, ok := pps[pp]
	if !ok {
		epCounts = make(map[identity.NumericIdentity]int)
		pps[pp] = epCounts
	}
	return counter.Counter[identity.NumericIdentity](epCounts).Add(nid)
}

// Delete decrements the reference count for the numeric identity associated with the PortProto.
// It returns true if the numeric identity was deleted.
func (pps PortProtoSet) Delete(pp PortProto, nid identity.NumericIdentity) bool {
	epCounts, ok := pps[pp]
	if !ok {
		return false
	}
	deleted := counter.Counter[identity.NumericIdentity](epCounts).Delete(nid)
	if deleted && len(epCounts) == 0 {
		delete(pps, pp)
	}
	return deleted
}

type NidPortSeq iter.Seq2[identity.NumericIdentity, uint16]

func emptyNidPortSeq(func(identity.NumericIdentity, uint16) bool) {}

// NamedPortMultiMap may have multiple entries for a name if multiple PODs
// define the same name with different values.
type NamedPortMultiMap interface {
	// GetNamedPort returns the port number for the named port, if any.
	// Wildcard identity gets the named port defined for any other identity.
	GetNamedPort(name string, proto u8proto.U8proto, nids iter.Seq[identity.NumericIdentity]) (uint16, error)

	// GetNamedPorts returns the port numbers for the named port, if any, by
	// numeric identity.
	// Wildcard identity gets the named ports defined for all other identities.
	GetNamedPorts(name string, proto u8proto.U8proto, nids iter.Seq[identity.NumericIdentity]) NidPortSeq

	// Len returns the number of Name->PortProtoSet mappings known.
	Len() int
}

func NewNamedPortMultiMap() *namedPortMultiMap {
	return &namedPortMultiMap{
		m:     make(map[string]PortProtoSet),
		ports: make(map[namedPortCacheKey]map[identity.NumericIdentity]unique.Handle[namedPortSet]),
	}
}

// Implements NamedPortMultiMap and allows changes through Update. All accesses
// must be protected by its RW mutex.
type namedPortMultiMap struct {
	lock.RWMutex
	m map[string]PortProtoSet
	// ports caches the port set by numeric identity, nid 0 caches ports for all identities.
	ports map[namedPortCacheKey]map[identity.NumericIdentity]unique.Handle[namedPortSet]
}

type namedPortCacheKey struct {
	name  string
	proto u8proto.U8proto
}

// namedPortSet is an interned, sorted, deduplicated set of uint16 ports encoded
// as native-endian bytes. It must only be constructed from sorted []uint16 via
// makeNamedPortSet(), and its bytes must be treated as immutable.
type namedPortSet string

var zeroNamedPortSet unique.Handle[namedPortSet]

func (npm *namedPortMultiMap) Len() int {
	npm.RLock()
	defer npm.RUnlock()
	return len(npm.m)
}

// Update applies potential changes in named ports, and returns whether there were any.
func (npm *namedPortMultiMap) Update(nid identity.NumericIdentity, old, new NamedPortMap) (namedPortsChanged bool) {
	npm.Lock()
	defer npm.Unlock()

	touchedNames := map[string]struct{}{}

	// Handle removals: Ports in old but not in new, or changed.
	for name, oldPP := range old {
		newPP, exists := new[name]
		if !exists || oldPP != newPP {
			if pps, ok := npm.m[name]; ok {
				if deleted := pps.Delete(oldPP, nid); deleted {
					namedPortsChanged = true
					touchedNames[name] = struct{}{}
				}
			}
		}
	}

	// Clean up empty PortProtoSets from the main map
	for name, pps := range npm.m {
		if len(pps) == 0 {
			delete(npm.m, name)
		}
	}

	// Handle additions: Ports in new but not in old, or changed.
	for name, newPP := range new {
		oldPP, exists := old[name]
		if !exists || newPP != oldPP {
			pps, ok := npm.m[name]
			if !ok {
				pps = make(PortProtoSet)
				npm.m[name] = pps
			}
			if pps.Add(newPP, nid) {
				namedPortsChanged = true
				touchedNames[name] = struct{}{}
			}
		}
	}
	for name := range touchedNames {
		npm.invalidateNamedPorts(name, nid)
	}
	return namedPortsChanged
}

// invalidateNamedPorts invalidates cached portsets for the given identity and the wildcard identity
func (npm *namedPortMultiMap) invalidateNamedPorts(name string, nid identity.NumericIdentity) {
	for key, byNID := range npm.ports {
		if key.name == name {
			delete(byNID, 0)
			delete(byNID, nid)
			if len(byNID) == 0 {
				delete(npm.ports, key)
			}
		}
	}
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

// GetNamedPort returns the port number for the named port, if any.
func (npm NamedPortMap) GetNamedPort(name string, proto u8proto.U8proto) (uint16, error) {
	if npm == nil {
		return 0, ErrNilMap
	}
	pp, ok := npm[name]
	if !ok {
		return 0, ErrUnknownNamedPort
	}
	if pp.Proto != 0 && proto != pp.Proto {
		return 0, ErrIncompatibleProtocol
	}
	if pp.Port == 0 {
		return 0, ErrNamedPortIsZero
	}
	return pp.Port, nil
}

// GetNamedPort returns the port number for the named port, if any.
// Numeric identities that have no named port mapping are skipped.
// Wildcard identity gets the named port defined for any other identity.
// Callers that need stricter per-identity semantics can fall back to GetNamedPorts().
func (npm *namedPortMultiMap) GetNamedPort(name string, proto u8proto.U8proto, nids iter.Seq[identity.NumericIdentity]) (uint16, error) {
	if npm == nil {
		return 0, ErrNilMap
	}
	npm.RLock()
	defer npm.RUnlock()
	if npm.m == nil {
		return 0, ErrNilMap
	}
	pps, ok := npm.m[name]
	if !ok {
		// Return an error the caller can filter out as this happens only for egress policy
		// and it is likely the destination POD with the port name is simply not scheduled yet.
		return 0, ErrUnknownNamedPort
	}
	// Find if there is a single port that has no proto conflict and no zero port value.
	var ports []uint16
	for nid := range nids {
		ports = collectNamedPorts(pps, proto, nid, ports)
		if len(ports) > 1 {
			return 0, ErrDuplicateNamedPorts
		}
	}
	if len(ports) == 0 {
		return 0, ErrUnknownNamedPort
	}
	return ports[0], nil
}

// GetNamedPorts returns the port numbers for the named port, if any.
func (npm *namedPortMultiMap) GetNamedPorts(name string, proto u8proto.U8proto, nids iter.Seq[identity.NumericIdentity]) NidPortSeq {
	if npm == nil {
		return emptyNidPortSeq
	}
	npm.Lock()
	if npm.m == nil {
		npm.Unlock()
		return emptyNidPortSeq
	}
	if npm.ports == nil {
		npm.ports = make(map[namedPortCacheKey]map[identity.NumericIdentity]unique.Handle[namedPortSet])
	}
	key := namedPortCacheKey{name: name, proto: proto}
	byNID, ok := npm.ports[key]
	if !ok || byNID == nil {
		byNID = make(map[identity.NumericIdentity]unique.Handle[namedPortSet])
		npm.ports[key] = byNID
	}
	pps := npm.m[name]
	var resultNIDs []identity.NumericIdentity
	var resultPorts []uint16
	for nid := range nids {
		if portSet, ok := byNID[nid]; ok {
			if portSet != zeroNamedPortSet {
				resultNIDs, resultPorts = appendNamedPorts(resultNIDs, resultPorts, nid, portSet)
			}
			continue
		}

		// cache miss, collect the ports for this numeric identity
		ports := collectNamedPorts(pps, proto, nid, nil)
		if len(ports) == 0 {
			byNID[nid] = zeroNamedPortSet
			continue
		}
		slices.Sort(ports)
		portSet := makeNamedPortSet(ports)
		byNID[nid] = portSet
		resultNIDs, resultPorts = appendNamedPorts(resultNIDs, resultPorts, nid, portSet)
	}
	npm.Unlock()

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

// collectNamedPorts collects named ports registered for the given numeric identity.
// For a wildcard identity (0) named ports registered for all identities are returned.
func collectNamedPorts(pps PortProtoSet, proto u8proto.U8proto, nid identity.NumericIdentity, ports []uint16) []uint16 {
	for pp, nidCounts := range pps {
		if nid != 0 {
			if _, exists := nidCounts[nid]; !exists {
				continue
			}
		}
		if pp.Proto != 0 && proto != pp.Proto {
			continue
		}
		if pp.Port == 0 {
			continue
		}
		if !slices.Contains(ports, pp.Port) {
			ports = append(ports, pp.Port)
		}
	}
	return ports
}

func makeNamedPortSet(ports []uint16) unique.Handle[namedPortSet] {
	if len(ports) == 0 {
		return zeroNamedPortSet
	}
	// SAFETY: ports is sorted, deduplicated, and not mutated after this point.
	// unsafe.String aliases ports only for the duration of unique.Make(). The
	// unique package clones string values before retaining new canonical values;
	// if the value is already interned, the temporary string is not retained.
	portSet := namedPortSet(unsafe.String(
		(*byte)(unsafe.Pointer(unsafe.SliceData(ports))),
		len(ports)*2,
	))
	return unique.Make(portSet)
}

func appendNamedPorts(resultNIDs []identity.NumericIdentity, resultPorts []uint16, nid identity.NumericIdentity, portSet unique.Handle[namedPortSet]) ([]identity.NumericIdentity, []uint16) {
	portSet.Value().forEachPort(func(port uint16) bool {
		resultNIDs = append(resultNIDs, nid)
		resultPorts = append(resultPorts, port)
		return true
	})
	return resultNIDs, resultPorts
}

func (ps namedPortSet) forEachPort(yield func(uint16) bool) bool {
	if len(ps) == 0 {
		return true
	}
	// SAFETY: namedPortSet values are created from []uint16 native-endian bytes
	// and are immutable after interning. We read as bytes rather than casting
	// back to []uint16 because unique.Make clones strings, so the cloned string
	// backing storage is not guaranteed to have uint16 alignment.
	portBytes := unsafe.Slice(unsafe.StringData(string(ps)), len(ps))
	for len(portBytes) >= 2 {
		if !yield(binary.NativeEndian.Uint16(portBytes[:2])) {
			return false
		}
		portBytes = portBytes[2:]
	}
	return true
}
