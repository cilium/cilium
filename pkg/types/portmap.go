// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"errors"
	"fmt"
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
	Proto u8proto.U8proto // 0 for any
	Port  uint16          // non-0
}

// NamedPortMap maps port names to port numbers and protocols.
type NamedPortMap map[string]PortProto

// PortProtoSet maps PortProto to a set of endpoint IDs that define it.
type PortProtoSet map[PortProto]map[identity.NumericIdentity]struct{}

// Equal returns true if the PortProtoSets are equal.
func (pps PortProtoSet) Equal(other PortProtoSet) bool {
	if len(pps) != len(other) {
		return false
	}

	for port, epSet := range pps {
		otherEpSet, exists := other[port]
		if !exists || len(epSet) != len(otherEpSet) {
			return false
		}
		for epID := range epSet {
			if _, epExists := otherEpSet[epID]; !epExists {
				return false
			}
		}
	}
	return true
}

// Add adds the epID to the set associated with the PortProto, returning true if it was newly added.
func (pps PortProtoSet) Add(pp PortProto, epID identity.NumericIdentity) bool {
	epSet, ok := pps[pp]
	if !ok {
		epSet = make(map[identity.NumericIdentity]struct{})
		pps[pp] = epSet
	}
	if _, exists := epSet[epID]; !exists {
		epSet[epID] = struct{}{}
		return true
	}
	return false
}

// Delete removes the epID from the set associated with the PortProto.
// It returns true if the epID was found and removed.
// The second return value is true if the set for the PortProto is now empty.
func (pps PortProtoSet) Delete(pp PortProto, epID identity.NumericIdentity) (deleted bool, setEmpty bool) {
	if epSet, ok := pps[pp]; ok {
		if _, exists := epSet[epID]; exists {
			delete(epSet, epID)
			return true, len(epSet) == 0
		}
	}
	return false, false
}

// NamedPortMultiMap may have multiple entries for a name if multiple PODs
// define the same name with different values.
type NamedPortMultiMap interface {
	// GetNamedPort returns the port number for the named port, if any.
	GetNamedPort(name string, proto u8proto.U8proto, epIDs map[identity.NumericIdentity]struct{}) (uint16, error)

	// Len returns the number of Name->PortProtoSet mappings known.
	Len() int
}

func NewNamedPortMultiMap() *namedPortMultiMap {
	return &namedPortMultiMap{
		m: make(map[string]PortProtoSet),
	}
}

// Implements NamedPortMultiMap and allows changes through Update. All accesses
// must be protected by its RW mutex.
type namedPortMultiMap struct {
	lock.RWMutex
	m map[string]PortProtoSet
}

func (npm *namedPortMultiMap) Len() int {
	npm.RLock()
	defer npm.RUnlock()
	return len(npm.m)
}

// Update applies potential changes in named ports, and returns whether there were any.
func (npm *namedPortMultiMap) Update(epID identity.NumericIdentity, old, new NamedPortMap) (namedPortsChanged bool) {
	npm.Lock()
	defer npm.Unlock()

	// Handle removals: Ports in old but not in new, or changed.
	for name, oldPP := range old {
		newPP, exists := new[name]
		if !exists || oldPP != newPP {
			if pps, ok := npm.m[name]; ok {
				if deleted, epSetEmpty := pps.Delete(oldPP, epID); deleted {
					namedPortsChanged = true
					if epSetEmpty {
						delete(pps, oldPP)
						if len(pps) == 0 {
							delete(npm.m, name)
						}
					}
				}
			}
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
			if pps.Add(newPP, epID) {
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
func (npm *namedPortMultiMap) GetNamedPort(name string, proto u8proto.U8proto, epIDs map[identity.NumericIdentity]struct{}) (uint16, error) {
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
	// Find if there is a single port that has no proto conflict and no zero port value
	port := uint16(0)
	err := ErrUnknownNamedPort
	for pp, epSet := range pps {
		// Check if this PortProto is defined by any of the target endpoint IDs
		validEp := false
		for epID := range epIDs {
			if _, exists := epSet[epID]; exists {
				validEp = true
				break
			}
		}
		if !validEp {
			continue // Skip if PortProto is not from the target endpoints
		}

		if pp.Proto != 0 && proto != pp.Proto {
			err = ErrIncompatibleProtocol
			continue // conflicting proto
		}
		if pp.Port == 0 {
			err = ErrNamedPortIsZero
			continue // zero port
		}
		if port != 0 && pp.Port != port {
			return 0, ErrDuplicateNamedPorts
		}
		port = pp.Port
	}
	if port == 0 {
		return 0, err
	}
	return port, nil
}
