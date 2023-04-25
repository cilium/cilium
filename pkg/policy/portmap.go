// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/cilium/pkg/iana"
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
	Port  uint16 // non-0
	Proto uint8  // 0 for any
}

// NamedPortMap maps port names to port numbers and protocols.
type NamedPortMap map[string]PortProto

// PortProtoSet is a set of unique PortProto values.
type PortProtoSet map[PortProto]struct{}

// Equal returns true if the PortProtoSets are equal.
func (pps PortProtoSet) Equal(other PortProtoSet) bool {
	if len(pps) != len(other) {
		return false
	}

	for port := range pps {
		if _, exists := other[port]; !exists {
			return false
		}
	}
	return true
}

// NamedPortMultiMap may have multiple entries for a name if multiple PODs
// define the same name with different values.
type NamedPortMultiMap interface {
	// GetNamedPort returns the port number for the named port, if any.
	GetNamedPort(name string, proto uint8) (uint16, error)
	// Len returns the number of Name->PortProtoSet mappings known.
	Len() int
	Equal(other NamedPortMultiMap) bool
}

func NewNamedPortMultiMap() namedPortMultiMap {
	return make(namedPortMultiMap)
}

type namedPortMultiMap map[string]PortProtoSet

// Equal returns true if the NamedPortMultiMaps are equal.
func (npm namedPortMultiMap) Equal(other NamedPortMultiMap) bool {
	o, ok := other.(namedPortMultiMap)
	if !ok || len(npm) != len(o) {
		return false
	}
	for name, ports := range npm {
		if otherPorts, exists := o[name]; !exists || !ports.Equal(otherPorts) {
			return false
		}
	}
	return true
}

func (npm namedPortMultiMap) Len() int {
	return len(npm)
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
		Proto: uint8(u8p),
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
func (npm NamedPortMap) GetNamedPort(name string, proto uint8) (uint16, error) {
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
func (npm namedPortMultiMap) GetNamedPort(name string, proto uint8) (uint16, error) {
	if npm == nil {
		return 0, ErrNilMap
	}
	pps, ok := npm[name]
	if !ok {
		// Return an error the caller can filter out as this happens only for egress policy
		// and it is likely the destination POD with the port name is simply not scheduled yet.
		return 0, ErrUnknownNamedPort
	}
	// Find if there is a single port that has no proto conflict and no zero port value
	port := uint16(0)
	err := ErrUnknownNamedPort
	for pp := range pps {
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
