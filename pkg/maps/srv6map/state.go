// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package srv6map

import (
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/types"
)

const (
	StateMapName4   = "cilium_srv6_state_v4"
	StateMapName6   = "cilium_srv6_state_v6"
	MaxStateEntries = 16384
)

var (
	SRv6StateMap4 *srv6StateMap
	SRv6StateMap6 *srv6StateMap
)

// Generic SRv6 state key for IPv4 and IPv6.
type StateKey struct {
	InnerSrc *net.IP
	InnerDst *net.IP
}

func (k *StateKey) String() string {
	return fmt.Sprintf("%s %s", k.InnerSrc, k.InnerDst)
}

// StateValue implements the bpf.MapValue interface. It contains the
// SRv6 outer IPs for the state maps.
type StateValue struct {
	OuterSrc *net.IP
	OuterDst *net.IP
}

// String pretty prints the state outer IPs.
func (v *StateValue) String() string {
	return fmt.Sprintf("%s %s", v.OuterSrc, v.OuterDst)
}

func OpenStateMaps() error {
	var m4, m6 *ebpf.Map
	var err error

	if m4, err = ebpf.LoadRegisterMap(StateMapName4); err != nil {
		return err
	}
	if m6, err = ebpf.LoadRegisterMap(StateMapName6); err != nil {
		return err
	}

	SRv6StateMap4 = &srv6StateMap{
		m4,
	}
	SRv6StateMap6 = &srv6StateMap{
		m6,
	}

	return nil
}

// srv6StateMap is the internal representation of an SRv6 state map.
type srv6StateMap struct {
	*ebpf.Map
}

type StateKey4 struct {
	InnerSrc types.IPv4
	InnerDst types.IPv4
}

type StateKey6 struct {
	InnerSrc types.IPv6
	InnerDst types.IPv6
}

// SRv6StateIterateCallback represents the signature of the callback function
// expected by the IterateWithCallback method, which in turn is used to iterate
// all the keys/values of an SRv6 state map.
type SRv6StateIterateCallback func(*StateKey, *StateValue)

// IterateWithCallback4 iterates through the IPv4 keys/values of an SRv6 map
// map, passing each key/value pair to the cb callback.
func (m srv6StateMap) IterateWithCallback4(cb SRv6StateIterateCallback) error {
	return m.Map.IterateWithCallback(&StateKey4{}, &StateValue{},
		func(k, v interface{}) {
			key4 := k.(*StateKey4)
			srcIP := key4.InnerSrc.IP()
			dstIP := key4.InnerDst.IP()
			key := StateKey{
				InnerSrc: &srcIP,
				InnerDst: &dstIP,
			}
			value := v.(*StateValue)

			cb(&key, value)
		})
}

// IterateWithCallback6 iterates through the IPv6 keys/values of an SRv6 state
// map, passing each key/value pair to the cb callback.
func (m srv6StateMap) IterateWithCallback6(cb SRv6StateIterateCallback) error {
	return m.Map.IterateWithCallback(&StateKey6{}, &StateValue{},
		func(k, v interface{}) {
			key6 := k.(*StateKey6)
			srcIP := key6.InnerSrc.IP()
			dstIP := key6.InnerDst.IP()
			key := StateKey{
				InnerSrc: &srcIP,
				InnerDst: &dstIP,
			}
			value := v.(*StateValue)

			cb(&key, value)
		})
}
