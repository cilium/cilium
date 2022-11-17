// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package srv6map

import (
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/types"
)

const (
	VRFMapName4   = "cilium_srv6_vrf_v4"
	VRFMapName6   = "cilium_srv6_vrf_v6"
	MaxVRFEntries = 16384
)

var (
	SRv6VRFMap4 *srv6VRFMap
	SRv6VRFMap6 *srv6VRFMap
)

// Generic VRF mapping key for IPv4 and IPv6.
type VRFKey struct {
	SourceIP *net.IP
	DestCIDR *net.IPNet
}

func (k *VRFKey) String() string {
	return fmt.Sprintf("%s %s", k.SourceIP, k.DestCIDR)
}

// Match returns true if the sourceIP and destCIDR parameters match the SRv6
// policy key.
func (k *VRFKey) Match(srcIP net.IP, cidr *net.IPNet) bool {
	return k.SourceIP.String() == srcIP.String() && k.DestCIDR.String() == cidr.String()
}

// VRFValue implements the bpf.MapValue interface. It contains the
// VRF ID for SRv6 lookups.
type VRFValue struct {
	ID uint32
}

// String pretty prints the VRF ID.
func (v *VRFValue) String() string {
	return fmt.Sprintf("%d", v.ID)
}

func initVRFMaps(create bool) error {
	var m4, m6 *ebpf.Map
	var err error

	if create {
		m4 = ebpf.NewMap(&ebpf.MapSpec{
			Name:       VRFMapName4,
			Type:       ebpf.LPMTrie,
			KeySize:    uint32(unsafe.Sizeof(VRFKey4{})),
			ValueSize:  uint32(unsafe.Sizeof(VRFValue{})),
			MaxEntries: uint32(MaxVRFEntries),
			Flags:      unix.BPF_F_NO_PREALLOC,
			Pinning:    ebpf.PinByName,
		})
		if err = m4.OpenOrCreate(); err != nil {
			return err
		}

		m6 = ebpf.NewMap(&ebpf.MapSpec{
			Name:       VRFMapName6,
			Type:       ebpf.LPMTrie,
			KeySize:    uint32(unsafe.Sizeof(VRFKey6{})),
			ValueSize:  uint32(unsafe.Sizeof(VRFValue{})),
			MaxEntries: uint32(MaxVRFEntries),
			Flags:      unix.BPF_F_NO_PREALLOC,
			Pinning:    ebpf.PinByName,
		})
		if err = m6.OpenOrCreate(); err != nil {
			return err
		}
	} else {
		if m4, err = ebpf.LoadRegisterMap(VRFMapName4); err != nil {
			return err
		}
		if m6, err = ebpf.LoadRegisterMap(VRFMapName6); err != nil {
			return err
		}
	}

	SRv6VRFMap4 = &srv6VRFMap{
		m4,
	}
	SRv6VRFMap6 = &srv6VRFMap{
		m6,
	}

	return nil
}

func CreateVRFMaps() error {
	return initVRFMaps(true)
}

func OpenVRFMaps() error {
	return initVRFMaps(false)
}

// srv6VRFMap is the internal representation of an SRv6 VRF mapping map.
type srv6VRFMap struct {
	*ebpf.Map
}

type VRFKey4 struct {
	// PrefixLen is full 32 bits of VRF ID + DestCIDR's mask bits
	PrefixLen uint32 `align:"lpm"`

	SourceIP types.IPv4 `align:"src_ip"`
	DestCIDR types.IPv4 `align:"dst_cidr"`
}

type VRFKey6 struct {
	// PrefixLen is full 32 bits of VRF ID + DestCIDR's mask bits
	PrefixLen uint32 `align:"lpm"`

	SourceIP types.IPv6 `align:"src_ip"`
	DestCIDR types.IPv6 `align:"dst_cidr"`
}

func (k *VRFKey4) getDestCIDR() *net.IPNet {
	staticPrefixBits := uint32(unsafe.Sizeof(k.SourceIP) * 8)
	return &net.IPNet{
		IP:   k.DestCIDR.IP(),
		Mask: net.CIDRMask(int(k.PrefixLen-staticPrefixBits), 32),
	}
}

func (k *VRFKey6) getDestCIDR() *net.IPNet {
	staticPrefixBits := uint32(unsafe.Sizeof(k.SourceIP) * 8)
	return &net.IPNet{
		IP:   k.DestCIDR.IP(),
		Mask: net.CIDRMask(int(k.PrefixLen-staticPrefixBits), 128),
	}
}

// SRv6VRFIterateCallback represents the signature of the callback function
// expected by the IterateWithCallback method, which in turn is used to iterate
// all the keys/values of an SRv6 policy map.
type SRv6VRFIterateCallback func(*VRFKey, *VRFValue)

// IterateWithCallback4 iterates through the IPv4 keys/values of a VRF mapping
// map, passing each key/value pair to the cb callback.
func (m srv6VRFMap) IterateWithCallback4(cb SRv6VRFIterateCallback) error {
	return m.Map.IterateWithCallback(&VRFKey4{}, &VRFValue{},
		func(k, v interface{}) {
			key4 := k.(*VRFKey4)
			srcIP := key4.SourceIP.IP()
			key := VRFKey{
				SourceIP: &srcIP,
				DestCIDR: key4.getDestCIDR(),
			}
			value := v.(*VRFValue)

			cb(&key, value)
		})
}

// IterateWithCallback6 iterates through the IPv6 keys/values of a VRF mapping
// map, passing each key/value pair to the cb callback.
func (m srv6VRFMap) IterateWithCallback6(cb SRv6VRFIterateCallback) error {
	return m.Map.IterateWithCallback(&VRFKey6{}, &VRFValue{},
		func(k, v interface{}) {
			key6 := k.(*VRFKey6)
			srcIP := key6.SourceIP.IP()
			key := VRFKey{
				SourceIP: &srcIP,
				DestCIDR: key6.getDestCIDR(),
			}
			value := v.(*VRFValue)

			cb(&key, value)
		})
}
