// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lxcmap

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"
)

const (
	MapName = "cilium_lxc"

	// MaxEntries represents the maximum number of endpoints in the map
	MaxEntries = 65535

	// PortMapMax represents the maximum number of Ports Mapping per container.
	PortMapMax = 16
)

var (
	// LXCMap represents the BPF map for endpoints
	lxcMap     *bpf.Map
	lxcMapOnce sync.Once
)

func LXCMap() *bpf.Map {
	lxcMapOnce.Do(func() {
		lxcMap = bpf.NewMap(MapName,
			bpf.MapTypeHash,
			&EndpointKey{},
			int(unsafe.Sizeof(EndpointKey{})),
			&EndpointInfo{},
			int(unsafe.Sizeof(EndpointInfo{})),
			MaxEntries,
			0,
			bpf.ConvertKeyValue,
		).WithCache().WithPressureMetric().
			WithEvents(option.Config.GetEventBufferConfig(MapName))
	})
	return lxcMap
}

const (
	// EndpointFlagHost indicates that this endpoint represents the host
	EndpointFlagHost = 1
)

// EndpointFrontend is the interface to implement for an object to synchronize
// with the endpoint BPF map.
type EndpointFrontend interface {
	LXCMac() mac.MAC
	GetNodeMAC() mac.MAC
	GetIfIndex() int
	GetID() uint64
	IPv4Address() netip.Addr
	IPv6Address() netip.Addr
	GetIdentity() identity.NumericIdentity
}

// GetBPFKeys returns all keys which should represent this endpoint in the BPF
// endpoints map
func GetBPFKeys(e EndpointFrontend) []*EndpointKey {
	keys := []*EndpointKey{}
	if e.IPv6Address().IsValid() {
		keys = append(keys, NewEndpointKey(e.IPv6Address().AsSlice()))
	}

	if e.IPv4Address().IsValid() {
		keys = append(keys, NewEndpointKey(e.IPv4Address().AsSlice()))
	}

	return keys
}

// GetBPFValue returns the value which should represent this endpoint in the
// BPF endpoints map
// Must only be called if init() succeeded.
func GetBPFValue(e EndpointFrontend) (*EndpointInfo, error) {
	mac, err := e.LXCMac().Uint64()
	if err != nil {
		return nil, fmt.Errorf("invalid LXC MAC: %v", err)
	}

	nodeMAC, err := e.GetNodeMAC().Uint64()
	if err != nil {
		return nil, fmt.Errorf("invalid node MAC: %v", err)
	}

	info := &EndpointInfo{
		IfIndex: uint32(e.GetIfIndex()),
		// Store security identity in network byte order so it can be
		// written into the packet without an additional byte order
		// conversion.
		LxcID:   uint16(e.GetID()),
		MAC:     mac,
		NodeMAC: nodeMAC,
		SecID:   e.GetIdentity().Uint32(),
	}

	return info, nil

}

type pad3uint32 [3]uint32

// DeepCopyInto is a deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *pad3uint32) DeepCopyInto(out *pad3uint32) {
	copy(out[:], in[:])
	return
}

// EndpointInfo represents the value of the endpoints BPF map.
//
// Must be in sync with struct endpoint_info in <bpf/lib/common.h>
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type EndpointInfo struct {
	IfIndex uint32 `align:"ifindex"`
	Unused  uint16 `align:"unused"`
	LxcID   uint16 `align:"lxc_id"`
	Flags   uint32 `align:"flags"`
	// go alignment
	_       uint32
	MAC     mac.Uint64MAC `align:"mac"`
	NodeMAC mac.Uint64MAC `align:"node_mac"`
	SecID   uint32        `align:"sec_id"`
	Pad     pad3uint32    `align:"pad"`
}

// GetValuePtr returns the unsafe pointer to the BPF value
func (v *EndpointInfo) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type EndpointKey struct {
	bpf.EndpointKey
}

// NewValue returns a new empty instance of the structure representing the BPF
// map value
func (k EndpointKey) NewValue() bpf.MapValue { return &EndpointInfo{} }

// NewEndpointKey returns an EndpointKey based on the provided IP address. The
// address family is automatically detected
func NewEndpointKey(ip net.IP) *EndpointKey {
	return &EndpointKey{
		EndpointKey: bpf.NewEndpointKey(ip, 0),
	}
}

// IsHost returns true if the EndpointInfo represents a host IP
func (v *EndpointInfo) IsHost() bool {
	return v.Flags&EndpointFlagHost != 0
}

// String returns the human readable representation of an EndpointInfo
func (v *EndpointInfo) String() string {
	if v.Flags&EndpointFlagHost != 0 {
		return "(localhost)"
	}

	return fmt.Sprintf("id=%-5d sec_id=%-5d flags=0x%04X ifindex=%-3d mac=%s nodemac=%s",
		v.LxcID,
		v.SecID,
		v.Flags,
		v.IfIndex,
		v.MAC,
		v.NodeMAC,
	)
}

// WriteEndpoint updates the BPF map with the endpoint information and links
// the endpoint information to all keys provided.
func WriteEndpoint(f EndpointFrontend) error {
	info, err := GetBPFValue(f)
	if err != nil {
		return err
	}

	// FIXME: Revert on failure
	for _, v := range GetBPFKeys(f) {
		if err := LXCMap().Update(v, info); err != nil {
			return err
		}
	}

	return nil
}

// AddHostEntry adds a special endpoint which represents the local host
func AddHostEntry(ip net.IP) error {
	key := NewEndpointKey(ip)
	ep := &EndpointInfo{Flags: EndpointFlagHost}
	return LXCMap().Update(key, ep)
}

// SyncHostEntry checks if a host entry exists in the lxcmap and adds one if needed.
// Returns boolean indicating if a new entry was added and an error.
func SyncHostEntry(ip net.IP) (bool, error) {
	key := NewEndpointKey(ip)
	value, err := LXCMap().Lookup(key)
	if err != nil || value.(*EndpointInfo).Flags&EndpointFlagHost == 0 {
		err = AddHostEntry(ip)
		if err == nil {
			return true, nil
		}
	}
	return false, err
}

// DeleteEntry deletes a single map entry
func DeleteEntry(ip net.IP) error {
	return LXCMap().Delete(NewEndpointKey(ip))
}

// DeleteElement deletes the endpoint using all keys which represent the
// endpoint. It returns the number of errors encountered during deletion.
func DeleteElement(f EndpointFrontend) []error {
	var errors []error
	for _, k := range GetBPFKeys(f) {
		if err := LXCMap().Delete(k); err != nil {
			errors = append(errors, fmt.Errorf("Unable to delete key %v from %s: %s", k, bpf.MapPath(MapName), err))
		}
	}

	return errors
}

// DumpToMap dumps the contents of the lxcmap into a map and returns it
func DumpToMap() (map[string]*EndpointInfo, error) {
	m := map[string]*EndpointInfo{}
	callback := func(key bpf.MapKey, value bpf.MapValue) {
		if info, ok := value.DeepCopyMapValue().(*EndpointInfo); ok {
			if endpointKey, ok := key.(*EndpointKey); ok {
				m[endpointKey.ToIP().String()] = info
			}
		}
	}

	if err := LXCMap().DumpWithCallback(callback); err != nil {
		return nil, fmt.Errorf("unable to read BPF endpoint list: %s", err)
	}

	return m, nil
}
