// Copyright 2016-2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package lxcmap

import (
	"fmt"
	"net"
	"strings"
	"unsafe"

	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/logfields"

	log "github.com/sirupsen/logrus"
)

const (
	MapName = "cilium_lxc"

	// MaxKeys represents the maximum number of endpoints in the map
	MaxKeys = 0xFFFF

	// PortMapMax represents the maximum number of Ports Mapping per container.
	PortMapMax = 16
)

var (
	mapInstance = bpf.NewMap(MapName,
		bpf.MapTypeHash,
		int(unsafe.Sizeof(EndpointKey{})),
		int(unsafe.Sizeof(EndpointInfo{})),
		MaxKeys, 0)
)

func init() {
	bpf.OpenAfterMount(mapInstance)
}

// MAC is the __u64 representation of a MAC address.
type MAC uint64

func (m MAC) String() string {
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X",
		uint64((m & 0x0000000000FF)),
		uint64((m&0x00000000FF00)>>8),
		uint64((m&0x000000FF0000)>>16),
		uint64((m&0x0000FF000000)>>24),
		uint64((m&0x00FF00000000)>>32),
		uint64((m&0xFF0000000000)>>40),
	)
}

// ParseMAC parses s only as an IEEE 802 MAC-48.
func ParseMAC(s string) (MAC, error) {
	ha, err := net.ParseMAC(s)
	if err != nil {
		return 0, err
	}
	if len(ha) != 6 {
		return 0, fmt.Errorf("invalid MAC address %s", s)
	}
	return MAC(ha[5])<<40 | MAC(ha[4])<<32 | MAC(ha[3])<<24 |
		MAC(ha[2])<<16 | MAC(ha[1])<<8 | MAC(ha[0]), nil
}

// PortMap represents a port mapping from the host to the LXC.
type PortMap struct {
	From uint16
	To   uint16
}

func (pm PortMap) String() string {
	return fmt.Sprintf("%d:%d", byteorder.HostToNetwork(pm.From), byteorder.HostToNetwork(pm.To))
}

const (
	// EndpointFlagHost indicates that this endpoint represents the host
	EndpointFlagHost = 1
)

// EndpointFrontend is the interface to implement for an object to synchronize
// with the endpoint BPF map
type EndpointFrontend interface {
	// GetBPFKeys must return a slice of EndpointKey which all represent the endpoint
	GetBPFKeys() []EndpointKey

	// GetBPFValue must return an EndpointInfo structure representing the frontend
	GetBPFValue() (*EndpointInfo, error)
}

// EndpointInfo represents the value of the endpoints BPF map.
//
// Must be in sync with struct endpoint_info in <bpf/lib/common.h>
type EndpointInfo struct {
	IfIndex    uint32
	SecLabelID uint16
	LxcID      uint16
	Flags      uint32
	MAC        MAC
	NodeMAC    MAC
	V6Addr     types.IPv6
	PortMap    [PortMapMax]PortMap
}

// GetValuePtr returns the unsafe pointer to the BPF value
func (v EndpointInfo) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(&v) }

// Must be in sync with ENDPOINT_KEY_* in <bpf/lib/common.h>
const (
	endpointKeyIPv4 uint8 = 1
	endpointKeyIPv6 uint8 = 2
)

// EndpointKey represents the key value of the endpoints BPF map
//
// Must be in sync with struct endpoint_key in <bpf/lib/common.h>
type EndpointKey struct {
	ip     types.IPv6 // represents both IPv6 and IPv4
	family uint8
	pad1   uint8
	pad2   uint16
}

// GetKeyPtr returns the unsafe pointer to the BPF key
func (k EndpointKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(&k) }

// NewValue returns a new empty instance of the structure representing the BPF
// map value
func (k EndpointKey) NewValue() bpf.MapValue { return &EndpointInfo{} }

// NewEndpointKey returns an EndpointKey based on the provided IP address. The
// address family is automatically detected
func NewEndpointKey(ip net.IP) EndpointKey {
	key := EndpointKey{}
	copy(key.ip[:], ip)

	if ip4 := ip.To4(); ip4 != nil {
		key.family = endpointKeyIPv4
		copy(key.ip[:], ip4)
	} else {
		key.family = endpointKeyIPv6
		copy(key.ip[:], ip)
	}

	return key
}

// String returns the human readable representation of an EndpointInfo
func (v EndpointInfo) String() string {
	var portMaps []string
	for _, port := range v.PortMap {
		if pStr := port.String(); pStr != "0:0" {
			portMaps = append(portMaps, pStr)
		}
	}
	if len(portMaps) == 0 {
		portMaps = append(portMaps, "(empty)")
	}
	return fmt.Sprintf("id=%d ifindex=%d mac=%s nodemac=%s ip=%s seclabel=0x%x portMaps=%s",
		v.LxcID,
		v.IfIndex,
		v.MAC,
		v.NodeMAC,
		v.V6Addr,
		byteorder.HostToNetwork(v.SecLabelID),
		strings.Join(portMaps, " "),
	)
}

// WriteEndpoint updates the BPF map with the endpoint information and links
// the endpoint information to all keys provided.
func WriteEndpoint(f EndpointFrontend) error {
	info, err := f.GetBPFValue()
	if err != nil {
		return err
	}

	// FIXME: Revert on failure
	for _, k := range f.GetBPFKeys() {
		if err := mapInstance.Update(k, *info); err != nil {
			return err
		}
	}

	return nil
}

// AddHostEntry adds a special endpoint which represents the local host
func AddHostEntry(ip net.IP) error {
	key := NewEndpointKey(ip)
	ep := EndpointInfo{Flags: EndpointFlagHost}
	return mapInstance.Update(key, ep)
}

// DeleteElement deletes the endpoint using all keys which represent the
// endpoint. It returns the number of errors encountered during deletion.
func DeleteElement(f EndpointFrontend) int {
	errors := 0
	for _, k := range f.GetBPFKeys() {
		if err := mapInstance.Delete(k); err != nil {
			log.WithError(err).WithField(logfields.BPFMapKey, k).Warn("Unable to delete endpoint in BPF map")
			errors++
		}
	}

	return errors
}
