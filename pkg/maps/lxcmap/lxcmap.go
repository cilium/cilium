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

/*
#cgo CFLAGS: -I../../../bpf/include
#include <linux/bpf.h>
*/
import "C"

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"unsafe"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/endpoint"
)

// LXCMap is an internal representation of an eBPF LXC Map.
type LXCMap struct {
	Mutex sync.Mutex // Mutex protects the whole LXCMap.
	fd    int
}

const (
	MapName = "cilium_lxc"

	// MaxKeys represents the maximum number of keys in the LXCMap.
	MaxKeys = common.EndpointsPerHost

	// PortMapMax represents the maximum number of Ports Mapping per container.
	PortMapMax = 16
)

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
	return MAC(MAC(ha[5])<<40 | MAC(ha[4])<<32 | MAC(ha[3])<<24 |
		MAC(ha[2])<<16 | MAC(ha[1])<<8 | MAC(ha[0])), nil
}

// PortMap represents a port mapping from the host to the LXC.
type PortMap struct {
	From uint16
	To   uint16
}

func (pm PortMap) String() string {
	return fmt.Sprintf("%d:%d", common.Swab16(pm.From), common.Swab16(pm.To))
}

type v6Addr [16]byte

func (v6 v6Addr) String() string {
	return net.IP(v6[:]).String()
}

// LXCInfo is an internal representation of an LXC most relevant details for eBPF
// programs.
type LXCInfo struct {
	IfIndex    uint32
	SecLabelID uint16
	LxcID      uint16
	MAC        MAC
	NodeMAC    MAC
	V6Addr     v6Addr
	PortMap    [PortMapMax]PortMap
}

func (lxc LXCInfo) String() string {
	var portMaps []string
	for _, port := range lxc.PortMap {
		if pStr := port.String(); pStr != "0:0" {
			portMaps = append(portMaps, pStr)
		}
	}
	if len(portMaps) == 0 {
		portMaps = append(portMaps, "(empty)")
	}
	return fmt.Sprintf("id=%d ifindex=%d mac=%s nodemac=%s ip=%s seclabel=0x%x portMaps=%s",
		lxc.LxcID,
		lxc.IfIndex,
		lxc.MAC,
		lxc.NodeMAC,
		lxc.V6Addr,
		common.Swab16(lxc.SecLabelID),
		strings.Join(portMaps, " "),
	)
}

// WriteEndpoint transforms the ep's relevant data into an LXCInfo and stores it in
// LXCMap.
func (m *LXCMap) WriteEndpoint(ep *endpoint.Endpoint) error {
	if m == nil {
		return nil
	}

	key := uint32(ep.ID)

	mac, err := ep.LXCMAC.Uint64()
	if err != nil {
		return err
	}

	nodeMAC, err := ep.NodeMAC.Uint64()
	if err != nil {
		return err
	}

	lxc := LXCInfo{
		IfIndex: uint32(ep.IfIndex),
		// Store security label in network byte order so it can be
		// written into the packet without an additional byte order
		// conversion.
		SecLabelID: common.Swab16(uint16(ep.GetIdentity())),
		LxcID:      ep.ID,
		MAC:        MAC(mac),
		NodeMAC:    MAC(nodeMAC),
	}

	copy(lxc.V6Addr[:], ep.IPv6)

	for i, pM := range ep.PortMap {
		lxc.PortMap[i] = PortMap{
			From: common.Swab16(pM.From),
			To:   common.Swab16(pM.To),
		}
	}

	m.Mutex.Lock()
	defer m.Mutex.Unlock()

	err = bpf.UpdateElement(m.fd, unsafe.Pointer(&key), unsafe.Pointer(&lxc), 0)
	if err != nil {
		return err
	}

	if ep.IPv4 != nil {
		key := uint32(ep.IPv4.EndpointID()) | (1 << 16)
		// FIXME: Remove key again? Needs to be solved by caller
		return bpf.UpdateElement(m.fd, unsafe.Pointer(&key), unsafe.Pointer(&lxc), 0)
	}

	return nil
}

// DeleteElement deletes the element with the given id from the LXCMap.
func (m *LXCMap) DeleteElement(ep *endpoint.Endpoint) error {
	if m == nil {
		return nil
	}

	// FIXME: errors are currently ignored
	id6 := uint32(ep.ID)
	m.Mutex.Lock()
	defer m.Mutex.Unlock()
	err := bpf.DeleteElement(m.fd, unsafe.Pointer(&id6))

	if ep.IPv4 != nil {
		if id4 := uint32(ep.IPv4.EndpointID()); id4 != 0 {
			id4 = id4 | (1 << 16)
			if err := bpf.DeleteElement(m.fd, unsafe.Pointer(&id4)); err != nil {
				return err
			}
		}
	}

	return err
}

// OpenMap opens the endpoint map.
func OpenMap() (*LXCMap, error) {
	path := bpf.MapPath(MapName)

	fd, _, err := bpf.OpenOrCreateMap(
		path,
		C.BPF_MAP_TYPE_HASH,
		uint32(unsafe.Sizeof(uint32(0))),
		uint32(unsafe.Sizeof(LXCInfo{})),
		MaxKeys,
	)
	if err != nil {
		return nil, err
	}
	m := new(LXCMap)
	m.fd = fd

	return m, nil
}
