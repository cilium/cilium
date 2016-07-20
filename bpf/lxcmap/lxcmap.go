package lxcmap

/*
#cgo CFLAGS: -I../include
#include <linux/bpf.h>
*/
import "C"

import (
	"fmt"
	"net"
	"strings"
	"unsafe"

	common "github.com/noironetworks/cilium-net/common"
	"github.com/noironetworks/cilium-net/common/bpf"
	"github.com/noironetworks/cilium-net/common/types"
)

// LXCMap is an internal representation of an eBPF LXC Map.
type LXCMap struct {
	fd int
}

const (
	// MaxKeys represents the maximum number of keys in the LXCMap.
	MaxKeys = common.EndpointsPerHost

	// PortMapMax represents the maximum number of Ports Mapping per container.
	PortMapMax = 16
)

// MAC is the __u64 representation of a MAC address.
type MAC C.__u64

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
	SecLabelID uint32
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
	return fmt.Sprintf("ifindex=%d mac=%s nodemac=%s ip=%s seclabel=0x%x portMaps=%s",
		lxc.IfIndex,
		lxc.MAC,
		lxc.NodeMAC,
		lxc.V6Addr,
		common.Swab32(lxc.SecLabelID),
		strings.Join(portMaps, " "),
	)
}

// WriteEndpoint transforms the ep's relevant data into an LXCInfo and stores it in
// LXCMap.
func (m *LXCMap) WriteEndpoint(ep *types.Endpoint) error {
	if m == nil {
		return nil
	}

	key := ep.ID

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
		SecLabelID: common.Swab32(ep.SecLabel.ID),
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

	return bpf.UpdateElement(m.fd, unsafe.Pointer(&key), unsafe.Pointer(&lxc), 0)
}

// DeleteElement deletes the element with the given id from the LXCMap.
func (m *LXCMap) DeleteElement(id uint16) error {
	if m == nil {
		return nil
	}

	return bpf.DeleteElement(m.fd, unsafe.Pointer(&id))
}

// OpenMap opens the LXCMap in the given path.
func OpenMap(path string) (*LXCMap, error) {

	fd, _, err := bpf.OpenOrCreateMap(
		path,
		C.BPF_MAP_TYPE_HASH,
		uint32(unsafe.Sizeof(uint16(0))),
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
