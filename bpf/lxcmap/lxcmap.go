package lxcmap

/*
#include <linux/bpf.h>
#include <sys/resource.h>
*/
import "C"

import (
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	common "github.com/noironetworks/cilium-net/common"
	"github.com/noironetworks/cilium-net/common/bpf"
	"github.com/noironetworks/cilium-net/common/types"
)

// LXCMap is an internal representation of an eBPF LXC Map.
type LxcMap struct {
	fd int
}

const (
	// MaxKeys represents the maximum number of keys in the LXCMap.
	// TODO: bump this number to 0xffff
	// Or at least make it dependent on the number of containers per node)
	MAX_KEYS = 1024

	// PortMapMax represents the maximum number of Ports Mapping per container.
	PORTMAP_MAX = 16
)

// MAC is the __u64 representation of a MAC address.
type Mac C.__u64

func (m Mac) String() string {
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
func ParseMAC(s string) (Mac, error) {
	ha, err := net.ParseMAC(s)
	if err != nil {
		return 0, err
	}
	if len(ha) != 6 {
		return 0, fmt.Errorf("invalid MAC address %s", s)
	}
	return Mac(Mac(ha[5])<<40 | Mac(ha[4])<<32 | Mac(ha[3])<<24 | Mac(ha[2])<<16 | Mac(ha[1])<<8 | Mac(ha[0])), nil
}

// PortMap represents a port mapping from the host to the LXC.
type Portmap struct {
	From uint16
	To   uint16
}

func (pm Portmap) String() string {
	return fmt.Sprintf("%d:%d", common.Swab16(pm.From), common.Swab16(pm.To))
}

type V6addr struct {
       Addr [16]byte
}


func (v6 V6addr) String() string {
	return net.IP(v6.Addr[:]).String()
}

// LXCInfo is an internal representation of an LXC most relevant details for eBPF
// programs.
type LxcInfo struct {
	Ifindex  uint32
	SecLabel uint32
	MAC      Mac
	NodeMAC  Mac
	V6addr   V6addr
	Portmap  [PORTMAP_MAX]Portmap
}

func (lxc LxcInfo) String() string {
	var portmaps []string
	for _, port := range lxc.Portmap {
		if pStr := port.String(); pStr != "0:0" {
			portmaps = append(portmaps, pStr)
		}
	}
	if len(portmaps) == 0 {
		portmaps = append(portmaps, "(empty)")
	}
	return fmt.Sprintf("ifindex=%d mac=%s nodemac=%s ip=%s seclabel=0x%x portmaps=%s",
		lxc.Ifindex,
		lxc.MAC,
		lxc.NodeMAC,
		lxc.V6addr,
		common.Swab32(lxc.SecLabel),
		strings.Join(portmaps, " "),
	)
}

// WriteEndpoint transforms the ep's relevant data into an LXCInfo and stores it in
// LXCMap.
func (m *LxcMap) WriteEndpoint(ep *types.Endpoint) error {
	key := ep.U16ID()

	mac, err := ep.LxcMAC.Uint64()
	if err != nil {
		return err
	}

	nodeMac, err := ep.NodeMAC.Uint64()
	if err != nil {
		return err
	}

	lxc := LxcInfo{
		Ifindex: uint32(ep.IfIndex),
		// Store security label in network byte order so it can be
		// written into the packet without an additional byte order
		// conversion.
		SecLabel: common.Swab32(ep.SecLabel),
		MAC:      Mac(mac),
		NodeMAC:  Mac(nodeMac),
	}

	copy(lxc.V6addr.Addr[:], ep.LxcIP)

	for i, portmap := range ep.PortMap {
		lxc.Portmap[i] = Portmap{
			From: common.Swab16(portmap.From),
			To:   common.Swab16(portmap.To),
		}
	}

	return bpf.UpdateElement(m.fd, unsafe.Pointer(&key), unsafe.Pointer(&lxc), 0)
}

// DeleteElement deletes the element with the given id from the LXCMap.
func (m *LxcMap) DeleteElement(id string) error {
	n, _ := strconv.ParseUint(id, 10, 16)
	key := uint16(n)
	return bpf.DeleteElement(m.fd, unsafe.Pointer(&key))
}

// OpenMap opens the LXCMap in the given path.
func OpenMap(path string) (*LxcMap, error) {
	var fd int

	rl := syscall.Rlimit{
		Cur: math.MaxUint64,
		Max: math.MaxUint64,
	}

	err := syscall.Setrlimit(C.RLIMIT_MEMLOCK, &rl)
	if err != nil {
		return nil, fmt.Errorf("Unable to increase rlimit: %s", err)
	}

	if _, err = os.Stat(path); os.IsNotExist(err) {
		mapDir := filepath.Dir(path)
		if _, err = os.Stat(mapDir); os.IsNotExist(err) {
			if err = os.MkdirAll(mapDir, 0755); err != nil {
				return nil, fmt.Errorf("Unable create map base directory: %s", err)
			}
		}

		fd, err = bpf.CreateMap(
			C.BPF_MAP_TYPE_HASH,
			uint32(unsafe.Sizeof(uint16(0))),
			uint32(unsafe.Sizeof(LxcInfo{})),
			MAX_KEYS,
		)

		if err != nil {
			return nil, err
		}

		err = bpf.ObjPin(fd, path)
		if err != nil {
			return nil, err
		}
	} else {
		fd, err = bpf.ObjGet(path)
		if err != nil {
			return nil, err
		}

		// FIXME: Read in existing container data
	}

	m := new(LxcMap)
	m.fd = fd

	return m, nil
}
