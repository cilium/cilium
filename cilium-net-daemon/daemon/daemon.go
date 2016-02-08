package daemon

import (
	"net"

	"github.com/noironetworks/cilium-net/bpf/lxcmap"
	"github.com/noironetworks/cilium-net/common"

	"github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/appc/cni/pkg/types"
	hb "github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/appc/cni/plugins/ipam/host-local/backend"
	"github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/op/go-logging"
)

const (
	ipamType = "cilium-host-local"
)

var (
	log = logging.MustGetLogger("cilium-net")
)

type Daemon struct {
	libDir   string
	lxcMap   *lxcmap.LxcMap
	ipamConf hb.IPAMConfig
}

func NewDaemon(libdir string, m *lxcmap.LxcMap, nodeAddr net.IP) *Daemon {
	nodeSubNet := net.IPNet{IP: nodeAddr, Mask: common.ContainerIPv6Mask}
	nodeRoute := net.IPNet{IP: nodeAddr, Mask: common.ContainerIPv6Mask}

	ipamConf := hb.IPAMConfig{
		Type:    ipamType,
		Subnet:  types.IPNet(nodeSubNet),
		Gateway: nodeAddr,
		Routes: []types.Route{
			types.Route{
				Dst: nodeRoute,
			},
			types.Route{
				Dst: net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
				GW:  nodeAddr,
			},
		},
	}

	return &Daemon{
		libDir:   libdir,
		lxcMap:   m,
		ipamConf: ipamConf,
	}
}
