package daemon

import (
	"net"

	"github.com/noironetworks/cilium-net/bpf/lxcmap"
	"github.com/noironetworks/cilium-net/common"

	"github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/appc/cni/pkg/types"
	hb "github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/appc/cni/plugins/ipam/host-local/backend"
	"github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/hashicorp/consul/api"
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
	consul   *api.Client
}

func NewDaemon(libdir string, m *lxcmap.LxcMap, nodeAddr net.IP, consulConfig *api.Config) (*Daemon, error) {
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

	var (
		consul *api.Client
		err    error
	)
	if consulConfig != nil {
		consul, err = api.NewClient(consulConfig)
	} else {
		consul, err = api.NewClient(api.DefaultConfig())
	}
	if err != nil {
		return nil, err
	}

	return &Daemon{
		libDir:   libdir,
		lxcMap:   m,
		ipamConf: ipamConf,
		consul:   consul,
	}, nil
}
