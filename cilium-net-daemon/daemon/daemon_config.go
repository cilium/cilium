package daemon

import (
	"net"

	consulAPI "github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/hashicorp/consul/api"
	"github.com/noironetworks/cilium-net/bpf/lxcmap"
)

type Config struct {
	LibDir             string
	LXCMap             *lxcmap.LxcMap
	NodeAddress        net.IP
	IPv4Range          *net.IPNet
	ConsulConfig       *consulAPI.Config
	DockerEndpoint     string
	K8sEndpoint        string
	ValidLabelPrefixes []string
}
