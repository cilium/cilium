package daemon

import (
	"net"

	consulAPI "github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/hashicorp/consul/api"
	"github.com/noironetworks/cilium-net/bpf/lxcmap"
)

// Config is the configuration used by Daemon.
type Config struct {
	LibDir             string            // Cilium library directory
	LXCMap             *lxcmap.LXCMap    // LXCMap where all LXCs are stored
	NodeAddress        net.IP            // Node IPv6 Address
	IPv4Range          *net.IPNet        // Containers IPv4 Address range
	ConsulConfig       *consulAPI.Config // Consul configuration
	DockerEndpoint     string            // Docker endpoint
	K8sEndpoint        string            // Kubernetes endpoint
	ValidLabelPrefixes []string          // Label prefixes used to filter from all labels
}
