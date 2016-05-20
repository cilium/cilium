package daemon

import (
	"fmt"
	"net"
	"sync"

	"github.com/noironetworks/cilium-net/common"
	"github.com/noironetworks/cilium-net/common/types"

	cniTypes "github.com/appc/cni/pkg/types"
	hb "github.com/appc/cni/plugins/ipam/host-local/backend"
	dClient "github.com/docker/engine-api/client"
	consulAPI "github.com/hashicorp/consul/api"
	"github.com/op/go-logging"
	k8sClientConfig "k8s.io/kubernetes/pkg/client/restclient"
	k8sClient "k8s.io/kubernetes/pkg/client/unversioned"
	"k8s.io/kubernetes/pkg/registry/service/ipallocator"
)

var (
	log = logging.MustGetLogger("cilium-net")
)

// Daemon is the cilium daemon that is in charge of perform all necessary plumbing,
// monitoring when a LXC starts.
type Daemon struct {
	ipamConf             map[types.IPAMType]*types.IPAMConfig
	consul               *consulAPI.Client
	endpoints            map[string]*types.Endpoint
	endpointsMU          sync.Mutex
	validLabelPrefixesMU sync.Mutex
	dockerClient         *dClient.Client
	k8sClient            *k8sClient.Client
	conf                 *Config
}

func createConsulClient(config *consulAPI.Config) (*consulAPI.Client, error) {
	if config != nil {
		return consulAPI.NewClient(config)
	}
	return consulAPI.NewClient(consulAPI.DefaultConfig())
}

func createDockerClient(endpoint string) (*dClient.Client, error) {
	defaultHeaders := map[string]string{"User-Agent": "cilium"}
	return dClient.NewClient(endpoint, "v1.21", nil, defaultHeaders)
}

func createK8sClient(endpoint string) (*k8sClient.Client, error) {
	config := k8sClientConfig.Config{Host: endpoint}
	k8sClientConfig.SetKubernetesDefaults(&config)
	return k8sClient.New(&config)
}

// NewDaemon creates and returns a new Daemon with the parameters set in c.
func NewDaemon(c *Config) (*Daemon, error) {
	if c == nil {
		return nil, fmt.Errorf("Configuration is nil")
	}
	ones, bits := common.NodeIPv6Mask.Size()
	maskPerIPAMType := ones + 1
	ipamSubnets := net.IPNet{IP: c.NodeAddress, Mask: net.CIDRMask(maskPerIPAMType, bits)}
	cniIPAMSubnet := ipamSubnets
	libnetworkIPAMSubnet := net.IPNet{IP: common.NextNetwork(ipamSubnets), Mask: net.CIDRMask(maskPerIPAMType, bits)}
	nodeRoute := net.IPNet{IP: c.NodeAddress, Mask: common.ContainerIPv6Mask}

	ipamConf := map[types.IPAMType]*types.IPAMConfig{
		types.CNIIPAMType: &types.IPAMConfig{
			IPAMConfig: hb.IPAMConfig{
				Name:    string(types.CNIIPAMType),
				Subnet:  cniTypes.IPNet(cniIPAMSubnet),
				Gateway: c.NodeAddress,
				Routes: []cniTypes.Route{
					cniTypes.Route{
						Dst: nodeRoute,
					},
					cniTypes.Route{
						Dst: net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
						GW:  c.NodeAddress,
					},
				},
			},
			IPAllocator: ipallocator.NewCIDRRange(&cniIPAMSubnet),
		},
		types.LibnetworkIPAMType: &types.IPAMConfig{
			IPAMConfig: hb.IPAMConfig{
				Name:    string(types.LibnetworkIPAMType),
				Subnet:  cniTypes.IPNet(libnetworkIPAMSubnet),
				Gateway: c.NodeAddress,
				Routes: []cniTypes.Route{
					cniTypes.Route{
						Dst: nodeRoute,
					},
					cniTypes.Route{
						Dst: net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
						GW:  c.NodeAddress,
					},
				},
			},
			IPAllocator: ipallocator.NewCIDRRange(&libnetworkIPAMSubnet),
		},
	}

	consul, err := createConsulClient(c.ConsulConfig)
	if err != nil {
		return nil, err
	}

	dockerClient, err := createDockerClient(c.DockerEndpoint)
	if err != nil {
		return nil, err
	}

	k8sClient, err := createK8sClient(c.K8sEndpoint)
	if err != nil {
		return nil, err
	}

	d := Daemon{
		conf:         c,
		ipamConf:     ipamConf,
		consul:       consul,
		dockerClient: dockerClient,
		k8sClient:    k8sClient,
		endpoints:    make(map[string]*types.Endpoint),
	}

	if c.RestoreState {
		if err := d.SyncState(common.CiliumPath, true); err != nil {
			log.Warningf("Error while syncing state %s\n", err)
		}
	}

	return &d, nil
}
