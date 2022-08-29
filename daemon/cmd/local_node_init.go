package cmd

import (
	"context"
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/spf13/pflag"
	"go.uber.org/fx"
)

// localNodeInitCell provides the initialization of the local node store.
var localNodeInitCell = hive.NewCellWithConfig[daemonLocalNodeConfig](
	"daemon-local-node-init",
	fx.Provide(
		func(clientset k8sClient.Clientset, config daemonLocalNodeConfig) node.LocalNodeInitializer {
			return &daemonLocalNodeInit{clientset, config}
		},
	),
)

// daemonLocalNodeConfig has the configuration options for affecting the initialization
// of the local node state.
type daemonLocalNodeConfig struct {
	// IPv4NodeAddr is the IPv4 address for the local node.
	IPv4NodeAddr string

	// IPv6NodeAddr is the IPv6 address for the local node.
	IPv6NodeAddr string

	IPv4Range string
	IPv6Range string

	// TODO(JM): These get filled in by convention from viper. We might instead want to
	// depend explicitly on some base configuration that has these.
	EnableIPv4          bool
	EnableIPv6          bool
	DirectRoutingDevice string
	Tunnel              string
}

func (daemonLocalNodeConfig) CellFlags(flags *pflag.FlagSet) {
	flags.String(option.IPv4NodeAddr, "auto", "IPv4 address of node")
	flags.String(option.IPv6NodeAddr, "auto", "IPv6 address of node")
	flags.String(option.IPv4Range, AutoCIDR, "Per-node IPv4 endpoint prefix, e.g. 10.16.0.0/16")
	flags.String(option.IPv6Range, AutoCIDR, "Per-node IPv6 endpoint prefix, e.g. fd02:1:1::/96")
}

type daemonLocalNodeInit struct {
	clientset k8sClient.Clientset
	config    daemonLocalNodeConfig
}

func (ni *daemonLocalNodeInit) InitLocalNode(localNode *nodeTypes.Node) error {
	// Initialize the local node first from configuration.
	if err := ni.initLocalNodeFromConfig(localNode); err != nil {
		return err
	}

	// And then from k8s if enabled.
	if ni.clientset.IsEnabled() {
		if err := ni.initLocalNodeFromK8s(localNode); err != nil {
			return err
		}
	}

	return ni.validate(localNode)
}

func (ni *daemonLocalNodeInit) initLocalNodeFromConfig(localNode *nodeTypes.Node) error {
	if ni.config.IPv6NodeAddr != "auto" {
		if ip := net.ParseIP(ni.config.IPv6NodeAddr); ip == nil {
			return fmt.Errorf("Invalid IPv6 node address: %q", ni.config.IPv6NodeAddr)
		} else {
			if !ip.IsGlobalUnicast() {
				return fmt.Errorf("Invalid IPv6 node address: %q, not a global unicast address", ni.config.IPv6NodeAddr)
			}
			localNode.IPAddresses =
				append(localNode.IPAddresses,
					nodeTypes.Address{
						Type: addressing.NodeInternalIP,
						IP:   ip,
					})
		}
	}

	if ni.config.IPv4NodeAddr != "auto" {
		if ip := net.ParseIP(ni.config.IPv4NodeAddr); ip == nil {
			return fmt.Errorf("Invalid IPv4 node address: %q", ni.config.IPv4NodeAddr)
		} else {
			localNode.IPAddresses =
				append(localNode.IPAddresses,
					nodeTypes.Address{
						Type: addressing.NodeInternalIP,
						IP:   ip,
					})
		}
	}

	// If the device has been specified, the IPv4AllocPrefix and the
	// IPv6AllocPrefix were already allocated before the k8s.Init().
	//
	// If the device hasn't been specified, k8s.Init() allocated the
	// IPv4AllocPrefix and the IPv6AllocPrefix from k8s node annotations.
	//
	// If k8s.Init() failed to retrieve the IPv4AllocPrefix we can try to derive
	// it from an existing node_config.h file or from previous cilium_host
	// interfaces.
	//
	// Then, we will calculate the IPv4 or IPv6 alloc prefix based on the IPv6
	// or IPv4 alloc prefix, respectively, retrieved by k8s node annotations.
	if ni.config.IPv4Range != AutoCIDR {
		allocCIDR, err := cidr.ParseCIDR(ni.config.IPv4Range)
		if err != nil {
			log.WithError(err).WithField(logfields.V4Prefix, ni.config.IPv4Range).Fatal("Invalid IPv4 allocation prefix")
		}
		localNode.IPv4AllocCIDR = allocCIDR
	}

	if ni.config.IPv6Range != AutoCIDR {
		allocCIDR, err := cidr.ParseCIDR(ni.config.IPv6Range)
		if err != nil {
			log.WithError(err).WithField(logfields.V6Prefix, ni.config.IPv6Range).Fatal("Invalid IPv6 allocation prefix")
		}
		localNode.IPv6AllocCIDR = allocCIDR
	}

	return nil
}

func (ni *daemonLocalNodeInit) initLocalNodeFromK8s(localNode *nodeTypes.Node) error {
	getter := k8s.K8sClient{Interface: ni.clientset}
	bootstrapStats.k8sInit.Start()
	n, err := k8s.WaitForNodeInformation(context.TODO(), getter)
	bootstrapStats.k8sInit.End(err == nil)
	if n == nil || err != nil {
		return fmt.Errorf("Failed to populate local node: %w", err)
	}

	// Information from K8s overrides existing settings.
	*localNode = *n

	return nil
}

func (ni *daemonLocalNodeInit) validate(localNode *nodeTypes.Node) error {
	if ni.config.EnableIPv6 && localNode.IPv6AllocCIDR == nil {
		return fmt.Errorf("IPv6 allocation CIDR is not configured. Please specificy --%s", option.IPv6Range)
	}

	if ni.config.EnableIPv4 && localNode.IPv4AllocCIDR == nil {
		return fmt.Errorf("IPv4 allocation CIDR is not configured. Please specificy --%s", option.IPv4Range)
	}

	if ni.config.EnableIPv4 || ni.config.Tunnel != option.TunnelDisabled {
		if localNode.GetNodeIP(false) == nil {
			return fmt.Errorf("external IPv4 node address could not be derived, please configure via --ipv4-node")
		}
	}

	/*
		if option.Config.EnableIPv4 && addrs.ipv4RouterAddress == nil {
			return fmt.Errorf("BUG: Internal IPv4 node address was not configured")
		}*/

	return nil
}
