// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/cidr"
	datapathTables "github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

type ipamInitializerParams struct {
	cell.In

	Logger              *slog.Logger
	DirectRoutingDevice datapathTables.DirectRoutingDevice
	DB                  *statedb.DB
	IPAM                *ipam.IPAM
	LocalNodeStore      *node.LocalNodeStore
}

type ipamInitializer struct {
	logger              *slog.Logger
	directRoutingDevice datapathTables.DirectRoutingDevice
	db                  *statedb.DB
	ipam                *ipam.IPAM
	localNodeStore      *node.LocalNodeStore
}

func newIPAMInitializer(params ipamInitializerParams) *ipamInitializer {
	return &ipamInitializer{
		logger:              params.Logger,
		directRoutingDevice: params.DirectRoutingDevice,
		db:                  params.DB,
		ipam:                params.IPAM,
		localNodeStore:      params.LocalNodeStore,
	}
}

func (r *ipamInitializer) configureAndStartIPAM(ctx context.Context) {
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
	if option.Config.IPv4Range != AutoCIDR {
		allocCIDR, err := cidr.ParseCIDR(option.Config.IPv4Range)
		if err != nil {
			logging.Fatal(
				r.logger,
				"Invalid IPv4 allocation prefix",
				logfields.Error, err,
				logfields.V4Prefix, option.Config.IPv4Range,
			)
		}

		r.localNodeStore.Update(func(n *node.LocalNode) {
			n.IPv4AllocCIDR = allocCIDR
		})
	}

	if option.Config.IPv6Range != AutoCIDR {
		allocCIDR, err := cidr.ParseCIDR(option.Config.IPv6Range)
		if err != nil {
			logging.Fatal(
				r.logger,
				"Invalid IPv6 allocation prefix",
				logfields.Error, err,
				logfields.V6Prefix, option.Config.IPv6Range,
			)
		}

		r.localNodeStore.Update(func(n *node.LocalNode) {
			n.IPv6AllocCIDR = allocCIDR
		})
	}

	if err := r.AutoComplete(ctx); err != nil {
		logging.Fatal(r.logger, "Cannot autocomplete node addresses", logfields.Error, err)
	}

	// start
	r.logger.Info("Initializing node addressing")
	// Set up ipam conf after init() because we might be running d.conf.KVStoreIPv4Registration
	r.ipam.ConfigureAllocator()
}

func (r *ipamInitializer) RestoreFinished() {
	r.ipam.RestoreFinished()
}

// AutoComplete completes the parts of addressing that can be auto derived
func (r *ipamInitializer) AutoComplete(ctx context.Context) error {
	directRoutingDevice := ""
	drd, _ := r.directRoutingDevice.Get(ctx, r.db.ReadTxn())
	if drd != nil {
		directRoutingDevice = drd.Name
	}

	// initDefaultPrefix initializes the node address and allocation prefixes with
	// default values derived from the system. device can be set to the primary
	// network device of the system in which case the first address with global
	// scope will be regarded as the system's node address.
	r.localNodeStore.Update(func(n *node.LocalNode) {
		r.setDefaultPrefix(option.Config, directRoutingDevice, n)
	})

	ln, err := r.localNodeStore.Get(ctx)
	if err != nil {
		return fmt.Errorf("failed to retrieve local node: %w", err)
	}

	if option.Config.EnableIPv6 && ln.IPv6AllocCIDR == nil {
		return fmt.Errorf("IPv6 allocation CIDR is not configured. Please specify --%s", option.IPv6Range)
	}

	if option.Config.EnableIPv4 && ln.IPv4AllocCIDR == nil {
		return fmt.Errorf("IPv4 allocation CIDR is not configured. Please specify --%s", option.IPv4Range)
	}

	return nil
}

func (r *ipamInitializer) makeIPv6HostIP() net.IP {
	ipstr := "fc00::10CA:1"
	ip := net.ParseIP(ipstr)
	if ip == nil {
		logging.Fatal(r.logger, "Unable to parse IP", logfields.IPAddr, ipstr)
	}

	return ip
}

func (r *ipamInitializer) setDefaultPrefix(cfg *option.DaemonConfig, device string, localNode *node.LocalNode) {
	if cfg.EnableIPv4 {
		isIPv6 := false

		ip, err := node.FirstGlobalV4Addr(device, localNode.GetCiliumInternalIP(isIPv6))
		if err != nil {
			return
		}

		if localNode.GetNodeIP(isIPv6) == nil {
			localNode.SetNodeInternalIP(ip)
		}

		ipv4range := localNode.IPv4AllocCIDR
		ipv6range := localNode.IPv6AllocCIDR

		if ipv4range == nil {
			// If the IPv6AllocRange is not nil then the IPv4 allocation should be
			// derived from the IPv6AllocRange.
			//                     vvvv vvvv
			// FD00:0000:0000:0000:0000:0000:0000:0000
			if ipv6range != nil {
				ip = net.IPv4(
					ipv6range.IP[8],
					ipv6range.IP[9],
					ipv6range.IP[10],
					ipv6range.IP[11])
			}
			v4range := fmt.Sprintf(defaults.DefaultIPv4Prefix+"/%d",
				ip.To4()[3], defaults.DefaultIPv4PrefixLen)
			_, ip4net, err := net.ParseCIDR(v4range)
			if err != nil {
				logging.Panic(r.logger, "BUG: Invalid default IPv4 prefix",
					logfields.Error, err,
					logfields.V4Prefix, v4range,
				)
			}

			localNode.IPv4AllocCIDR = cidr.NewCIDR(ip4net)
			r.logger.Debug(
				"Using autogenerated IPv4 allocation range",
				logfields.V4Prefix, localNode.IPv4AllocCIDR,
			)
		}
	}

	if cfg.EnableIPv6 {
		isIPv6 := true
		ipv4range := localNode.IPv4AllocCIDR
		ipv6range := localNode.IPv6AllocCIDR

		if localNode.GetNodeIP(isIPv6) == nil {
			// Find a IPv6 node address first
			addr, _ := node.FirstGlobalV6Addr(device, localNode.GetCiliumInternalIP(isIPv6))
			if addr == nil {
				addr = r.makeIPv6HostIP()
			}
			localNode.SetNodeInternalIP(addr)
		}

		if ipv6range == nil {
			var v6range string
			var logMessage string
			if ipv4range != nil {
				// The IPv6 allocation should be derived from the IPv4 allocation.
				ip := localNode.IPv4AllocCIDR.IP
				v6range = fmt.Sprintf("%s%02x%02x:%02x%02x:0:0/%d",
					cfg.IPv6ClusterAllocCIDRBase, ip[0], ip[1], ip[2], ip[3], 96)
				logMessage = "Using autogenerated IPv6 allocation range from IPv4 allocation"
			} else {
				// The IPv6 allocation is derived from the node's IPv6 address.
				ip := localNode.GetNodeIP(isIPv6)
				if ip == nil {
					// This should not happen, as we set the node IP above.
					logging.Panic(r.logger, "BUG: Node IPv6 address is not available to derive IPv6 pod CIDR")
				}

				// We use the last 4 bytes of the node's IPv6 address to build the pod CIDR.
				// This makes the allocation logic independent of IPv4.
				v6range = fmt.Sprintf("%s%02x%02x:%02x%02x:0:0/%d",
					cfg.IPv6ClusterAllocCIDRBase, ip[12], ip[13], ip[14], ip[15], 96)
				logMessage = "Using autogenerated IPv6 allocation range from node IPv6"
			}

			_, ip6net, err := net.ParseCIDR(v6range)
			if err != nil {
				logging.Panic(r.logger, "BUG: Invalid default IPv6 prefix",
					logfields.Error, err,
					logfields.V6Prefix, v6range,
				)
			}

			localNode.IPv6AllocCIDR = cidr.NewCIDR(ip6net)
			r.logger.Debug(
				logMessage,
				logfields.V6Prefix, localNode.IPv6AllocCIDR,
			)
		}
	}
}
