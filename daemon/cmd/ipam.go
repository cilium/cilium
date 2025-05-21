// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/cidr"
	linuxrouting "github.com/cilium/cilium/pkg/datapath/linux/routing"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/types"
	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipam"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/time"
)

const (
	mismatchRouterIPsMsg = "Mismatch of router IPs found during restoration. The Kubernetes resource contained %s, while the filesystem contained %s. Using the router IP from the filesystem. To change the router IP, specify --%s and/or --%s."
)

func (d *Daemon) allocateRouterIPv4(family types.NodeAddressingFamily, fromK8s, fromFS net.IP) (net.IP, error) {
	if option.Config.LocalRouterIPv4 != "" {
		routerIP := net.ParseIP(option.Config.LocalRouterIPv4)
		if routerIP == nil {
			return nil, fmt.Errorf("Invalid local-router-ip: %s", option.Config.LocalRouterIPv4)
		}
		if d.nodeAddressing.IPv4().AllocationCIDR().Contains(routerIP) {
			d.logger.Warn("Specified router IP is within IPv4 podCIDR.")
		}
		return routerIP, nil
	} else {
		return d.allocateDatapathIPs(family, fromK8s, fromFS)
	}
}

func (d *Daemon) allocateRouterIPv6(family types.NodeAddressingFamily, fromK8s, fromFS net.IP) (net.IP, error) {
	if option.Config.LocalRouterIPv6 != "" {
		routerIP := net.ParseIP(option.Config.LocalRouterIPv6)
		if routerIP == nil {
			return nil, fmt.Errorf("Invalid local-router-ip: %s", option.Config.LocalRouterIPv6)
		}
		if d.nodeAddressing.IPv6().AllocationCIDR().Contains(routerIP) {
			d.logger.Warn("Specified router IP is within IPv6 podCIDR.")
		}
		return routerIP, nil
	} else {
		return d.allocateDatapathIPs(family, fromK8s, fromFS)
	}
}

// Coalesce CIDRS when allocating the DatapathIPs and healthIPs. GH #18868
func coalesceCIDRs(rCIDRs []string) (result []string, err error) {
	cidrs := make([]*net.IPNet, 0, len(rCIDRs))
	for _, k := range rCIDRs {
		ip, mask, err := net.ParseCIDR(k)
		if err != nil {
			return nil, err
		}
		cidrs = append(cidrs, &net.IPNet{IP: ip, Mask: mask.Mask})
	}
	ipv4cidr, ipv6cidr := iputil.CoalesceCIDRs(cidrs)
	combinedcidrs := append(ipv4cidr, ipv6cidr...)
	result = make([]string, len(combinedcidrs))
	for i, k := range combinedcidrs {
		result[i] = k.String()
	}
	return
}

type ipamAllocateIP interface {
	AllocateIPWithoutSyncUpstream(ip net.IP, owner string, pool ipam.Pool) (*ipam.AllocationResult, error)
}

// reallocateDatapathIPs attempts to reallocate the old router IP from IPAM.
// It prefers fromFS over fromK8s. If neither IPs can be re-allocated, log
// messages are emitted and the function returns nil.
func reallocateDatapathIPs(logger *slog.Logger, alloc ipamAllocateIP, fromK8s, fromFS net.IP) (result *ipam.AllocationResult) {
	if fromK8s == nil && fromFS == nil {
		// We do nothing in this case because there are no router IPs to restore.
		return nil
	}

	// If we have both an IP from the filesystem and an IP from the Kubernetes
	// resource, and they are not equal, emit a warning.
	if fromK8s != nil && fromFS != nil && !fromK8s.Equal(fromFS) {
		logger.Warn(
			fmt.Sprintf(
				mismatchRouterIPsMsg,
				fromK8s, fromFS, option.LocalRouterIPv4, option.LocalRouterIPv6,
			),
		)
		// Above is just a warning; we still want to set the router IP regardless.
	}

	// Router IPs from the filesystem are preferred over the IPs found
	// in the Kubernetes resource (Node or CiliumNode), because we consider the
	// filesystem to be the most up-to-date source of truth.
	var err error
	if fromFS != nil {
		result, err = alloc.AllocateIPWithoutSyncUpstream(fromFS, "router", ipam.PoolDefault())
		if err != nil {
			logger.Warn(
				"Unable to restore router IP from filesystem",
				logfields.Error, err,
				logfields.IPAddr, fromFS,
			)
			result = nil
		}
		// Fall back to using the IP from the Kubernetes resource if available
	}

	// If we were not able to restore the IP from the filesystem, try to use
	// the IP from the Kubernetes resource.
	if result == nil && fromK8s != nil {
		result, err = alloc.AllocateIPWithoutSyncUpstream(fromK8s, "router", ipam.PoolDefault())
		if err != nil {
			logger.Warn(
				"Unable to restore router IP from kubernetes",
				logfields.Error, err,
				logfields.IPAddr, fromFS,
			)
			result = nil
		}
		// Fall back to allocating a fresh IP
	}

	if result == nil {
		logger.Warn("Router IP could not be re-allocated. Need to re-allocate. This will cause brief network disruption")
	}

	return result
}

func (d *Daemon) allocateDatapathIPs(family types.NodeAddressingFamily, fromK8s, fromFS net.IP) (routerIP net.IP, err error) {
	// Avoid allocating external IP
	d.ipam.ExcludeIP(family.PrimaryExternal(), "node-ip", ipam.PoolDefault())

	// (Re-)allocate the router IP. If not possible, allocate a fresh IP.
	// In that case, the old router IP needs to be removed from cilium_host
	// by the caller.
	// This will also cause disruption of networking until all endpoints
	// have been regenerated.
	result := reallocateDatapathIPs(d.logger, d.ipam, fromK8s, fromFS)
	if result == nil {
		family := ipam.DeriveFamily(family.PrimaryExternal())
		result, err = d.ipam.AllocateNextFamilyWithoutSyncUpstream(family, "router", ipam.PoolDefault())
		if err != nil {
			return nil, fmt.Errorf("Unable to allocate router IP for family %s: %w", family, err)
		}
	}

	ipfamily := ipam.DeriveFamily(family.PrimaryExternal())
	masq := (ipfamily == ipam.IPv4 && option.Config.EnableIPv4Masquerade) ||
		(ipfamily == ipam.IPv6 && option.Config.EnableIPv6Masquerade)

	// Coalescing multiple CIDRs. GH #18868
	if masq &&
		option.Config.IPAM == ipamOption.IPAMENI &&
		result != nil &&
		len(result.CIDRs) > 0 {
		result.CIDRs, err = coalesceCIDRs(result.CIDRs)
		if err != nil {
			return nil, fmt.Errorf("failed to coalesce CIDRs: %w", err)
		}
	}

	if (option.Config.IPAM == ipamOption.IPAMENI ||
		option.Config.IPAM == ipamOption.IPAMAlibabaCloud ||
		option.Config.IPAM == ipamOption.IPAMAzure) && result != nil {
		var routingInfo *linuxrouting.RoutingInfo
		routingInfo, err = linuxrouting.NewRoutingInfo(d.logger, result.GatewayIP, result.CIDRs,
			result.PrimaryMAC, result.InterfaceNumber, option.Config.IPAM,
			masq)
		if err != nil {
			return nil, fmt.Errorf("failed to create router info: %w", err)
		}
		if err = routingInfo.Configure(
			result.IP,
			d.mtuConfig.GetDeviceMTU(),
			option.Config.EgressMultiHomeIPRuleCompat,
			true,
		); err != nil {
			return nil, fmt.Errorf("failed to configure router IP rules and routes: %w", err)
		}

		node.SetRouterInfo(routingInfo)

		d.jobGroup.Add(job.OneShot("egress-route-reconciler", func(ctx context.Context, health cell.Health) error {
			// Limit the rate of reconciliation if for whatever reason the routes
			// table is very busy. Once every 30 seconds seems reasonable as a
			// worst case scenario.
			limiter := rate.NewLimiter(30*time.Second, 1)

			for {
				watchSet, err := routingInfo.ReconcileGatewayRoutes(
					d.mtuConfig.GetDeviceMTU(),
					option.Config.EgressMultiHomeIPRuleCompat,
					d.db.ReadTxn(),
					d.routes,
				)
				if err != nil {
					health.Degraded("Failed to install egress routes", err)
					limiter.Wait(ctx)
					continue
				}

				health.OK("Egress routes installed")

				limiter.Wait(ctx)

				_, err = watchSet.Wait(ctx, 0)
				if err != nil {
					return err
				}
			}
		}))
	}

	return result.IP, nil
}

func (d *Daemon) allocateHealthIPs() error {
	bootstrapStats.healthCheck.Start()
	defer bootstrapStats.healthCheck.End(true)
	if !option.Config.EnableHealthChecking || !option.Config.EnableEndpointHealthChecking {
		return nil
	}
	var healthIPv4, healthIPv6 net.IP
	if option.Config.EnableIPv4 {
		var result *ipam.AllocationResult
		var err error
		healthIPv4 = node.GetEndpointHealthIPv4(d.logger)
		if healthIPv4 != nil {
			result, err = d.ipam.AllocateIPWithoutSyncUpstream(healthIPv4, "health", ipam.PoolDefault())
			if err != nil {
				d.logger.Warn(
					"unable to re-allocate health IPv4, a new health IPv4 will be allocated",
					logfields.Error, err,
					logfields.IPv4, healthIPv4,
				)
				healthIPv4 = nil
			}
		}
		if healthIPv4 == nil {
			result, err = d.ipam.AllocateNextFamilyWithoutSyncUpstream(ipam.IPv4, "health", ipam.PoolDefault())
			if err != nil {
				return fmt.Errorf("unable to allocate health IPv4: %w, see https://cilium.link/ipam-range-full", err)
			}
			node.SetEndpointHealthIPv4(result.IP)
		}

		// Coalescing multiple CIDRs. GH #18868
		if option.Config.EnableIPv4Masquerade &&
			option.Config.IPAM == ipamOption.IPAMENI &&
			result != nil &&
			len(result.CIDRs) > 0 {
			result.CIDRs, err = coalesceCIDRs(result.CIDRs)
			if err != nil {
				return fmt.Errorf("failed to coalesce CIDRs: %w", err)
			}
		}

		d.logger.Debug("IPv4 health endpoint address", logfields.IPAddr, result.IP)

		// In ENI and AlibabaCloud ENI mode, we require the gateway, CIDRs, and the ENI MAC addr
		// in order to set up rules and routes on the local node to direct
		// endpoint traffic out of the ENIs.
		if option.Config.IPAM == ipamOption.IPAMENI || option.Config.IPAM == ipamOption.IPAMAlibabaCloud {
			if d.healthEndpointRouting, err = parseRoutingInfo(result); err != nil {
				d.logger.Warn("Unable to allocate health information for ENI", logfields.Error, err)
			}
		}
	}

	if option.Config.EnableIPv6 {
		var result *ipam.AllocationResult
		var err error
		healthIPv6 = node.GetEndpointHealthIPv6(d.logger)
		if healthIPv6 != nil {
			result, err = d.ipam.AllocateIPWithoutSyncUpstream(healthIPv6, "health", ipam.PoolDefault())
			if err != nil {
				d.logger.Warn(
					"unable to re-allocate health IPv6, a new health IPv6 will be allocated",
					logfields.Error, err,
					logfields.IPv6, healthIPv6,
				)
				healthIPv6 = nil
			}
		}
		if healthIPv6 == nil {
			result, err = d.ipam.AllocateNextFamilyWithoutSyncUpstream(ipam.IPv6, "health", ipam.PoolDefault())
			if err != nil {
				if healthIPv4 != nil {
					d.ipam.ReleaseIP(healthIPv4, ipam.PoolDefault())
					node.SetEndpointHealthIPv4(nil)
				}
				return fmt.Errorf("unable to allocate health IPv6: %w, see https://cilium.link/ipam-range-full", err)
			}
			node.SetEndpointHealthIPv6(result.IP)
		}
		d.logger.Debug("IPv6 health endpoint address", logfields.IPAddr, result.IP)
	}
	return nil
}

func (d *Daemon) allocateIngressIPs() error {
	bootstrapStats.ingressIPAM.Start()
	if option.Config.EnableEnvoyConfig {
		if option.Config.EnableIPv4 {
			var result *ipam.AllocationResult
			var err error

			// Reallocate the same address as before, if possible
			ingressIPv4 := node.GetIngressIPv4(d.logger)
			if ingressIPv4 != nil {
				result, err = d.ipam.AllocateIPWithoutSyncUpstream(ingressIPv4, "ingress", ipam.PoolDefault())
				if err != nil {
					d.logger.Warn("unable to re-allocate ingress IPv4.",
						logfields.Error, err,
						logfields.SourceIP, ingressIPv4,
					)
					result = nil
				}
			}

			// Allocate a fresh IP if not restored, or the reallocation of the restored
			// IP failed
			if result == nil {
				result, err = d.ipam.AllocateNextFamilyWithoutSyncUpstream(ipam.IPv4, "ingress", ipam.PoolDefault())
				if err != nil {
					return fmt.Errorf("unable to allocate ingress IPs: %w, see https://cilium.link/ipam-range-full", err)
				}
			}

			// Coalescing multiple CIDRs. GH #18868
			if option.Config.EnableIPv4Masquerade &&
				option.Config.IPAM == ipamOption.IPAMENI &&
				result != nil &&
				len(result.CIDRs) > 0 {
				result.CIDRs, err = coalesceCIDRs(result.CIDRs)
				if err != nil {
					return fmt.Errorf("failed to coalesce CIDRs: %w", err)
				}
			}

			node.SetIngressIPv4(result.IP)
			d.logger.Info(fmt.Sprintf("  Ingress IPv4: %s", node.GetIngressIPv4(d.logger)))

			// In ENI and AlibabaCloud ENI mode, we require the gateway, CIDRs, and the
			// ENI MAC addr in order to set up rules and routes on the local node to
			// direct ingress traffic out of the ENIs.
			if option.Config.IPAM == ipamOption.IPAMENI || option.Config.IPAM == ipamOption.IPAMAlibabaCloud {
				if ingressRouting, err := parseRoutingInfo(result); err != nil {
					d.logger.Warn("Unable to allocate ingress information for ENI", logfields.Error, err)
				} else {
					if err := ingressRouting.Configure(
						result.IP,
						d.mtuConfig.GetDeviceMTU(),
						option.Config.EgressMultiHomeIPRuleCompat,
						false,
					); err != nil {
						d.logger.Warn("Error while configuring ingress IP rules and routes.", logfields.Error, err)
					}
				}
			}
		}

		// Only allocate if enabled and not restored already
		if option.Config.EnableIPv6 {
			var result *ipam.AllocationResult
			var err error

			// Reallocate the same address as before, if possible
			ingressIPv6 := node.GetIngressIPv6(d.logger)
			if ingressIPv6 != nil {
				result, err = d.ipam.AllocateIPWithoutSyncUpstream(ingressIPv6, "ingress", ipam.PoolDefault())
				if err != nil {
					d.logger.Warn("unable to re-allocate ingress IPv6.",
						logfields.Error, err,
						logfields.SourceIP, ingressIPv6,
					)
					result = nil
				}
			}

			// Allocate a fresh IP if not restored, or the reallocation of the restored
			// IP failed
			if result == nil {
				result, err = d.ipam.AllocateNextFamilyWithoutSyncUpstream(ipam.IPv6, "ingress", ipam.PoolDefault())
				if err != nil {
					if ingressIPv4 := node.GetIngressIPv4(d.logger); ingressIPv4 != nil {
						d.ipam.ReleaseIP(ingressIPv4, ipam.PoolDefault())
						node.SetIngressIPv4(nil)
					}
					return fmt.Errorf("unable to allocate ingress IPs: %w, see https://cilium.link/ipam-range-full", err)
				}
			}

			// Coalescing multiple CIDRs. GH #18868
			if option.Config.EnableIPv6Masquerade &&
				option.Config.IPAM == ipamOption.IPAMENI &&
				result != nil &&
				len(result.CIDRs) > 0 {
				result.CIDRs, err = coalesceCIDRs(result.CIDRs)
				if err != nil {
					return fmt.Errorf("failed to coalesce CIDRs: %w", err)
				}
			}

			node.SetIngressIPv6(result.IP)
			d.logger.Info(fmt.Sprintf("  Ingress IPv6: %s", node.GetIngressIPv6(d.logger)))
		}
	}
	bootstrapStats.ingressIPAM.End(true)
	return nil
}

type restoredIPs struct {
	IPv4FromK8s, IPv4FromFS net.IP
	IPv6FromK8s, IPv6FromFS net.IP
}

func (d *Daemon) allocateIPs(ctx context.Context, router restoredIPs) error {
	bootstrapStats.ipam.Start()

	if option.Config.EnableIPv4 {
		routerIP, err := d.allocateRouterIPv4(d.nodeAddressing.IPv4(), router.IPv4FromK8s, router.IPv4FromFS)
		if err != nil {
			return err
		}
		if routerIP != nil {
			node.SetInternalIPv4Router(routerIP)
		}
	}

	if option.Config.EnableIPv6 {
		routerIP, err := d.allocateRouterIPv6(d.nodeAddressing.IPv6(), router.IPv6FromK8s, router.IPv6FromFS)
		if err != nil {
			return err
		}
		if routerIP != nil {
			node.SetIPv6Router(routerIP)
		}
	}

	// Clean up any stale IPs from the `cilium_host` interface
	d.removeOldCiliumHostIPs(ctx, node.GetInternalIPv4Router(d.logger), node.GetIPv6Router(d.logger))

	d.logger.Info("Addressing information:")
	d.logger.Info(fmt.Sprintf("  Cluster-Name: %s", option.Config.ClusterName))
	d.logger.Info(fmt.Sprintf("  Cluster-ID: %d", option.Config.ClusterID))
	d.logger.Info(fmt.Sprintf("  Local node-name: %s", nodeTypes.GetName()))
	d.logger.Info(fmt.Sprintf("  Node-IPv6: %s", node.GetIPv6(d.logger)))

	iter := d.nodeAddrs.All(d.db.ReadTxn())
	addrs := statedb.Collect(
		statedb.Filter(
			iter,
			func(addr tables.NodeAddress) bool { return addr.DeviceName != tables.WildcardDeviceName }))

	if option.Config.EnableIPv6 {
		d.logger.Debug(fmt.Sprintf("  IPv6 allocation prefix: %s", node.GetIPv6AllocRange(d.logger)))

		if c := option.Config.IPv6NativeRoutingCIDR; c != nil {
			d.logger.Info(fmt.Sprintf("  IPv6 native routing prefix: %s", c.String()))
		}

		d.logger.Info(fmt.Sprintf("  IPv6 router address: %s", node.GetIPv6Router(d.logger)))

		d.logger.Info("  Local IPv6 addresses:")
		for _, addr := range addrs {
			if addr.Addr.Is6() {
				d.logger.Info(fmt.Sprintf("  - %s", addr.Addr))
			}
		}
	}

	d.logger.Info(fmt.Sprintf("  External-Node IPv4: %s", node.GetIPv4(d.logger)))
	d.logger.Info(fmt.Sprintf("  Internal-Node IPv4: %s", node.GetInternalIPv4Router(d.logger)))

	if option.Config.EnableIPv4 {
		d.logger.Debug(fmt.Sprintf("  IPv4 allocation prefix: %s", node.GetIPv4AllocRange(d.logger)))

		if c := option.Config.IPv4NativeRoutingCIDR; c != nil {
			d.logger.Info(fmt.Sprintf("  IPv4 native routing prefix: %s", c.String()))
		}

		// Allocate IPv4 service loopback IP
		loopbackIPv4 := net.ParseIP(option.Config.ServiceLoopbackIPv4)
		if loopbackIPv4 == nil {
			return fmt.Errorf("Invalid IPv4 loopback address %s", option.Config.ServiceLoopbackIPv4)
		}
		node.SetServiceLoopbackIPv4(loopbackIPv4)
		d.logger.Info(fmt.Sprintf("  Loopback IPv4: %s", node.GetServiceLoopbackIPv4(d.logger).String()))

		d.logger.Info("  Local IPv4 addresses:")
		for _, addr := range addrs {
			if addr.Addr.Is4() {
				d.logger.Info(fmt.Sprintf("  - %s", addr.Addr))
			}
		}
	}

	bootstrapStats.ipam.End(true)

	if option.Config.EnableEnvoyConfig {
		if err := d.allocateIngressIPs(); err != nil {
			return err
		}
	}

	return d.allocateHealthIPs()
}

func (d *Daemon) configureIPAM() {
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
				d.logger,
				"Invalid IPv4 allocation prefix",
				logfields.Error, err,
				logfields.V4Prefix, option.Config.IPv4Range,
			)
		}
		node.SetIPv4AllocRange(allocCIDR)
	}

	if option.Config.IPv6Range != AutoCIDR {
		allocCIDR, err := cidr.ParseCIDR(option.Config.IPv6Range)
		if err != nil {
			logging.Fatal(
				d.logger,
				"Invalid IPv6 allocation prefix",
				logfields.Error, err,
				logfields.V6Prefix, option.Config.IPv6Range,
			)
		}

		node.SetIPv6NodeRange(allocCIDR)
	}

	device := ""
	drd, _ := d.directRoutingDev.Get(d.ctx, d.db.ReadTxn())
	if drd != nil {
		device = drd.Name
	}
	if err := node.AutoComplete(d.logger, device); err != nil {
		logging.Fatal(d.logger, "Cannot autocomplete node addresses", logfields.Error, err)
	}
}

func (d *Daemon) startIPAM() {
	bootstrapStats.ipam.Start()
	d.logger.Info("Initializing node addressing")
	// Set up ipam conf after init() because we might be running d.conf.KVStoreIPv4Registration
	d.ipam.ConfigureAllocator()
	bootstrapStats.ipam.End(true)
}

func parseRoutingInfo(result *ipam.AllocationResult) (*linuxrouting.RoutingInfo, error) {
	if result.IP.To4() != nil {
		return linuxrouting.NewRoutingInfo(
			logging.DefaultSlogLogger,
			result.GatewayIP,
			result.CIDRs,
			result.PrimaryMAC,
			result.InterfaceNumber,
			option.Config.IPAM,
			option.Config.EnableIPv4Masquerade,
		)
	} else {
		return linuxrouting.NewRoutingInfo(
			logging.DefaultSlogLogger,
			result.GatewayIP,
			result.CIDRs,
			result.PrimaryMAC,
			result.InterfaceNumber,
			option.Config.IPAM,
			option.Config.EnableIPv6Masquerade,
		)
	}
}
