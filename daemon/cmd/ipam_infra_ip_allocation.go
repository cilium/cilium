// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/util/wait"

	linuxrouting "github.com/cilium/cilium/pkg/datapath/linux/routing"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/tables"
	datapathTables "github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/types"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipam"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/resiliency"
	"github.com/cilium/cilium/pkg/time"
)

type infraIPAllocatorParams struct {
	cell.In

	Logger         *slog.Logger
	JobGroup       job.Group
	DB             *statedb.DB
	Routes         statedb.Table[*datapathTables.Route]
	NodeAddrs      statedb.Table[datapathTables.NodeAddress]
	NodeAddressing datapath.NodeAddressing
	MTU            mtu.MTU
	IPAM           *ipam.IPAM
}

// infraIPAllocator is responsible to create infra related IPs (router, ingress & health)
type infraIPAllocator struct {
	logger         *slog.Logger
	jobGroup       job.Group
	db             *statedb.DB
	routes         statedb.Table[*datapathTables.Route]
	nodeAddrs      statedb.Table[datapathTables.NodeAddress]
	nodeAddressing datapath.NodeAddressing
	mtuManager     mtu.MTU
	ipAllocator    ipamAllocator

	// healthEndpointRouting is the information required to set up the health
	// endpoint's routing in ENI or Azure IPAM mode
	healthEndpointRouting *linuxrouting.RoutingInfo
}

type ipamAllocator interface {
	AllocateIPWithoutSyncUpstream(ip net.IP, owner string, pool ipam.Pool) (*ipam.AllocationResult, error)
	AllocateNextFamilyWithoutSyncUpstream(family ipam.Family, owner string, pool ipam.Pool) (result *ipam.AllocationResult, err error)
	ExcludeIP(ip net.IP, owner string, pool ipam.Pool)
	ReleaseIP(ip net.IP, pool ipam.Pool) error
}

func newInfraIPAllocator(params infraIPAllocatorParams) *infraIPAllocator {
	return &infraIPAllocator{
		logger:         params.Logger,
		jobGroup:       params.JobGroup,
		db:             params.DB,
		routes:         params.Routes,
		nodeAddrs:      params.NodeAddrs,
		nodeAddressing: params.NodeAddressing,
		mtuManager:     params.MTU,
		ipAllocator:    params.IPAM,
	}
}

const (
	mismatchRouterIPsMsg = "Mismatch of router IPs found during restoration. The Kubernetes resource contained %s, while the filesystem contained %s. Using the router IP from the filesystem. To change the router IP, specify --%s and/or --%s."
)

func (r *infraIPAllocator) GetHealthEndpointRouting() *linuxrouting.RoutingInfo {
	return r.healthEndpointRouting
}

func (r *infraIPAllocator) allocateRouterIPv4(ctx context.Context, family types.NodeAddressingFamily, fromK8s, fromFS net.IP) (net.IP, error) {
	if option.Config.LocalRouterIPv4 != "" {
		routerIP := net.ParseIP(option.Config.LocalRouterIPv4)
		if routerIP == nil {
			return nil, fmt.Errorf("Invalid local-router-ip: %s", option.Config.LocalRouterIPv4)
		}
		if r.nodeAddressing.IPv4().AllocationCIDR().Contains(routerIP) {
			r.logger.Warn("Specified router IP is within IPv4 podCIDR.")
		}
		return routerIP, nil
	} else {
		return r.allocateDatapathIPs(ctx, family, fromK8s, fromFS)
	}
}

func (r *infraIPAllocator) allocateRouterIPv6(ctx context.Context, family types.NodeAddressingFamily, fromK8s, fromFS net.IP) (net.IP, error) {
	if option.Config.LocalRouterIPv6 != "" {
		routerIP := net.ParseIP(option.Config.LocalRouterIPv6)
		if routerIP == nil {
			return nil, fmt.Errorf("Invalid local-router-ip: %s", option.Config.LocalRouterIPv6)
		}
		if r.nodeAddressing.IPv6().AllocationCIDR().Contains(routerIP) {
			r.logger.Warn("Specified router IP is within IPv6 podCIDR.")
		}
		return routerIP, nil
	} else {
		return r.allocateDatapathIPs(ctx, family, fromK8s, fromFS)
	}
}

// Coalesce CIDRS when allocating the DatapathIPs and healthIPs. GH #18868
func (r *infraIPAllocator) coalesceCIDRs(rCIDRs []string) (result []string, err error) {
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
	return result, err
}

// reallocateDatapathIPs attempts to reallocate the old router IP from IPAM.
// It prefers fromFS over fromK8s. If neither IPs can be re-allocated, log
// messages are emitted and the function returns nil.
func (r *infraIPAllocator) reallocateDatapathIPs(fromK8s, fromFS net.IP) (result *ipam.AllocationResult) {
	if fromK8s == nil && fromFS == nil {
		// We do nothing in this case because there are no router IPs to restore.
		return nil
	}

	// If we have both an IP from the filesystem and an IP from the Kubernetes
	// resource, and they are not equal, emit a warning.
	if fromK8s != nil && fromFS != nil && !fromK8s.Equal(fromFS) {
		r.logger.Warn(
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
		result, err = r.ipAllocator.AllocateIPWithoutSyncUpstream(fromFS, "router", ipam.PoolDefault())
		if err != nil {
			r.logger.Warn(
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
		result, err = r.ipAllocator.AllocateIPWithoutSyncUpstream(fromK8s, "router", ipam.PoolDefault())
		if err != nil {
			r.logger.Warn(
				"Unable to restore router IP from kubernetes",
				logfields.Error, err,
				logfields.IPAddr, fromFS,
			)
			result = nil
		}
		// Fall back to allocating a fresh IP
	}

	if result == nil {
		r.logger.Warn("Router IP could not be re-allocated. Need to re-allocate. This will cause brief network disruption")
	}

	return result
}

func (r *infraIPAllocator) waitForENI(ctx context.Context, macAddr string) error {
	bo := wait.Backoff{
		Duration: 250 * time.Millisecond,
		Factor:   2,
		Jitter:   0.2,
		Steps:    5,
	}

	findENIByMAC := func(ctx context.Context) (bool, error) {
		links, err := safenetlink.LinkList()
		if err != nil {
			return false, fmt.Errorf("unable to list interfaces: %w", err)
		}

		for _, l := range links {
			// filter out slave devices
			if l.Attrs().RawFlags&unix.IFF_SLAVE != 0 {
				continue
			}
			if l.Attrs().HardwareAddr.String() == macAddr {
				return true, nil
			}
		}
		return false, nil
	}

	return wait.ExponentialBackoffWithContext(ctx, bo, findENIByMAC)
}

func (r *infraIPAllocator) allocateDatapathIPs(ctx context.Context, family types.NodeAddressingFamily, fromK8s, fromFS net.IP) (routerIP net.IP, err error) {
	// Avoid allocating external IP
	r.ipAllocator.ExcludeIP(family.PrimaryExternal(), "node-ip", ipam.PoolDefault())

	// (Re-)allocate the router IP. If not possible, allocate a fresh IP.
	// In that case, the old router IP needs to be removed from cilium_host
	// by the caller.
	// This will also cause disruption of networking until all endpoints
	// have been regenerated.
	result := r.reallocateDatapathIPs(fromK8s, fromFS)
	if result == nil {
		family := ipam.DeriveFamily(family.PrimaryExternal())
		result, err = r.ipAllocator.AllocateNextFamilyWithoutSyncUpstream(family, "router", ipam.PoolDefault())
		if err != nil {
			return nil, fmt.Errorf("Unable to allocate router IP for family %s: %w", family, err)
		}
	}

	ipfamily := ipam.DeriveFamily(family.PrimaryExternal())
	masq := (ipfamily == ipam.IPv4 && option.Config.EnableIPv4Masquerade) ||
		(ipfamily == ipam.IPv6 && option.Config.EnableIPv6Masquerade)

	// Coalescing multiple CIDRs. GH #18868
	if masq &&
		(option.Config.IPAM == ipamOption.IPAMENI || option.Config.IPAM == ipamOption.IPAMAzure) &&
		result != nil &&
		len(result.CIDRs) > 0 {
		result.CIDRs, err = r.coalesceCIDRs(result.CIDRs)
		if err != nil {
			return nil, fmt.Errorf("failed to coalesce CIDRs: %w", err)
		}
	}

	if (option.Config.IPAM == ipamOption.IPAMENI ||
		option.Config.IPAM == ipamOption.IPAMAlibabaCloud ||
		option.Config.IPAM == ipamOption.IPAMAzure) && result != nil {
		var routingInfo *linuxrouting.RoutingInfo
		routingInfo, err = linuxrouting.NewRoutingInfo(r.logger, result.GatewayIP, result.CIDRs,
			result.PrimaryMAC, result.InterfaceNumber, option.Config.IPAM,
			masq)
		if err != nil {
			return nil, fmt.Errorf("failed to create router info: %w", err)
		}

		// wait for ENI to be up and running before configuring routes and rules.
		// This avoids spurious errors where netlink is not able to find
		// the ifindex by its MAC because the ENI is not showing up yet.
		if option.Config.IPAM == ipamOption.IPAMENI {
			if err := r.waitForENI(ctx, result.PrimaryMAC); err != nil {
				r.logger.Warn("unable to find ENI netlink interface, this will likely lead to an error in configuring the router routes and rules",
					logfields.MACAddr, result.PrimaryMAC,
				)
			}
		}

		if err = routingInfo.Configure(
			result.IP,
			r.mtuManager.GetDeviceMTU(),
			option.Config.EgressMultiHomeIPRuleCompat,
			true,
		); err != nil {
			return nil, fmt.Errorf("failed to configure router IP rules and routes: %w", err)
		}

		node.SetRouterInfo(routingInfo)

		r.jobGroup.Add(job.OneShot("egress-route-reconciler", func(ctx context.Context, health cell.Health) error {
			// Limit the rate of reconciliation if for whatever reason the routes
			// table is very busy. Once every 30 seconds seems reasonable as a
			// worst case scenario.
			limiter := rate.NewLimiter(30*time.Second, 1)

			for {
				watchSet, err := routingInfo.ReconcileGatewayRoutes(
					r.mtuManager.GetDeviceMTU(),
					option.Config.EgressMultiHomeIPRuleCompat,
					r.db.ReadTxn(),
					r.routes,
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

func (r *infraIPAllocator) allocateHealthIPs() error {
	bootstrapStats.healthCheck.Start()
	defer bootstrapStats.healthCheck.End(true)
	if !option.Config.EnableHealthChecking || !option.Config.EnableEndpointHealthChecking {
		return nil
	}
	var healthIPv4, healthIPv6 net.IP
	if option.Config.EnableIPv4 {
		var result *ipam.AllocationResult
		var err error
		healthIPv4 = node.GetEndpointHealthIPv4(r.logger)
		if healthIPv4 != nil {
			result, err = r.ipAllocator.AllocateIPWithoutSyncUpstream(healthIPv4, "health", ipam.PoolDefault())
			if err != nil {
				r.logger.Warn(
					"unable to re-allocate health IPv4, a new health IPv4 will be allocated",
					logfields.Error, err,
					logfields.IPv4, healthIPv4,
				)
				healthIPv4 = nil
			}
		}
		if healthIPv4 == nil {
			result, err = r.ipAllocator.AllocateNextFamilyWithoutSyncUpstream(ipam.IPv4, "health", ipam.PoolDefault())
			if err != nil {
				return fmt.Errorf("unable to allocate health IPv4: %w, see https://cilium.link/ipam-range-full", err)
			}
			node.SetEndpointHealthIPv4(result.IP)
		}

		// Coalescing multiple CIDRs. GH #18868
		if option.Config.EnableIPv4Masquerade &&
			(option.Config.IPAM == ipamOption.IPAMENI || option.Config.IPAM == ipamOption.IPAMAzure) &&
			result != nil &&
			len(result.CIDRs) > 0 {
			result.CIDRs, err = r.coalesceCIDRs(result.CIDRs)
			if err != nil {
				return fmt.Errorf("failed to coalesce CIDRs: %w", err)
			}
		}

		r.logger.Debug("IPv4 health endpoint address", logfields.IPAddr, result.IP)

		// In ENI and AlibabaCloud ENI mode, we require the gateway, CIDRs, and the ENI MAC addr
		// in order to set up rules and routes on the local node to direct
		// endpoint traffic out of the ENIs.
		if option.Config.IPAM == ipamOption.IPAMENI || option.Config.IPAM == ipamOption.IPAMAlibabaCloud {
			if r.healthEndpointRouting, err = r.parseRoutingInfo(result); err != nil {
				r.logger.Warn("Unable to allocate health information for ENI", logfields.Error, err)
			}
		}
	}

	if option.Config.EnableIPv6 {
		var result *ipam.AllocationResult
		var err error
		healthIPv6 = node.GetEndpointHealthIPv6(r.logger)
		if healthIPv6 != nil {
			result, err = r.ipAllocator.AllocateIPWithoutSyncUpstream(healthIPv6, "health", ipam.PoolDefault())
			if err != nil {
				r.logger.Warn(
					"unable to re-allocate health IPv6, a new health IPv6 will be allocated",
					logfields.Error, err,
					logfields.IPv6, healthIPv6,
				)
				healthIPv6 = nil
			}
		}
		if healthIPv6 == nil {
			result, err = r.ipAllocator.AllocateNextFamilyWithoutSyncUpstream(ipam.IPv6, "health", ipam.PoolDefault())
			if err != nil {
				if healthIPv4 != nil {
					r.ipAllocator.ReleaseIP(healthIPv4, ipam.PoolDefault())
					node.SetEndpointHealthIPv4(nil)
				}
				return fmt.Errorf("unable to allocate health IPv6: %w, see https://cilium.link/ipam-range-full", err)
			}
			node.SetEndpointHealthIPv6(result.IP)
		}
		r.logger.Debug("IPv6 health endpoint address", logfields.IPAddr, result.IP)
	}
	return nil
}

func (r *infraIPAllocator) allocateIngressIPs() error {
	bootstrapStats.ingressIPAM.Start()
	if option.Config.EnableEnvoyConfig {
		if option.Config.EnableIPv4 {
			var result *ipam.AllocationResult
			var err error

			// Reallocate the same address as before, if possible
			ingressIPv4 := node.GetIngressIPv4(r.logger)
			if ingressIPv4 != nil {
				result, err = r.ipAllocator.AllocateIPWithoutSyncUpstream(ingressIPv4, "ingress", ipam.PoolDefault())
				if err != nil {
					r.logger.Warn("unable to re-allocate ingress IPv4.",
						logfields.Error, err,
						logfields.SourceIP, ingressIPv4,
					)
					result = nil
				}
			}

			// Allocate a fresh IP if not restored, or the reallocation of the restored
			// IP failed
			if result == nil {
				result, err = r.ipAllocator.AllocateNextFamilyWithoutSyncUpstream(ipam.IPv4, "ingress", ipam.PoolDefault())
				if err != nil {
					return fmt.Errorf("unable to allocate ingress IPs: %w, see https://cilium.link/ipam-range-full", err)
				}
			}

			// Coalescing multiple CIDRs. GH #18868
			if option.Config.EnableIPv4Masquerade &&
				(option.Config.IPAM == ipamOption.IPAMENI || option.Config.IPAM == ipamOption.IPAMAzure) &&
				result != nil &&
				len(result.CIDRs) > 0 {
				result.CIDRs, err = r.coalesceCIDRs(result.CIDRs)
				if err != nil {
					return fmt.Errorf("failed to coalesce CIDRs: %w", err)
				}
			}

			node.SetIngressIPv4(result.IP)
			r.logger.Info(fmt.Sprintf("  Ingress IPv4: %s", node.GetIngressIPv4(r.logger)))

			// In ENI and AlibabaCloud ENI mode, we require the gateway, CIDRs, and the
			// ENI MAC addr in order to set up rules and routes on the local node to
			// direct ingress traffic out of the ENIs.
			if option.Config.IPAM == ipamOption.IPAMENI || option.Config.IPAM == ipamOption.IPAMAlibabaCloud {
				if ingressRouting, err := r.parseRoutingInfo(result); err != nil {
					r.logger.Warn("Unable to allocate ingress information for ENI", logfields.Error, err)
				} else {
					if err := ingressRouting.Configure(
						result.IP,
						r.mtuManager.GetDeviceMTU(),
						option.Config.EgressMultiHomeIPRuleCompat,
						false,
					); err != nil {
						r.logger.Warn("Error while configuring ingress IP rules and routes.", logfields.Error, err)
					}
				}
			}
		}

		// Only allocate if enabled and not restored already
		if option.Config.EnableIPv6 {
			var result *ipam.AllocationResult
			var err error

			// Reallocate the same address as before, if possible
			ingressIPv6 := node.GetIngressIPv6(r.logger)
			if ingressIPv6 != nil {
				result, err = r.ipAllocator.AllocateIPWithoutSyncUpstream(ingressIPv6, "ingress", ipam.PoolDefault())
				if err != nil {
					r.logger.Warn("unable to re-allocate ingress IPv6.",
						logfields.Error, err,
						logfields.SourceIP, ingressIPv6,
					)
					result = nil
				}
			}

			// Allocate a fresh IP if not restored, or the reallocation of the restored
			// IP failed
			if result == nil {
				result, err = r.ipAllocator.AllocateNextFamilyWithoutSyncUpstream(ipam.IPv6, "ingress", ipam.PoolDefault())
				if err != nil {
					if ingressIPv4 := node.GetIngressIPv4(r.logger); ingressIPv4 != nil {
						r.ipAllocator.ReleaseIP(ingressIPv4, ipam.PoolDefault())
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
				result.CIDRs, err = r.coalesceCIDRs(result.CIDRs)
				if err != nil {
					return fmt.Errorf("failed to coalesce CIDRs: %w", err)
				}
			}

			node.SetIngressIPv6(result.IP)
			r.logger.Info(fmt.Sprintf("  Ingress IPv6: %s", node.GetIngressIPv6(r.logger)))
		}
	}
	bootstrapStats.ingressIPAM.End(true)
	return nil
}

type restoredIPs struct {
	IPv4FromK8s, IPv4FromFS net.IP
	IPv6FromK8s, IPv6FromFS net.IP
}

func (r *infraIPAllocator) AllocateIPs(ctx context.Context, router restoredIPs) error {
	bootstrapStats.ipam.Start()

	if option.Config.EnableIPv4 {
		routerIP, err := r.allocateRouterIPv4(ctx, r.nodeAddressing.IPv4(), router.IPv4FromK8s, router.IPv4FromFS)
		if err != nil {
			return err
		}
		if routerIP != nil {
			node.SetInternalIPv4Router(routerIP)
		}
	}

	if option.Config.EnableIPv6 {
		routerIP, err := r.allocateRouterIPv6(ctx, r.nodeAddressing.IPv6(), router.IPv6FromK8s, router.IPv6FromFS)
		if err != nil {
			return err
		}
		if routerIP != nil {
			node.SetIPv6Router(routerIP)
		}
	}

	// Clean up any stale IPs from the `cilium_host` interface
	r.removeOldCiliumHostIPs(ctx, node.GetInternalIPv4Router(r.logger), node.GetIPv6Router(r.logger))

	r.logger.Info("Addressing information:")
	r.logger.Info(fmt.Sprintf("  Cluster-Name: %s", option.Config.ClusterName))
	r.logger.Info(fmt.Sprintf("  Cluster-ID: %d", option.Config.ClusterID))
	r.logger.Info(fmt.Sprintf("  Local node-name: %s", nodeTypes.GetName()))
	r.logger.Info(fmt.Sprintf("  Node-IPv6: %s", node.GetIPv6(r.logger)))

	iter := r.nodeAddrs.All(r.db.ReadTxn())
	addrs := statedb.Collect(
		statedb.Filter(
			iter,
			func(addr tables.NodeAddress) bool { return addr.DeviceName != tables.WildcardDeviceName }))

	if option.Config.EnableIPv6 {
		r.logger.Debug(fmt.Sprintf("  IPv6 allocation prefix: %s", node.GetIPv6AllocRange(r.logger)))

		if c := option.Config.IPv6NativeRoutingCIDR; c != nil {
			r.logger.Info(fmt.Sprintf("  IPv6 native routing prefix: %s", c.String()))
		}

		r.logger.Info(fmt.Sprintf("  IPv6 router address: %s", node.GetIPv6Router(r.logger)))

		// Allocate IPv6 service loopback IP
		loopbackIPv6 := net.ParseIP(option.Config.ServiceLoopbackIPv6)
		if loopbackIPv6 == nil {
			return fmt.Errorf("Invalid IPv6 loopback address %s", option.Config.ServiceLoopbackIPv6)
		}
		node.SetServiceLoopbackIPv6(loopbackIPv6)
		r.logger.Info(fmt.Sprintf("  Loopback IPv6: %s", node.GetServiceLoopbackIPv6(r.logger).String()))

		r.logger.Info("  Local IPv6 addresses:")
		for _, addr := range addrs {
			if addr.Addr.Is6() {
				r.logger.Info(fmt.Sprintf("  - %s", addr.Addr))
			}
		}
	}

	r.logger.Info(fmt.Sprintf("  External-Node IPv4: %s", node.GetIPv4(r.logger)))
	r.logger.Info(fmt.Sprintf("  Internal-Node IPv4: %s", node.GetInternalIPv4Router(r.logger)))

	if option.Config.EnableIPv4 {
		r.logger.Debug(fmt.Sprintf("  IPv4 allocation prefix: %s", node.GetIPv4AllocRange(r.logger)))

		if c := option.Config.IPv4NativeRoutingCIDR; c != nil {
			r.logger.Info(fmt.Sprintf("  IPv4 native routing prefix: %s", c.String()))
		}

		// Allocate IPv4 service loopback IP
		loopbackIPv4 := net.ParseIP(option.Config.ServiceLoopbackIPv4)
		if loopbackIPv4 == nil {
			return fmt.Errorf("Invalid IPv4 loopback address %s", option.Config.ServiceLoopbackIPv4)
		}
		node.SetServiceLoopbackIPv4(loopbackIPv4)
		r.logger.Info(fmt.Sprintf("  Loopback IPv4: %s", node.GetServiceLoopbackIPv4(r.logger).String()))

		r.logger.Info("  Local IPv4 addresses:")
		for _, addr := range addrs {
			if addr.Addr.Is4() {
				r.logger.Info(fmt.Sprintf("  - %s", addr.Addr))
			}
		}
	}

	bootstrapStats.ipam.End(true)

	if option.Config.EnableEnvoyConfig {
		if err := r.allocateIngressIPs(); err != nil {
			return err
		}
	}

	return r.allocateHealthIPs()
}

func (r *infraIPAllocator) parseRoutingInfo(result *ipam.AllocationResult) (*linuxrouting.RoutingInfo, error) {
	if result.IP.To4() != nil {
		return linuxrouting.NewRoutingInfo(
			r.logger,
			result.GatewayIP,
			result.CIDRs,
			result.PrimaryMAC,
			result.InterfaceNumber,
			option.Config.IPAM,
			option.Config.EnableIPv4Masquerade,
		)
	} else {
		return linuxrouting.NewRoutingInfo(
			r.logger,
			result.GatewayIP,
			result.CIDRs,
			result.PrimaryMAC,
			result.InterfaceNumber,
			option.Config.IPAM,
			option.Config.EnableIPv6Masquerade,
		)
	}
}

// removeOldCiliumHostIPs calls removeOldRouterState() for both IPv4 and IPv6
// in a retry loop.
func (r *infraIPAllocator) removeOldCiliumHostIPs(ctx context.Context, restoredRouterIPv4, restoredRouterIPv6 net.IP) {
	gcHostIPsFn := func(ctx context.Context, retries int) (done bool, err error) {
		var errs error
		if option.Config.EnableIPv4 {
			errs = errors.Join(errs, removeOldRouterState(r.logger, false, restoredRouterIPv4))
		}
		if option.Config.EnableIPv6 {
			errs = errors.Join(errs, removeOldRouterState(r.logger, true, restoredRouterIPv6))
		}
		if resiliency.IsRetryable(errs) && !errors.As(errs, &netlink.LinkNotFoundError{}) {
			r.logger.Warn(
				"Failed to remove old router IPs from cilium_host.",
				logfields.Error, errs,
				logfields.Attempt, retries,
			)
			return false, nil
		}
		return true, errs
	}
	if err := resiliency.Retry(ctx, 100*time.Millisecond, 3, gcHostIPsFn); err != nil {
		r.logger.Error("Restore of the cilium_host ips failed. Manual intervention is required to remove all other old IPs.", logfields.Error, err)
	}
}
