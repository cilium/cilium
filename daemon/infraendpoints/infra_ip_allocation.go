// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package infraendpoints

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/cilium/cilium/pkg/common"
	linuxrouting "github.com/cilium/cilium/pkg/datapath/linux/routing"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	datapathTables "github.com/cilium/cilium/pkg/datapath/tables"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/defaults"
	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipam"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/resiliency"
	"github.com/cilium/cilium/pkg/time"
)

type infraIPAllocatorParams struct {
	cell.In

	Logger         *slog.Logger
	JobGroup       job.Group
	DaemonConfig   *option.DaemonConfig
	Config         config
	DB             *statedb.DB
	Routes         statedb.Table[*datapathTables.Route]
	NodeAddrs      statedb.Table[datapathTables.NodeAddress]
	NodeAddressing datapath.NodeAddressing
	LocalNodeStore *node.LocalNodeStore
	MTU            mtu.MTU
	IPAM           *ipam.IPAM
}

type InfraIPAllocator interface {
	AllocateIPs(ctx context.Context) error
	GetHealthEndpointRouting() *linuxrouting.RoutingInfo
}

var _ InfraIPAllocator = &infraIPAllocator{}

// infraIPAllocator is responsible to create infra related IPs (router, ingress & health)
type infraIPAllocator struct {
	logger         *slog.Logger
	jobGroup       job.Group
	daemonConfig   *option.DaemonConfig
	config         config
	db             *statedb.DB
	routes         statedb.Table[*datapathTables.Route]
	nodeAddressing datapath.NodeAddressing
	localNodeStore *node.LocalNodeStore
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

func newInfraIPAllocator(params infraIPAllocatorParams) InfraIPAllocator {
	return &infraIPAllocator{
		logger:         params.Logger,
		jobGroup:       params.JobGroup,
		daemonConfig:   params.DaemonConfig,
		config:         params.Config,
		db:             params.DB,
		routes:         params.Routes,
		nodeAddressing: params.NodeAddressing,
		localNodeStore: params.LocalNodeStore,
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

func (r *infraIPAllocator) allocateRouterIPv4(ctx context.Context, family datapath.NodeAddressingFamily, fromK8s, fromFS net.IP) (net.IP, error) {
	if r.daemonConfig.LocalRouterIPv4 != "" {
		routerIP := net.ParseIP(r.daemonConfig.LocalRouterIPv4)
		if routerIP == nil {
			return nil, fmt.Errorf("invalid local-router-ip: %s", r.daemonConfig.LocalRouterIPv4)
		}
		if r.nodeAddressing.IPv4().AllocationCIDR().Contains(routerIP) {
			r.logger.Warn("Specified router IP is within IPv4 podCIDR.")
		}
		return routerIP, nil
	}

	return r.reallocateRouterIPs(ctx, family, fromK8s, fromFS)
}

func (r *infraIPAllocator) allocateRouterIPv6(ctx context.Context, family datapath.NodeAddressingFamily, fromK8s, fromFS net.IP) (net.IP, error) {
	if r.daemonConfig.LocalRouterIPv6 != "" {
		routerIP := net.ParseIP(r.daemonConfig.LocalRouterIPv6)
		if routerIP == nil {
			return nil, fmt.Errorf("invalid local-router-ip: %s", r.daemonConfig.LocalRouterIPv6)
		}
		if r.nodeAddressing.IPv6().AllocationCIDR().Contains(routerIP) {
			r.logger.Warn("Specified router IP is within IPv6 podCIDR.")
		}
		return routerIP, nil
	}

	return r.reallocateRouterIPs(ctx, family, fromK8s, fromFS)
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

// reallocateOldRouterIPs attempts to reallocate the old router IP from IPAM.
// It prefers fromFS over fromK8s. If neither IPs can be re-allocated, log
// messages are emitted and the function returns nil.
func (r *infraIPAllocator) reallocateOldRouterIPs(fromK8s, fromFS net.IP) (result *ipam.AllocationResult) {
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

func (r *infraIPAllocator) reallocateRouterIPs(ctx context.Context, family datapath.NodeAddressingFamily, fromK8s, fromFS net.IP) (routerIP net.IP, err error) {
	// Avoid allocating external IP
	r.ipAllocator.ExcludeIP(family.PrimaryExternal(), "node-ip", ipam.PoolDefault())

	// (Re-)allocate the router IP. If not possible, allocate a fresh IP.
	// In that case, the old router IP needs to be removed from cilium_host
	// by the caller.
	// This will also cause disruption of networking until all endpoints
	// have been regenerated.
	result := r.reallocateOldRouterIPs(fromK8s, fromFS)
	if result == nil {
		family := ipam.DeriveFamily(family.PrimaryExternal())
		result, err = r.ipAllocator.AllocateNextFamilyWithoutSyncUpstream(family, "router", ipam.PoolDefault())
		if err != nil {
			return nil, fmt.Errorf("unable to allocate router IP for family %s: %w", family, err)
		}
	}

	ipfamily := ipam.DeriveFamily(family.PrimaryExternal())
	masq := (ipfamily == ipam.IPv4 && r.daemonConfig.EnableIPv4Masquerade) ||
		(ipfamily == ipam.IPv6 && r.daemonConfig.EnableIPv6Masquerade)

	// Coalescing multiple CIDRs. GH #18868
	if masq &&
		(r.daemonConfig.IPAM == ipamOption.IPAMENI || r.daemonConfig.IPAM == ipamOption.IPAMAzure) &&
		result != nil &&
		len(result.CIDRs) > 0 {
		result.CIDRs, err = r.coalesceCIDRs(result.CIDRs)
		if err != nil {
			return nil, fmt.Errorf("failed to coalesce CIDRs: %w", err)
		}
	}

	if (r.daemonConfig.IPAM == ipamOption.IPAMENI ||
		r.daemonConfig.IPAM == ipamOption.IPAMAlibabaCloud ||
		r.daemonConfig.IPAM == ipamOption.IPAMAzure) && result != nil {
		var routingInfo *linuxrouting.RoutingInfo
		routingInfo, err = linuxrouting.NewRoutingInfo(r.logger, result.GatewayIP, result.CIDRs,
			result.PrimaryMAC, result.InterfaceNumber, r.daemonConfig.IPAM,
			masq)
		if err != nil {
			return nil, fmt.Errorf("failed to create router info: %w", err)
		}

		// wait for ENI to be up and running before configuring routes and rules.
		// This avoids spurious errors where netlink is not able to find
		// the ifindex by its MAC because the ENI is not showing up yet.
		if r.daemonConfig.IPAM == ipamOption.IPAMENI {
			if err := r.waitForENI(ctx, result.PrimaryMAC); err != nil {
				r.logger.Warn("unable to find ENI netlink interface, this will likely lead to an error in configuring the router routes and rules",
					logfields.MACAddr, result.PrimaryMAC,
				)
			}
		}

		if err = routingInfo.Configure(
			result.IP,
			r.mtuManager.GetDeviceMTU(),
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

func (r *infraIPAllocator) allocateHealthIPs(oldV4HealthIP net.IP, oldV6HealthIP net.IP) error {
	if !r.daemonConfig.EnableHealthChecking || !r.daemonConfig.EnableEndpointHealthChecking {
		return nil
	}
	var healthIPv4, healthIPv6 net.IP
	if r.daemonConfig.EnableIPv4 {
		var result *ipam.AllocationResult
		var err error
		healthIPv4 = oldV4HealthIP
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
			r.localNodeStore.Update(func(n *node.LocalNode) { n.IPv4HealthIP = result.IP })
		}

		// Coalescing multiple CIDRs. GH #18868
		if r.daemonConfig.EnableIPv4Masquerade &&
			(r.daemonConfig.IPAM == ipamOption.IPAMENI || r.daemonConfig.IPAM == ipamOption.IPAMAzure) &&
			result != nil &&
			len(result.CIDRs) > 0 {
			result.CIDRs, err = r.coalesceCIDRs(result.CIDRs)
			if err != nil {
				return fmt.Errorf("failed to coalesce CIDRs: %w", err)
			}
		}

		r.logger.Debug("Allocated IPv4 health endpoint address", logfields.IPAddr, result.IP)

		// In ENI and AlibabaCloud ENI mode, we require the gateway, CIDRs, and the ENI MAC addr
		// in order to set up rules and routes on the local node to direct
		// endpoint traffic out of the ENIs.
		if r.daemonConfig.IPAM == ipamOption.IPAMENI || r.daemonConfig.IPAM == ipamOption.IPAMAlibabaCloud {
			if r.healthEndpointRouting, err = r.parseRoutingInfo(result); err != nil {
				r.logger.Warn("Unable to allocate health information for ENI", logfields.Error, err)
			}
		}
	}

	if r.daemonConfig.EnableIPv6 {
		var result *ipam.AllocationResult
		var err error
		healthIPv6 = oldV6HealthIP
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
					r.localNodeStore.Update(func(n *node.LocalNode) { n.IPv4HealthIP = nil })
				}
				return fmt.Errorf("unable to allocate health IPv6: %w, see https://cilium.link/ipam-range-full", err)
			}
			r.localNodeStore.Update(func(n *node.LocalNode) { n.IPv6HealthIP = result.IP })
		}
		r.logger.Debug("Allocated IPv6 health endpoint address", logfields.IPAddr, result.IP)
	}
	return nil
}

func (r *infraIPAllocator) allocateIngressIPs(oldV4IngressIP net.IP, oldV6IngressIP net.IP) error {
	if !r.daemonConfig.EnableEnvoyConfig {
		return nil
	}

	ingressIPv4 := oldV4IngressIP
	if r.daemonConfig.EnableIPv4 {
		var result *ipam.AllocationResult
		var err error

		// Reallocate the same address as before, if possible
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
		if r.daemonConfig.EnableIPv4Masquerade &&
			(r.daemonConfig.IPAM == ipamOption.IPAMENI || r.daemonConfig.IPAM == ipamOption.IPAMAzure) &&
			result != nil &&
			len(result.CIDRs) > 0 {
			result.CIDRs, err = r.coalesceCIDRs(result.CIDRs)
			if err != nil {
				return fmt.Errorf("failed to coalesce CIDRs: %w", err)
			}
		}

		ingressIPv4 = result.IP
		r.localNodeStore.Update(func(n *node.LocalNode) { n.IPv4IngressIP = result.IP })
		r.logger.Debug("Allocated IPv4 Ingress address", logfields.IPAddr, result.IP)

		// In ENI and AlibabaCloud ENI mode, we require the gateway, CIDRs, and the
		// ENI MAC addr in order to set up rules and routes on the local node to
		// direct ingress traffic out of the ENIs.
		if r.daemonConfig.IPAM == ipamOption.IPAMENI || r.daemonConfig.IPAM == ipamOption.IPAMAlibabaCloud {
			if ingressRouting, err := r.parseRoutingInfo(result); err != nil {
				r.logger.Warn("Unable to allocate ingress information for ENI", logfields.Error, err)
			} else {
				if err := ingressRouting.Configure(
					result.IP,
					r.mtuManager.GetDeviceMTU(),
					false,
				); err != nil {
					r.logger.Warn("Error while configuring ingress IP rules and routes.", logfields.Error, err)
				}
			}
		}
	}

	// Only allocate if enabled and not restored already
	if r.daemonConfig.EnableIPv6 {
		var result *ipam.AllocationResult
		var err error

		// Reallocate the same address as before, if possible
		ingressIPv6 := oldV6IngressIP
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
				if ingressIPv4 != nil {
					r.ipAllocator.ReleaseIP(ingressIPv4, ipam.PoolDefault())
					r.localNodeStore.Update(func(n *node.LocalNode) { n.IPv4IngressIP = nil })
				}
				return fmt.Errorf("unable to allocate ingress IPs: %w, see https://cilium.link/ipam-range-full", err)
			}
		}

		// Coalescing multiple CIDRs. GH #18868
		if r.daemonConfig.EnableIPv6Masquerade &&
			r.daemonConfig.IPAM == ipamOption.IPAMENI &&
			result != nil &&
			len(result.CIDRs) > 0 {
			result.CIDRs, err = r.coalesceCIDRs(result.CIDRs)
			if err != nil {
				return fmt.Errorf("failed to coalesce CIDRs: %w", err)
			}
		}

		r.localNodeStore.Update(func(n *node.LocalNode) { n.IPv6IngressIP = result.IP })
		r.logger.Debug("Allocated IPv6 Ingress address", logfields.IPAddr, result.IP)
	}

	return nil
}

func (r *infraIPAllocator) AllocateIPs(ctx context.Context) error {
	// fetch local node. be aware that updating the local node via localNodeStore.Update doesn't update this instance!
	localNode, err := r.localNodeStore.Get(ctx)
	if err != nil {
		return fmt.Errorf("failed to get local node: %w", err)
	}

	// Fetch the router (`cilium_host`) IPs in case they were set a priori from
	// the Kubernetes or CiliumNode resource in the K8s subsystem.
	restoredRouterIPIPv4FromK8s, restoredRouterIPv6FromK8s := localNode.GetCiliumInternalIP(false), localNode.GetCiliumInternalIP(true)
	// Fetch the router IPs from the filesystem in case they were set a priori
	restoredRouterIPIPv4FromFS, restoredRouterIPIPv6FromFS := r.extractCiliumHostIPFromFS()

	if err := r.allocateRouterIPs(ctx, restoredRouterIPIPv4FromK8s, restoredRouterIPIPv4FromFS, restoredRouterIPv6FromK8s, restoredRouterIPIPv6FromFS); err != nil {
		return fmt.Errorf("failed to allocate router IPs: %w", err)
	}

	if err := r.allocateServiceLoopbackIPs(); err != nil {
		return fmt.Errorf("failed to allocate service loopback IPs: %w", err)
	}

	if err := r.allocateIngressIPs(localNode.IPv4IngressIP, localNode.IPv6IngressIP); err != nil {
		return fmt.Errorf("failed to allocate ingress IPs: %w", err)
	}

	if err := r.allocateHealthIPs(localNode.IPv4HealthIP, localNode.IPv6HealthIP); err != nil {
		return fmt.Errorf("failed to allocate health IPs: %w", err)
	}

	return nil
}

// ExtractCiliumHostIPFromFS returns the Cilium IPv4 gateway and router IPv6 address from
// the node_config.h file if is present; or by deriving it from
// defaults.HostDevice interface, on which only the IPv4 is possible to derive.
func (r *infraIPAllocator) extractCiliumHostIPFromFS() (net.IP, net.IP) {
	nodeConfig := r.daemonConfig.GetNodeConfigPath()
	ipv4GW, ipv6Router := getCiliumHostIPsFromFile(nodeConfig)
	if ipv4GW != nil || ipv6Router != nil {
		r.logger.Info(
			"Restored router address from node_config",
			logfields.IPv4, ipv4GW,
			logfields.IPv6, ipv6Router,
			logfields.File, nodeConfig,
		)
		return ipv4GW, ipv6Router
	}

	ipv4GW, ipv6Router = getCiliumHostIPsFromNetDev(defaults.HostDevice)

	if ipv4GW != nil || ipv6Router != nil {
		r.logger.Info(
			"Restored router address from device",
			logfields.IPv4, ipv4GW,
			logfields.IPv6, ipv6Router,
			logfields.Device, defaults.HostDevice,
		)
	}

	return ipv4GW, ipv6Router
}

func (r *infraIPAllocator) allocateServiceLoopbackIPs() error {
	if r.daemonConfig.EnableIPv6 {
		// Allocate IPv6 service loopback IP
		serviceLoopbackIPv6 := net.ParseIP(r.config.ServiceLoopbackIPv6)
		if serviceLoopbackIPv6 == nil {
			return fmt.Errorf("invalid IPv6 service loopback address %s", r.config.ServiceLoopbackIPv6)
		}
		r.localNodeStore.Update(func(n *node.LocalNode) { n.Local.ServiceLoopbackIPv6 = serviceLoopbackIPv6 })
		r.logger.Debug("Allocated IPv6 service loopback address", logfields.IPAddr, serviceLoopbackIPv6)
	}

	if r.daemonConfig.EnableIPv4 {
		// Allocate IPv4 service loopback IP
		serviceLoopbackIPv4 := net.ParseIP(r.config.ServiceLoopbackIPv4)
		if serviceLoopbackIPv4 == nil {
			return fmt.Errorf("invalid IPv4 service loopback address %s", r.config.ServiceLoopbackIPv4)
		}
		r.localNodeStore.Update(func(n *node.LocalNode) { n.Local.ServiceLoopbackIPv4 = serviceLoopbackIPv4 })
		r.logger.Debug("Allocated IPv4 service loopback address", logfields.IPAddr, serviceLoopbackIPv4)
	}

	return nil
}

func (r *infraIPAllocator) allocateRouterIPs(ctx context.Context, restoredRouterIPv4FromK8s net.IP, restoredRouterIPv4FromFS net.IP, restoredRouterIPv6FromK8s net.IP, restoredRouterIPv6FromFS net.IP) error {
	var v4 net.IP
	var v6 net.IP

	if r.daemonConfig.EnableIPv4 {
		routerIP, err := r.allocateRouterIPv4(ctx, r.nodeAddressing.IPv4(), restoredRouterIPv4FromK8s, restoredRouterIPv4FromFS)
		if err != nil {
			return err
		}
		if routerIP != nil {
			r.localNodeStore.Update(func(n *node.LocalNode) { n.SetCiliumInternalIP(routerIP) })
			r.logger.Debug("Allocated IPv4 Router address", logfields.IPAddr, routerIP)
			v4 = routerIP
		}
	}

	if r.daemonConfig.EnableIPv6 {
		routerIP, err := r.allocateRouterIPv6(ctx, r.nodeAddressing.IPv6(), restoredRouterIPv6FromK8s, restoredRouterIPv6FromFS)
		if err != nil {
			return err
		}
		if routerIP != nil {
			r.localNodeStore.Update(func(n *node.LocalNode) { n.SetCiliumInternalIP(routerIP) })
			r.logger.Debug("Allocated IPv6 Router address", logfields.IPAddr, routerIP)
			v6 = routerIP
		}
	}

	// Clean up any stale IPs from the `cilium_host` interface
	r.removeOldCiliumHostIPs(ctx, v4, v6)

	return nil
}

func (r *infraIPAllocator) parseRoutingInfo(result *ipam.AllocationResult) (*linuxrouting.RoutingInfo, error) {
	if result.IP.To4() != nil {
		return linuxrouting.NewRoutingInfo(
			r.logger,
			result.GatewayIP,
			result.CIDRs,
			result.PrimaryMAC,
			result.InterfaceNumber,
			r.daemonConfig.IPAM,
			r.daemonConfig.EnableIPv4Masquerade,
		)
	} else {
		return linuxrouting.NewRoutingInfo(
			r.logger,
			result.GatewayIP,
			result.CIDRs,
			result.PrimaryMAC,
			result.InterfaceNumber,
			r.daemonConfig.IPAM,
			r.daemonConfig.EnableIPv6Masquerade,
		)
	}
}

// removeOldCiliumHostIPs calls removeOldRouterState() for both IPv4 and IPv6
// in a retry loop.
func (r *infraIPAllocator) removeOldCiliumHostIPs(ctx context.Context, restoredRouterIPv4, restoredRouterIPv6 net.IP) {
	gcHostIPsFn := func(ctx context.Context, retries int) (done bool, err error) {
		var errs error
		if r.daemonConfig.EnableIPv4 {
			errs = errors.Join(errs, r.removeOldRouterState(false, restoredRouterIPv4))
		}
		if r.daemonConfig.EnableIPv6 {
			errs = errors.Join(errs, r.removeOldRouterState(true, restoredRouterIPv6))
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

// removeOldRouterState will try to ensure that the only IP assigned to the
// `cilium_host` interface is the given restored IP. If the given IP is nil,
// then it attempts to clear all IPs from the interface.
func (r *infraIPAllocator) removeOldRouterState(ipv6 bool, restoredIP net.IP) error {
	l, err := safenetlink.LinkByName(defaults.HostDevice)
	if errors.As(err, &netlink.LinkNotFoundError{}) {
		// There's no old state remove as the host device doesn't exist.
		// This is always the case when the agent is started for the first time.
		return nil
	}
	if err != nil {
		return resiliency.Retryable(err)
	}

	family := netlink.FAMILY_V4
	if ipv6 {
		family = netlink.FAMILY_V6
	}
	addrs, err := safenetlink.AddrList(l, family)
	if err != nil {
		return resiliency.Retryable(err)
	}

	isRestoredIP := func(a netlink.Addr) bool {
		return restoredIP != nil && restoredIP.Equal(a.IP)
	}
	if len(addrs) == 0 || (len(addrs) == 1 && isRestoredIP(addrs[0])) {
		return nil // nothing to clean up
	}

	r.logger.Info("More than one stale router IP was found on the cilium_host device after restoration, cleaning up old router IPs.")

	for _, a := range addrs {
		if isRestoredIP(a) {
			continue
		}
		r.logger.Debug(
			"Removing stale router IP from cilium_host device",
			logfields.IPAddr, a.IP,
		)
		if e := netlink.AddrDel(l, &a); e != nil {
			err = errors.Join(err, resiliency.Retryable(fmt.Errorf("failed to remove IP %s: %w", a.IP, e)))
		}
	}

	return err
}

func getCiliumHostIPsFromFile(nodeConfig string) (ipv4GW, ipv6Router net.IP) {
	// ipLen is the length of the IP address stored in the node_config.h
	// it has the same length for both IPv4 and IPv6.
	const ipLen = net.IPv6len

	var hasIPv4, hasIPv6 bool
	f, err := os.Open(nodeConfig)
	switch {
	case err != nil:
	default:
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			txt := scanner.Text()
			switch {
			case !hasIPv6 && strings.Contains(txt, defaults.RestoreV6Addr):
				defineLine := strings.Split(txt, defaults.RestoreV6Addr)
				if len(defineLine) != 2 {
					continue
				}
				ipv6 := common.C2GoArray(defineLine[1])
				if len(ipv6) != ipLen {
					continue
				}
				ipv6Router = net.IP(ipv6)
				hasIPv6 = true
			case !hasIPv4 && strings.Contains(txt, defaults.RestoreV4Addr):
				defineLine := strings.Split(txt, defaults.RestoreV4Addr)
				if len(defineLine) != 2 {
					continue
				}
				ipv4 := common.C2GoArray(defineLine[1])
				if len(ipv4) != ipLen {
					continue
				}
				ipv4GW = net.IP(ipv4)
				hasIPv4 = true

			// Legacy cases based on the header defines:
			case !hasIPv4 && strings.Contains(txt, "IPV4_GATEWAY"):
				// #define IPV4_GATEWAY 0xee1c000a
				defineLine := strings.Split(txt, " ")
				if len(defineLine) != 3 {
					continue
				}
				ipv4GWHex := strings.TrimPrefix(defineLine[2], "0x")
				ipv4GWUint64, err := strconv.ParseUint(ipv4GWHex, 16, 32)
				if err != nil {
					continue
				}
				if ipv4GWUint64 != 0 {
					bs := make([]byte, net.IPv4len)
					binary.NativeEndian.PutUint32(bs, uint32(ipv4GWUint64))
					ipv4GW = net.IPv4(bs[0], bs[1], bs[2], bs[3])
					hasIPv4 = true
				}
			}
		}
	}
	return ipv4GW, ipv6Router
}
