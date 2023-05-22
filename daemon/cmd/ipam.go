// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/swag"

	"github.com/cilium/cilium/api/v1/models"
	ipamapi "github.com/cilium/cilium/api/v1/server/restapi/ipam"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/cidr"
	linuxrouting "github.com/cilium/cilium/pkg/datapath/linux/routing"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/defaults"
	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipam"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
)

type postIPAM struct {
	daemon *Daemon
}

// NewPostIPAMHandler creates a new postIPAM from the daemon.
func NewPostIPAMHandler(d *Daemon) ipamapi.PostIpamHandler {
	return &postIPAM{daemon: d}
}

// Handle incoming requests address allocation requests for the daemon.
func (h *postIPAM) Handle(params ipamapi.PostIpamParams) middleware.Responder {
	family := strings.ToLower(swag.StringValue(params.Family))
	owner := swag.StringValue(params.Owner)
	pool := ipam.Pool(swag.StringValue(params.Pool))
	var expirationTimeout time.Duration
	if swag.BoolValue(params.Expiration) {
		expirationTimeout = defaults.IPAMExpiration
	}
	ipv4Result, ipv6Result, err := h.daemon.ipam.AllocateNextWithExpiration(family, owner, pool, expirationTimeout)
	if err != nil {
		return api.Error(ipamapi.PostIpamFailureCode, err)
	}

	resp := &models.IPAMResponse{
		HostAddressing: node.GetNodeAddressing(),
		Address:        &models.AddressPair{},
	}

	if ipv4Result != nil {
		resp.Address.IPV4 = ipv4Result.IP.String()
		resp.Address.IPV4PoolName = ipv4Result.IPPoolName.String()
		resp.IPV4 = &models.IPAMAddressResponse{
			Cidrs:           ipv4Result.CIDRs,
			IP:              ipv4Result.IP.String(),
			MasterMac:       ipv4Result.PrimaryMAC,
			Gateway:         ipv4Result.GatewayIP,
			ExpirationUUID:  ipv4Result.ExpirationUUID,
			InterfaceNumber: ipv4Result.InterfaceNumber,
		}
	}

	if ipv6Result != nil {
		resp.Address.IPV6 = ipv6Result.IP.String()
		resp.Address.IPV6PoolName = ipv6Result.IPPoolName.String()
		resp.IPV6 = &models.IPAMAddressResponse{
			Cidrs:           ipv6Result.CIDRs,
			IP:              ipv6Result.IP.String(),
			MasterMac:       ipv6Result.PrimaryMAC,
			Gateway:         ipv6Result.GatewayIP,
			ExpirationUUID:  ipv6Result.ExpirationUUID,
			InterfaceNumber: ipv6Result.InterfaceNumber,
		}
	}

	return ipamapi.NewPostIpamCreated().WithPayload(resp)
}

type postIPAMIP struct {
	daemon *Daemon
}

// NewPostIPAMIPHandler creates a new postIPAM from the daemon.
func NewPostIPAMIPHandler(d *Daemon) ipamapi.PostIpamIPHandler {
	return &postIPAMIP{
		daemon: d,
	}
}

// Handle incoming requests address allocation requests for the daemon.
func (h *postIPAMIP) Handle(params ipamapi.PostIpamIPParams) middleware.Responder {
	owner := swag.StringValue(params.Owner)
	pool := ipam.Pool(swag.StringValue(params.Pool))
	if err := h.daemon.ipam.AllocateIPString(params.IP, owner, pool); err != nil {
		return api.Error(ipamapi.PostIpamIPFailureCode, err)
	}

	return ipamapi.NewPostIpamIPOK()
}

type deleteIPAMIP struct {
	daemon *Daemon
}

// NewDeleteIPAMIPHandler handle incoming requests to delete addresses.
func NewDeleteIPAMIPHandler(d *Daemon) ipamapi.DeleteIpamIPHandler {
	return &deleteIPAMIP{daemon: d}
}

func (h *deleteIPAMIP) Handle(params ipamapi.DeleteIpamIPParams) middleware.Responder {
	// Release of an IP that is in use is not allowed
	if ep := h.daemon.endpointManager.LookupIPv4(params.IP); ep != nil {
		return api.Error(ipamapi.DeleteIpamIPFailureCode, fmt.Errorf("IP is in use by endpoint %d", ep.ID))
	}
	if ep := h.daemon.endpointManager.LookupIPv6(params.IP); ep != nil {
		return api.Error(ipamapi.DeleteIpamIPFailureCode, fmt.Errorf("IP is in use by endpoint %d", ep.ID))
	}

	ip := net.ParseIP(params.IP)
	if ip == nil {
		return api.Error(ipamapi.DeleteIpamIPInvalidCode, fmt.Errorf("Invalid IP address: %s", params.IP))
	}

	pool := ipam.Pool(swag.StringValue(params.Pool))
	if err := h.daemon.ipam.ReleaseIP(ip, pool); err != nil {
		return api.Error(ipamapi.DeleteIpamIPFailureCode, err)
	}

	return ipamapi.NewDeleteIpamIPOK()
}

// DumpIPAM dumps in the form of a map, the list of
// reserved IPv4 and IPv6 addresses.
func (d *Daemon) DumpIPAM() *models.IPAMStatus {
	allocv4, allocv6, st := d.ipam.Dump()
	status := &models.IPAMStatus{
		Status: st,
	}

	v4 := make([]string, 0, len(allocv4))
	for ip := range allocv4 {
		v4 = append(v4, ip)
	}

	v6 := make([]string, 0, len(allocv6))
	if allocv4 == nil {
		allocv4 = map[string]string{}
	}
	for ip, owner := range allocv6 {
		v6 = append(v6, ip)
		// merge allocv6 into allocv4
		allocv4[ip] = owner
	}

	if option.Config.EnableIPv4 {
		status.IPV4 = v4
	}

	if option.Config.EnableIPv6 {
		status.IPV6 = v6
	}

	status.Allocations = allocv4

	return status
}

func (d *Daemon) allocateRouterIPv4(family types.NodeAddressingFamily) (net.IP, error) {
	if option.Config.LocalRouterIPv4 != "" {
		routerIP := net.ParseIP(option.Config.LocalRouterIPv4)
		if routerIP == nil {
			return nil, fmt.Errorf("Invalid local-router-ip: %s", option.Config.LocalRouterIPv4)
		}
		if d.datapath.LocalNodeAddressing().IPv4().AllocationCIDR().Contains(routerIP) {
			log.Warn("Specified router IP is within IPv4 podCIDR.")
		}
		return routerIP, nil
	} else {
		return d.allocateDatapathIPs(family)
	}
}

func (d *Daemon) allocateRouterIPv6(family types.NodeAddressingFamily) (net.IP, error) {
	if option.Config.LocalRouterIPv6 != "" {
		routerIP := net.ParseIP(option.Config.LocalRouterIPv6)
		if routerIP == nil {
			return nil, fmt.Errorf("Invalid local-router-ip: %s", option.Config.LocalRouterIPv6)
		}
		if d.datapath.LocalNodeAddressing().IPv6().AllocationCIDR().Contains(routerIP) {
			log.Warn("Specified router IP is within IPv6 podCIDR.")
		}
		return routerIP, nil
	} else {
		return d.allocateDatapathIPs(family)
	}
}

// Coalesce CIDRS when allocating the DatapathIPs and healthIPs. GH #18868
func coalesceCIDRs(rCIDRs []string) (result []string) {
	cidrs := make([]*net.IPNet, 0, len(rCIDRs))
	for _, k := range rCIDRs {
		ip, mask, _ := net.ParseCIDR(k)
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

func (d *Daemon) allocateDatapathIPs(family types.NodeAddressingFamily) (routerIP net.IP, err error) {
	// Avoid allocating external IP
	d.ipam.ExcludeIP(family.PrimaryExternal(), "node-ip", ipam.PoolDefault)

	// (Re-)allocate the router IP. If not possible, allocate a fresh IP.
	// In that case, removal and re-creation of the cilium_host is
	// required. It will also cause disruption of networking until all
	// endpoints have been regenerated.
	var result *ipam.AllocationResult
	routerIP = family.Router()
	if routerIP != nil {
		result, err = d.ipam.AllocateIPWithoutSyncUpstream(routerIP, "router", ipam.PoolDefault)
		if err != nil {
			log.Warn("Router IP could not be re-allocated. Need to re-allocate. This will cause brief network disruption")

			// The restored router IP is not part of the allocation range.
			// This indicates that the allocation range has changed.
			deleteHostDevice()

			// force re-allocation of the router IP
			routerIP = nil
		}
	}

	if routerIP == nil {
		family := ipam.DeriveFamily(family.PrimaryExternal())
		result, err = d.ipam.AllocateNextFamilyWithoutSyncUpstream(family, "router", ipam.PoolDefault)
		if err != nil {
			err = fmt.Errorf("Unable to allocate router IP for family %s: %s", family, err)
			return
		}
		routerIP = result.IP
	}

	// Coalescing multiple CIDRs. GH #18868
	if option.Config.EnableIPv4Masquerade &&
		option.Config.IPAM == ipamOption.IPAMENI &&
		result != nil &&
		len(result.CIDRs) > 0 {
		result.CIDRs = coalesceCIDRs(result.CIDRs)
	}

	if (option.Config.IPAM == ipamOption.IPAMENI ||
		option.Config.IPAM == ipamOption.IPAMAlibabaCloud ||
		option.Config.IPAM == ipamOption.IPAMAzure) && result != nil {
		var routingInfo *linuxrouting.RoutingInfo
		routingInfo, err = linuxrouting.NewRoutingInfo(result.GatewayIP, result.CIDRs,
			result.PrimaryMAC, result.InterfaceNumber, option.Config.IPAM,
			option.Config.EnableIPv4Masquerade)
		if err != nil {
			err = fmt.Errorf("failed to create router info %w", err)
			return
		}
		node.SetRouterInfo(routingInfo)
	}

	return
}

func (d *Daemon) allocateHealthIPs() error {
	bootstrapStats.healthCheck.Start()
	if option.Config.EnableHealthChecking && option.Config.EnableEndpointHealthChecking {
		if option.Config.EnableIPv4 {
			result, err := d.ipam.AllocateNextFamilyWithoutSyncUpstream(ipam.IPv4, "health", ipam.PoolDefault)
			if err != nil {
				return fmt.Errorf("unable to allocate health IPs: %s, see https://cilium.link/ipam-range-full", err)
			}

			// Coalescing multiple CIDRs. GH #18868
			if option.Config.EnableIPv4Masquerade &&
				option.Config.IPAM == ipamOption.IPAMENI &&
				result != nil &&
				len(result.CIDRs) > 0 {
				result.CIDRs = coalesceCIDRs(result.CIDRs)
			}

			log.Debugf("IPv4 health endpoint address: %s", result.IP)
			node.SetEndpointHealthIPv4(result.IP)

			// In ENI and AlibabaCloud ENI mode, we require the gateway, CIDRs, and the ENI MAC addr
			// in order to set up rules and routes on the local node to direct
			// endpoint traffic out of the ENIs.
			if option.Config.IPAM == ipamOption.IPAMENI || option.Config.IPAM == ipamOption.IPAMAlibabaCloud {
				var err error
				if d.healthEndpointRouting, err = parseRoutingInfo(result); err != nil {
					log.WithError(err).Warn("Unable to allocate health information for ENI")
				}
			}
		}

		if option.Config.EnableIPv6 {
			result, err := d.ipam.AllocateNextFamilyWithoutSyncUpstream(ipam.IPv6, "health", ipam.PoolDefault)
			if err != nil {
				if healthIPv4 := node.GetEndpointHealthIPv4(); healthIPv4 != nil {
					d.ipam.ReleaseIP(healthIPv4, ipam.PoolDefault)
					node.SetEndpointHealthIPv4(nil)
				}
				return fmt.Errorf("unable to allocate health IPs: %s, see https://cilium.link/ipam-range-full", err)
			}

			// Coalescing multiple CIDRs. GH #18868
			if option.Config.EnableIPv6Masquerade &&
				option.Config.IPAM == ipamOption.IPAMENI &&
				result != nil &&
				len(result.CIDRs) > 0 {
				result.CIDRs = coalesceCIDRs(result.CIDRs)
			}

			node.SetEndpointHealthIPv6(result.IP)
			log.Debugf("IPv6 health endpoint address: %s", result.IP)
		}
	}
	bootstrapStats.healthCheck.End(true)
	return nil
}

func (d *Daemon) allocateIngressIPs() error {
	bootstrapStats.ingressIPAM.Start()
	if option.Config.EnableEnvoyConfig {
		if option.Config.EnableIPv4 {
			var result *ipam.AllocationResult
			var err error

			// Reallocate the same address as before, if possible
			ingressIPv4 := node.GetIngressIPv4()
			if ingressIPv4 != nil {
				result, err = d.ipam.AllocateIPWithoutSyncUpstream(ingressIPv4, "ingress", ipam.PoolDefault)
				if err != nil {
					log.WithError(err).WithField(logfields.SourceIP, ingressIPv4).Warn("unable to re-allocate ingress IPv4.")
					result = nil
				}
			}

			// Allocate a fresh IP if not restored, or the reallocation of the restored
			// IP failed
			if result == nil {
				result, err = d.ipam.AllocateNextFamilyWithoutSyncUpstream(ipam.IPv4, "ingress", ipam.PoolDefault)
				if err != nil {
					return fmt.Errorf("unable to allocate ingress IPs: %s, see https://cilium.link/ipam-range-full", err)
				}
			}

			// Coalescing multiple CIDRs. GH #18868
			if option.Config.EnableIPv4Masquerade &&
				option.Config.IPAM == ipamOption.IPAMENI &&
				result != nil &&
				len(result.CIDRs) > 0 {
				result.CIDRs = coalesceCIDRs(result.CIDRs)
			}

			node.SetIngressIPv4(result.IP)
			log.Infof("  Ingress IPv4: %s", node.GetIngressIPv4())

			// In ENI and AlibabaCloud ENI mode, we require the gateway, CIDRs, and the
			// ENI MAC addr in order to set up rules and routes on the local node to
			// direct ingress traffic out of the ENIs.
			if option.Config.IPAM == ipamOption.IPAMENI || option.Config.IPAM == ipamOption.IPAMAlibabaCloud {
				if ingressRouting, err := parseRoutingInfo(result); err != nil {
					log.WithError(err).Warn("Unable to allocate ingress information for ENI")
				} else {
					if err := ingressRouting.Configure(
						result.IP,
						d.mtuConfig.GetDeviceMTU(),
						option.Config.EgressMultiHomeIPRuleCompat,
					); err != nil {
						log.WithError(err).Warn("Error while configuring ingress IP rules and routes.")
					}
				}
			}
		}

		// Only allocate if enabled and not restored already
		if option.Config.EnableIPv6 {
			var result *ipam.AllocationResult
			var err error

			// Reallocate the same address as before, if possible
			ingressIPv6 := node.GetIngressIPv6()
			if ingressIPv6 != nil {
				result, err = d.ipam.AllocateIPWithoutSyncUpstream(ingressIPv6, "ingress", ipam.PoolDefault)
				if err != nil {
					log.WithError(err).WithField(logfields.SourceIP, ingressIPv6).Warn("unable to re-allocate ingress IPv6.")
					result = nil
				}
			}

			// Allocate a fresh IP if not restored, or the reallocation of the restored
			// IP failed
			if result == nil {
				result, err = d.ipam.AllocateNextFamilyWithoutSyncUpstream(ipam.IPv6, "ingress", ipam.PoolDefault)
				if err != nil {
					if ingressIPv4 := node.GetIngressIPv4(); ingressIPv4 != nil {
						d.ipam.ReleaseIP(ingressIPv4, ipam.PoolDefault)
						node.SetIngressIPv4(nil)
					}
					return fmt.Errorf("unable to allocate ingress IPs: %s, see https://cilium.link/ipam-range-full", err)
				}
			}

			// Coalescing multiple CIDRs. GH #18868
			if option.Config.EnableIPv6Masquerade &&
				option.Config.IPAM == ipamOption.IPAMENI &&
				result != nil &&
				len(result.CIDRs) > 0 {
				result.CIDRs = coalesceCIDRs(result.CIDRs)
			}

			node.SetIngressIPv6(result.IP)
			log.Infof("  Ingress IPv6: %s", node.GetIngressIPv6())
		}
	}
	bootstrapStats.ingressIPAM.End(true)
	return nil
}

func (d *Daemon) allocateIPs() error {
	bootstrapStats.ipam.Start()
	if option.Config.EnableIPv4 {
		routerIP, err := d.allocateRouterIPv4(d.datapath.LocalNodeAddressing().IPv4())
		if err != nil {
			return err
		}
		if routerIP != nil {
			node.SetInternalIPv4Router(routerIP)
		}
	}

	if option.Config.EnableIPv6 {
		routerIP, err := d.allocateRouterIPv6(d.datapath.LocalNodeAddressing().IPv6())
		if err != nil {
			return err
		}
		if routerIP != nil {
			node.SetIPv6Router(routerIP)
		}
	}

	log.Info("Addressing information:")
	log.Infof("  Cluster-Name: %s", option.Config.ClusterName)
	log.Infof("  Cluster-ID: %d", option.Config.ClusterID)
	log.Infof("  Local node-name: %s", nodeTypes.GetName())
	log.Infof("  Node-IPv6: %s", node.GetIPv6())

	if option.Config.EnableIPv6 {
		log.Infof("  IPv6 allocation prefix: %s", node.GetIPv6AllocRange())

		if c := option.Config.GetIPv6NativeRoutingCIDR(); c != nil {
			log.Infof("  IPv6 native routing prefix: %s", c.String())
		}

		log.Infof("  IPv6 router address: %s", node.GetIPv6Router())

		if addrs, err := d.datapath.LocalNodeAddressing().IPv6().LocalAddresses(); err != nil {
			log.WithError(err).Fatal("Unable to list local IPv6 addresses")
		} else {
			log.Info("  Local IPv6 addresses:")
			for _, ip := range addrs {
				log.Infof("  - %s", ip)
			}
		}
	}

	log.Infof("  External-Node IPv4: %s", node.GetIPv4())
	log.Infof("  Internal-Node IPv4: %s", node.GetInternalIPv4Router())

	if option.Config.EnableIPv4 {
		log.Infof("  IPv4 allocation prefix: %s", node.GetIPv4AllocRange())

		if c := option.Config.GetIPv4NativeRoutingCIDR(); c != nil {
			log.Infof("  IPv4 native routing prefix: %s", c.String())
		}

		// Allocate IPv4 service loopback IP
		loopbackIPv4 := net.ParseIP(option.Config.LoopbackIPv4)
		if loopbackIPv4 == nil {
			return fmt.Errorf("Invalid IPv4 loopback address %s", option.Config.LoopbackIPv4)
		}
		node.SetIPv4Loopback(loopbackIPv4)
		log.Infof("  Loopback IPv4: %s", node.GetIPv4Loopback().String())

		if addrs, err := d.datapath.LocalNodeAddressing().IPv4().LocalAddresses(); err != nil {
			log.WithError(err).Fatal("Unable to list local IPv4 addresses")
		} else {
			log.Info("  Local IPv4 addresses:")
			for _, ip := range addrs {
				log.Infof("  - %s", ip)
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
			log.WithError(err).WithField(logfields.V4Prefix, option.Config.IPv4Range).Fatal("Invalid IPv4 allocation prefix")
		}
		node.SetIPv4AllocRange(allocCIDR)
	}

	if option.Config.IPv6Range != AutoCIDR {
		allocCIDR, err := cidr.ParseCIDR(option.Config.IPv6Range)
		if err != nil {
			log.WithError(err).WithField(logfields.V6Prefix, option.Config.IPv6Range).Fatal("Invalid IPv6 allocation prefix")
		}

		node.SetIPv6NodeRange(allocCIDR)
	}

	if err := node.AutoComplete(); err != nil {
		log.WithError(err).Fatal("Cannot autocomplete node addresses")
	}
}

func (d *Daemon) startIPAM() {
	bootstrapStats.ipam.Start()
	log.Info("Initializing node addressing")
	// Set up ipam conf after init() because we might be running d.conf.KVStoreIPv4Registration
	d.ipam = ipam.NewIPAM(d.datapath.LocalNodeAddressing(), option.Config, d.nodeDiscovery, d.k8sWatcher, &d.mtuConfig, d.clientset)
	if d.ipamMetadata != nil {
		d.ipam.WithMetadata(d.ipamMetadata)
	}
	bootstrapStats.ipam.End(true)
}

func parseRoutingInfo(result *ipam.AllocationResult) (*linuxrouting.RoutingInfo, error) {
	return linuxrouting.NewRoutingInfo(
		result.GatewayIP,
		result.CIDRs,
		result.PrimaryMAC,
		result.InterfaceNumber,
		option.Config.IPAM,
		option.Config.EnableIPv4Masquerade,
	)
}
