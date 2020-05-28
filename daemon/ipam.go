// Copyright 2016-2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	ipamapi "github.com/cilium/cilium/api/v1/server/restapi/ipam"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath"
	linuxrouting "github.com/cilium/cilium/pkg/datapath/linux/routing"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"

	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/swag"
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
	var expirationTimeout time.Duration
	if swag.BoolValue(params.Expiration) {
		expirationTimeout = defaults.IPAMExpiration
	}
	ipv4Result, ipv6Result, err := h.daemon.ipam.AllocateNextWithExpiration(family, owner, expirationTimeout)
	if err != nil {
		return api.Error(ipamapi.PostIpamFailureCode, err)
	}

	resp := &models.IPAMResponse{
		HostAddressing: node.GetNodeAddressing(),
		Address:        &models.AddressPair{},
	}

	if ipv4Result != nil {
		resp.Address.IPV4 = ipv4Result.IP.String()
		resp.IPV4 = &models.IPAMAddressResponse{
			Cidrs:          ipv4Result.CIDRs,
			IP:             ipv4Result.IP.String(),
			MasterMac:      ipv4Result.Master,
			Gateway:        ipv4Result.GatewayIP,
			ExpirationUUID: ipv4Result.ExpirationUUID,
		}
	}

	if ipv6Result != nil {
		resp.Address.IPV6 = ipv6Result.IP.String()
		resp.IPV6 = &models.IPAMAddressResponse{
			Cidrs:          ipv6Result.CIDRs,
			IP:             ipv6Result.IP.String(),
			MasterMac:      ipv6Result.Master,
			Gateway:        ipv6Result.GatewayIP,
			ExpirationUUID: ipv6Result.ExpirationUUID,
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
	if err := h.daemon.ipam.AllocateIPString(params.IP, owner); err != nil {
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

	if err := h.daemon.ipam.ReleaseIPString(params.IP); err != nil {
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

	v4 := []string{}
	for ip := range allocv4 {
		v4 = append(v4, ip)
	}

	v6 := []string{}
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

func (d *Daemon) allocateDatapathIPs(family datapath.NodeAddressingFamily) (routerIP net.IP, err error) {
	// Blacklist allocation of the external IP
	d.ipam.BlacklistIP(family.PrimaryExternal(), "node-ip")

	// (Re-)allocate the router IP. If not possible, allocate a fresh IP.
	// In that case, removal and re-creation of the cilium_host is
	// required. It will also cause disruption of networking until all
	// endpoints have been regenerated.
	routerIP = family.Router()
	if routerIP != nil {
		err = d.ipam.AllocateIPWithoutSyncUpstream(routerIP, "router")
		if err != nil {
			log.Warn("Router IP could not be re-allocated. Need to re-allocate. This will cause brief network disruption")

			// The restored router IP is not part of the allocation range.
			// This indicates that the allocation range has changed.
			if !option.Config.IsFlannelMasterDeviceSet() {
				deleteHostDevice()
			}

			// force re-allocation of the router IP
			routerIP = nil
		}
	}

	if routerIP == nil {
		var result *ipam.AllocationResult
		family := ipam.DeriveFamily(family.PrimaryExternal())
		result, err = d.ipam.AllocateNextFamilyWithoutSyncUpstream(family, "router")
		if err != nil {
			err = fmt.Errorf("Unable to allocate router IP for family %s: %s", family, err)
			return
		}
		routerIP = result.IP
	}

	return
}

func (d *Daemon) allocateHealthIPs() error {
	bootstrapStats.healthCheck.Start()
	if option.Config.EnableHealthChecking && option.Config.EnableEndpointHealthChecking {
		if option.Config.EnableIPv4 {
			result, err := d.ipam.AllocateNextFamilyWithoutSyncUpstream(ipam.IPv4, "health")
			if err != nil {
				return fmt.Errorf("unable to allocate health IPs: %s,see https://cilium.link/ipam-range-full", err)
			}

			log.Debugf("IPv4 health endpoint address: %s", result.IP)
			d.nodeDiscovery.LocalNode.IPv4HealthIP = result.IP

			// In ENI mode, we require the gateway, CIDRs, and the ENI MAC addr
			// in order to set up rules and routes on the local node to direct
			// endpoint traffic out of the ENIs.
			if option.Config.IPAM == option.IPAMENI {
				if err := d.parseHealthEndpointInfo(result); err != nil {
					log.WithError(err).Warn("Unable to allocate health information for ENI")
				}
			}
		}

		if option.Config.EnableIPv6 {
			result, err := d.ipam.AllocateNextFamilyWithoutSyncUpstream(ipam.IPv6, "health")
			if err != nil {
				if d.nodeDiscovery.LocalNode.IPv4HealthIP != nil {
					d.ipam.ReleaseIP(d.nodeDiscovery.LocalNode.IPv4HealthIP)
				}
				return fmt.Errorf("unable to allocate health IPs: %s,see https://cilium.link/ipam-range-full", err)
			}

			d.nodeDiscovery.LocalNode.IPv6HealthIP = result.IP
			log.Debugf("IPv6 health endpoint address: %s", result.IP)
		}
	}
	bootstrapStats.healthCheck.End(true)
	return nil
}

func (d *Daemon) allocateIPs() error {
	bootstrapStats.ipam.Start()
	if option.Config.EnableIPv4 {
		routerIP, err := d.allocateDatapathIPs(d.datapath.LocalNodeAddressing().IPv4())
		if err != nil {
			return err
		}
		if routerIP != nil {
			node.SetInternalIPv4(routerIP)
		}
	}

	if option.Config.EnableIPv6 {
		routerIP, err := d.allocateDatapathIPs(d.datapath.LocalNodeAddressing().IPv6())
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
	log.Infof("  Local node-name: %s", node.GetName())
	log.Infof("  Node-IPv6: %s", node.GetIPv6())

	if option.Config.EnableIPv6 {
		log.Infof("  IPv6 allocation prefix: %s", node.GetIPv6AllocRange())
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

	log.Infof("  External-Node IPv4: %s", node.GetExternalIPv4())
	log.Infof("  Internal-Node IPv4: %s", node.GetInternalIPv4())

	if option.Config.EnableIPv4 {
		log.Infof("  Cluster IPv4 prefix: %s", node.GetIPv4ClusterRange())
		log.Infof("  IPv4 allocation prefix: %s", node.GetIPv4AllocRange())

		if c := option.Config.IPv4NativeRoutingCIDR(); c != nil {
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
	return d.allocateHealthIPs()
}

func (d *Daemon) bootstrapIPAM() {
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
	bootstrapStats.ipam.Start()
	log.Info("Initializing node addressing")

	node.SetIPv4ClusterCidrMaskSize(option.Config.IPv4ClusterCIDRMaskSize)

	if option.Config.IPv4Range != AutoCIDR {
		allocCIDR, err := cidr.ParseCIDR(option.Config.IPv4Range)
		if err != nil {
			log.WithError(err).WithField(logfields.V4Prefix, option.Config.IPv4Range).Fatal("Invalid IPv4 allocation prefix")
		}
		node.SetIPv4AllocRange(allocCIDR)
	}

	if option.Config.IPv6Range != AutoCIDR {
		_, net, err := net.ParseCIDR(option.Config.IPv6Range)
		if err != nil {
			log.WithError(err).WithField(logfields.V6Prefix, option.Config.IPv6Range).Fatal("Invalid IPv6 allocation prefix")
		}

		node.SetIPv6NodeRange(net)
	}

	if err := node.AutoComplete(); err != nil {
		log.WithError(err).Fatal("Cannot autocomplete node addresses")
	}

	// Set up ipam conf after init() because we might be running d.conf.KVStoreIPv4Registration
	d.ipam = ipam.NewIPAM(d.datapath.LocalNodeAddressing(), ipam.Configuration{
		EnableIPv4: option.Config.EnableIPv4,
		EnableIPv6: option.Config.EnableIPv6,
	}, d.nodeDiscovery, d.k8sWatcher)
	bootstrapStats.ipam.End(true)
}

func (d *Daemon) parseHealthEndpointInfo(result *ipam.AllocationResult) error {
	var err error
	d.healthEndpointRouting, err = linuxrouting.NewRoutingInfo(result.GatewayIP,
		result.CIDRs,
		result.Master)
	return err
}
