// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"log/slog"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/plugins/cilium-cni/types"
)

// EndpointConfigurator returns a list of endpoint configurations for a given
// CNI ADD invocation. If the CNI ADD invocation should result in multiple endpoints
// being created, it may return multiple endpoint configurations, one for each endpoint.
type EndpointConfigurator interface {
	GetConfigurations(p ConfigurationParams) ([]EndpointConfiguration, error)
}

// EndpointConfiguration determines the configuration of an endpoint to be
// created during a CNI ADD invocation.
type EndpointConfiguration interface {
	// IfName specifies the container interface name to be used for this endpoint
	IfName() string
	// IPAMPool specifies which IPAM pool the endpoint's IP should be allocated from
	IPAMPool() string

	// PrepareEndpoint returns the interface configuration 'cmd' of the container
	// namespace as well as the template for the endpoint creation request 'ep'.
	PrepareEndpoint(ipam *models.IPAMResponse) (cmd *CmdState, ep *models.EndpointChangeRequest, err error)
}

// ConfigurationParams contains the arguments and Cilium configuration of a CNI
// invocation. Those fields may be used by custom implementations of the
// EndpointConfigurator interface to customize the CNI ADD call.
type ConfigurationParams struct {
	Log     *slog.Logger
	Conf    *models.DaemonConfigurationStatus
	Args    *skel.CmdArgs
	CniArgs *types.ArgsSpec
}

// DefaultConfigurator is the default endpoint configurator. It configures a
// single endpoint for the interface name provided by the CNI ADD invocation,
// using an auto-selected IPAM pool.
type DefaultConfigurator struct{}

// GetConfigurations returns a single a default configuration
func (c *DefaultConfigurator) GetConfigurations(p ConfigurationParams) ([]EndpointConfiguration, error) {
	return []EndpointConfiguration{
		&defaultEndpointConfiguration{
			ConfigurationParams: p,
		},
	}, nil
}

// defaultEndpointConfiguration is the default configuration when a single endpoint
// is to be created
type defaultEndpointConfiguration struct {
	ConfigurationParams
}

func (c *defaultEndpointConfiguration) IfName() string {
	return c.Args.IfName
}

func (c *defaultEndpointConfiguration) IPAMPool() string {
	return "" // auto-select
}

func (c *defaultEndpointConfiguration) PrepareEndpoint(ipam *models.IPAMResponse) (cmd *CmdState, ep *models.EndpointChangeRequest, err error) {
	ep = &models.EndpointChangeRequest{
		ContainerID:            c.Args.ContainerID,
		Labels:                 models.Labels{},
		State:                  models.EndpointStateWaitingDashForDashIdentity.Pointer(),
		Addressing:             &models.AddressPair{},
		K8sPodName:             string(c.CniArgs.K8S_POD_NAME),
		K8sNamespace:           string(c.CniArgs.K8S_POD_NAMESPACE),
		K8sUID:                 string(c.CniArgs.K8S_POD_UID),
		ContainerInterfaceName: c.Args.IfName,
		DatapathConfiguration:  &models.EndpointDatapathConfiguration{},
	}

	if c.Conf.IpamMode == ipamOption.IPAMDelegatedPlugin {
		// Prevent cilium agent from trying to release the IP when the endpoint is deleted.
		ep.DatapathConfiguration.ExternalIpam = true
	}

	if c.Conf.IpamMode == ipamOption.IPAMENI {
		ifindex, err := ifindexFromMac(ipam.IPV4.MasterMac)
		if err == nil {
			ep.ParentInterfaceIndex = ifindex
		} else {
			c.Log.Error("Unable to get interface index from MAC address", logfields.Error, err)
		}
	}

	state := &CmdState{
		HostAddr: ipam.HostAddressing,
	}

	return state, ep, nil
}

func ifindexFromMac(mac string) (int64, error) {
	var link netlink.Link

	links, err := safenetlink.LinkList()
	if err != nil {
		return -1, fmt.Errorf("unable to list interfaces: %w", err)
	}

	for _, l := range links {
		// Linux slave devices have the same MAC address as their master
		// device, but we want the master device.
		if l.Attrs().RawFlags&unix.IFF_SLAVE != 0 {
			continue
		}
		if l.Attrs().HardwareAddr.String() == mac {
			if link != nil {
				return -1, fmt.Errorf("several interfaces found with MAC %s: %s and %s", mac, link.Attrs().Name, l.Attrs().Name)
			}
			link = l
		}
	}

	if link == nil {
		return -1, fmt.Errorf("no interface found with MAC %s", mac)
	}

	return int64(link.Attrs().Index), nil
}
