// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/api/v1/models"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/plugins/cilium-cni/types"
)

// EndpointConfigurator returns a list of endpoint configurations for a given
// CNI ADD invocation. If the CNI ADD invocation should result in multiple endpoints
// being created, it may return multiple endpoint configurations, one for each endpoint.
type EndpointConfigurator interface {
	GetConfigurations(p ConfigurationParams) ([]EndpointConfiguration, error)
}

// EndpointConfiguration determines the configuration of an endpoint to be
// created duing a CNI ADD invocation.
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
	Log     *logrus.Entry
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
		ContainerInterfaceName: c.Args.IfName,
		DatapathConfiguration:  &models.EndpointDatapathConfiguration{},
	}

	if c.Conf.IpamMode == ipamOption.IPAMDelegatedPlugin {
		// Prevent cilium agent from trying to release the IP when the endpoint is deleted.
		ep.DatapathConfiguration.ExternalIpam = true
	}

	state := &CmdState{
		HostAddr: ipam.HostAddressing,
	}

	return state, ep, nil
}
