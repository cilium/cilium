// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/api/v1/models"
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
