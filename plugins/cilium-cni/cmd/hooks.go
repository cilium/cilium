// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	cniTypesV1 "github.com/containernetworking/cni/pkg/types/100"

	"github.com/cilium/cilium/api/v1/models"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/plugins/cilium-cni/types"
)

// OnConfigReady is invoked at the beginning of [(*Cmd).Add], right after the CNI network
// configuration, CNI arguments and the Cilium agent configuration were loaded. It may be used to
// sets up internal state of the hook.
type OnConfigReady interface {
	OnConfigReady(netConf *types.NetConf, cniArgs *types.ArgsSpec, conf *models.DaemonConfigurationStatus) error
}

// OnIPAMReady is invoked after IPAM configuration was validated. It may be used to derive further
// endpoint configuration related to IPAM.
type OnIPAMReady interface {
	OnIPAMReady(ipam *models.IPAMResponse) error
}

// OnLinkConfigReady is invoked before the datapath connectors are called to create the pod's
// network links (i.e. veth or netkit pairs). It may be used to further modify the link
// configuration.
type OnLinkConfigReady interface {
	OnLinkConfigReady(linkConfig *datapath.LinkConfig) error
}

// OnInterfaceConfigReady is invoked right before the pod's network interface pair is configured and
// the endpoint creation request is sent to the daemon. It may be used to modify the endpoint
// creation request, the command state and the CNI result accumulated so far.
type OnInterfaceConfigReady interface {
	OnInterfaceConfigReady(cmd *CmdState, ep *models.EndpointChangeRequest, res *cniTypesV1.Result) error
}

// WithOnConfigReady adds a new callback to be invoked after the CNI network configuration, CNI
// arguments and the Cilium agent configuration were loaded.
func WithOnConfigReady(f OnConfigReady) Option {
	return func(cmd *Cmd) {
		cmd.onConfigReady = append(cmd.onConfigReady, f)
	}
}

// WithOnIPAMReady adds a new callback to be invoked after IPAM configuration was validated.
func WithOnIPAMReady(f OnIPAMReady) Option {
	return func(cmd *Cmd) {
		cmd.onIPAMReady = append(cmd.onIPAMReady, f)
	}
}

// WithOnLinkConfigReady adds a new callback to be invoked before the datapath connectors are called
// to create the pod's network links.
func WithOnLinkConfigReady(f OnLinkConfigReady) Option {
	return func(cmd *Cmd) {
		cmd.onLinkConfigReady = append(cmd.onLinkConfigReady, f)
	}
}

// WithOnInterfaceConfigReady adds a new callback to be invoked before the pod's network interface
// pair is configured.
func WithOnInterfaceConfigReady(f OnInterfaceConfigReady) Option {
	return func(cmd *Cmd) {
		cmd.onInterfaceConfigReady = append(cmd.onInterfaceConfigReady, f)
	}
}
