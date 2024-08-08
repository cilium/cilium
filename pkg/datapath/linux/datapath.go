// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	datapath "github.com/cilium/cilium/pkg/datapath/types"
)

// DatapathConfiguration is the static configuration of the datapath. The
// configuration cannot change throughout the lifetime of a datapath object.
type DatapathConfiguration struct {
	// HostDevice is the name of the device to be used to access the host.
	HostDevice string

	// TunnelDevice is the name of the tunnel device (if any).
	TunnelDevice string
}

type linuxDatapath struct {
	datapath.IptablesManager
}

type DatapathParams struct {
	RuleManager datapath.IptablesManager
}

// NewDatapath creates a new Linux datapath
func NewDatapath(p DatapathParams) datapath.Datapath {
	dp := &linuxDatapath{
		IptablesManager: p.RuleManager,
	}

	return dp
}

func (l *linuxDatapath) Name() string {
	return "linux-datapath"
}
