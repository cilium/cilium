// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/datapath/tables"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/maps/nodemap"
	"github.com/cilium/cilium/pkg/node/manager"
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
	datapath.ConfigWriter
	datapath.IptablesManager
	nodeHandler    datapath.NodeHandler
	nodeNeighbors  datapath.NodeNeighbors
	nodeAddressing datapath.NodeAddressing
	loader         datapath.Loader
	wgAgent        datapath.WireguardAgent
	lbmap          datapath.LBMap
	bwmgr          datapath.BandwidthManager
	orchestrator   datapath.Orchestrator
}

type DatapathParams struct {
	ConfigWriter   datapath.ConfigWriter
	RuleManager    datapath.IptablesManager
	WGAgent        datapath.WireguardAgent
	NodeMap        nodemap.MapV2
	BWManager      datapath.BandwidthManager
	NodeAddressing datapath.NodeAddressing
	MTU            datapath.MTUConfiguration
	Loader         datapath.Loader
	NodeManager    manager.NodeManager
	DB             *statedb.DB
	Devices        statedb.Table[*tables.Device]
	Orchestrator   datapath.Orchestrator
	NodeHandler    datapath.NodeHandler
	NodeNeighbors  datapath.NodeNeighbors
}

// NewDatapath creates a new Linux datapath
func NewDatapath(p DatapathParams) datapath.Datapath {
	dp := &linuxDatapath{
		ConfigWriter:    p.ConfigWriter,
		IptablesManager: p.RuleManager,
		nodeAddressing:  p.NodeAddressing,
		loader:          p.Loader,
		wgAgent:         p.WGAgent,
		lbmap:           lbmap.New(),
		bwmgr:           p.BWManager,
		orchestrator:    p.Orchestrator,
		nodeHandler:     p.NodeHandler,
		nodeNeighbors:   p.NodeNeighbors,
	}

	return dp
}

func (l *linuxDatapath) Name() string {
	return "linux-datapath"
}

// Node returns the handler for node events
func (l *linuxDatapath) Node() datapath.NodeHandler {
	return l.nodeHandler
}

func (l *linuxDatapath) NodeNeighbors() datapath.NodeNeighbors {
	return l.nodeNeighbors
}

// LocalNodeAddressing returns the node addressing implementation of the local
// node
func (l *linuxDatapath) LocalNodeAddressing() datapath.NodeAddressing {
	return l.nodeAddressing
}

func (l *linuxDatapath) Loader() datapath.Loader {
	return l.loader
}

func (l *linuxDatapath) WireguardAgent() datapath.WireguardAgent {
	return l.wgAgent
}

func (l *linuxDatapath) LBMap() datapath.LBMap {
	return l.lbmap
}

func (l *linuxDatapath) BandwidthManager() datapath.BandwidthManager {
	return l.bwmgr
}

func (l *linuxDatapath) Orchestrator() datapath.Orchestrator {
	return l.orchestrator
}
