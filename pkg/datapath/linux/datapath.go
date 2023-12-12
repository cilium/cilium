// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"github.com/cilium/cilium/pkg/datapath/loader"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/maps/nodemap"
)

// DatapathConfiguration is the static configuration of the datapath. The
// configuration cannot change throughout the lifetime of a datapath object.
type DatapathConfiguration struct {
	// HostDevice is the name of the device to be used to access the host.
	HostDevice string

	// TunnelDevice is the name of the tunnel device (if any).
	TunnelDevice string

	ProcFs string
}

type linuxDatapath struct {
	datapath.ConfigWriter
	datapath.IptablesManager
	node           *linuxNodeHandler
	nodeAddressing datapath.NodeAddressing
	config         DatapathConfiguration
	loader         *loader.Loader
	wgAgent        datapath.WireguardAgent
	lbmap          datapath.LBMap
	bwmgr          datapath.BandwidthManager
}

type DatapathParams struct {
	ConfigWriter   datapath.ConfigWriter
	RuleManager    datapath.IptablesManager
	WGAgent        datapath.WireguardAgent
	NodeMap        nodemap.Map
	BWManager      datapath.BandwidthManager
	NodeAddressing datapath.NodeAddressing
	MTU            datapath.MTUConfiguration
}

// NewDatapath creates a new Linux datapath
func NewDatapath(p DatapathParams, cfg DatapathConfiguration) datapath.Datapath {
	dp := &linuxDatapath{
		ConfigWriter:    p.ConfigWriter,
		IptablesManager: p.RuleManager,
		nodeAddressing:  p.NodeAddressing,
		config:          cfg,
		loader:          loader.NewLoader(),
		wgAgent:         p.WGAgent,
		lbmap:           lbmap.New(),
		bwmgr:           p.BWManager,
	}

	dp.node = NewNodeHandler(cfg, dp.nodeAddressing, p.NodeMap, p.MTU)
	return dp
}

func (l *linuxDatapath) Name() string {
	return "linux-datapath"
}

// Node returns the handler for node events
func (l *linuxDatapath) Node() datapath.NodeHandler {
	return l.node
}

func (l *linuxDatapath) NodeIDs() datapath.NodeIDHandler {
	return l.node
}

func (l *linuxDatapath) NodeNeighbors() datapath.NodeNeighbors {
	return l.node
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

func (l *linuxDatapath) Procfs() string {
	return l.config.ProcFs
}

func (l *linuxDatapath) LBMap() datapath.LBMap {
	return l.lbmap
}

func (l *linuxDatapath) BandwidthManager() datapath.BandwidthManager {
	return l.bwmgr
}

func (l *linuxDatapath) DeleteEndpointBandwidthLimit(epID uint16) error {
	return l.bwmgr.DeleteEndpointBandwidthLimit(epID)
}
