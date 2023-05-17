// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"github.com/cilium/cilium/pkg/datapath/linux/config"
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
}

// NewDatapath creates a new Linux datapath
func NewDatapath(cfg DatapathConfiguration, ruleManager datapath.IptablesManager, wgAgent datapath.WireguardAgent, nodeMap nodemap.Map) datapath.Datapath {
	dp := &linuxDatapath{
		ConfigWriter:    &config.HeaderfileWriter{},
		IptablesManager: ruleManager,
		nodeAddressing:  NewNodeAddressing(),
		config:          cfg,
		loader:          loader.NewLoader(),
		wgAgent:         wgAgent,
		lbmap:           lbmap.New(),
	}

	dp.node = NewNodeHandler(cfg, dp.nodeAddressing, nodeMap)
	return dp
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
