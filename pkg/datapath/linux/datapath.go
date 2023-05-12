// SPDX-License-Identifier: Apache-2.0
// Copyright 2019 Authors of Cilium

package linux

import (
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/datapath/linux/config"
	"github.com/cilium/cilium/pkg/datapath/loader"
)

// DatapathConfiguration is the static configuration of the datapath. The
// configuration cannot change throughout the lifetime of a datapath object.
type DatapathConfiguration struct {
	// HostDevice is the name of the device to be used to access the host.
	HostDevice string
}

type linuxDatapath struct {
	datapath.ConfigWriter
	datapath.IptablesManager
	node           *linuxNodeHandler
	nodeAddressing datapath.NodeAddressing
	config         DatapathConfiguration
	loader         *loader.Loader
	wgAgent        datapath.WireguardAgent
}

// NewDatapath creates a new Linux datapath
func NewDatapath(cfg DatapathConfiguration, ruleManager datapath.IptablesManager, wgAgent datapath.WireguardAgent) datapath.Datapath {
	dp := &linuxDatapath{
		ConfigWriter:    &config.HeaderfileWriter{},
		IptablesManager: ruleManager,
		nodeAddressing:  NewNodeAddressing(),
		config:          cfg,
		loader:          loader.NewLoader(canDisableDwarfRelocations),
		wgAgent:         wgAgent,
	}

	dp.node = NewNodeHandler(cfg, dp.nodeAddressing)
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
