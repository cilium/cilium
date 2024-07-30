// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

// Datapath is the interface to abstract all datapath interactions. The
// abstraction allows to implement the datapath requirements with multiple
// implementations
type Datapath interface {
	ConfigWriter
	IptablesManager

	// Node must return the handler for node events
	Node() NodeHandler

	NodeNeighbors() NodeNeighbors

	// LocalNodeAddressing must return the node addressing implementation
	// of the local node
	LocalNodeAddressing() NodeAddressing

	// Loader must return the implementation of the loader, which is responsible
	// for loading, reloading, and compiling datapath programs.
	Loader() Loader

	// WireguardAgent returns the WireGuard agent for the local node
	WireguardAgent() WireguardAgent

	// LBMap returns the load-balancer map
	LBMap() LBMap

	BandwidthManager() BandwidthManager

	Orchestrator() Orchestrator
}
