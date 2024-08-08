// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

// Datapath is the interface to abstract all datapath interactions. The
// abstraction allows to implement the datapath requirements with multiple
// implementations
type Datapath interface {
	ConfigWriter
	IptablesManager

	// LocalNodeAddressing must return the node addressing implementation
	// of the local node
	LocalNodeAddressing() NodeAddressing

	// LBMap returns the load-balancer map
	LBMap() LBMap

	BandwidthManager() BandwidthManager

	Orchestrator() Orchestrator
}
