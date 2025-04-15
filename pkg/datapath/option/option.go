// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package option

// Available options for datapath mode.
const (
	// DatapathModeVeth specifies veth datapath mode (i.e. containers are
	// attached to a network via veth pairs).
	DatapathModeVeth = "veth"

	// DatapathModeNetkit specifies netkit datapath mode (i.e. containers
	// are attached to a network via netkit pairs). netkit is created in
	// L3 mode.
	DatapathModeNetkit = "netkit"

	// DatapathModeNetkitL2 specifies netkit datapath mode (i.e. containers
	// are attached to a network via netkit pairs). netkit is created in
	// L2 mode.
	DatapathModeNetkitL2 = "netkit-l2"
)
