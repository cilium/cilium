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

// Available options for Unsupported Protocol Actions
const (
	// UnsupportedProtoActionDrop specifies that traffic carrying unsupported
	// protocol types should be dropped in the datapath.
	UnsupportedProtoActionDrop = "drop"

	// UnsupportedProtoActionForward specifies that traffic carrying unsupported
	// protocol types should be forwarded to the host for processing.
	UnsupportedProtoActionForward = "forward"
)
