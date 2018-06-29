// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mtu

const (
	// MaxMTU is the highest MTU that can be used for devices and routes
	// handled by Cilium. It will typically be used to configure inbound
	// paths towards containers where it is guaranteed that the packet will
	// not be rerouted to another node, and therefore will not lead to
	// any form of IP fragmentation.
	// One might expect this to be 65535, however Linux seems to cap the
	// MTU of routes at 65520, so we use this value below.
	MaxMTU = 65520

	// EthernetMTU is the standard MTU for Ethernet devices. It is used
	// as the MTU for container devices when running direct routing mode.
	EthernetMTU = 1500

	// TunnelOverhead is an approximation for bytes used for tunnel
	// encapsulation. It accounts for:
	//    (Outer ethernet is not accounted against MTU size)
	//    Outer IPv4 header:  20B
	//    Outer UDP header:    8B
	//    Outer VXLAN header:  8B
	//    Original Ethernet:  14B
	//                        ---
	//    Total extra bytes:  50B
	TunnelOverhead = 50
)

var (
	// StandardMTU is the regular MTU used for configuring devices and
	// routes where packets are expected to be delivered outside the node.
	//
	// Note that this is a singleton for the process including this
	// package. This means, for instance, that when using this from the
	// ``pkg/plugins/*`` sources, it will not respect the settings
	// configured inside the ``daemon/``.
	StandardMTU = EthernetMTU

	// TunnelMTU is the MTU used for configuring a tunnel mesh for
	// inter-node connectivity.
	//
	// Similar to StandardMTU, this is a singleton for the process.
	TunnelMTU = EthernetMTU - TunnelOverhead
)

// UseMTU modifies StandardMTU so that all subsequent link and route MTU
// modifications will make use of this MTU.
func UseMTU(mtu int) {
	StandardMTU = mtu
	TunnelMTU = mtu - TunnelOverhead
}

// GetRouteMTU returns the MTU to be used on the network. When running in
// tunneling mode, this will have tunnel overhead accounted for.
func GetRouteMTU() int {
	return TunnelMTU
}

// GetDeviceMTU returns the MTU to be used on workload facing devices.
func GetDeviceMTU() int {
	return StandardMTU
}
