// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

type MTU struct{}

// GetDeviceMTU implements mtu.MTU.
func (*MTU) GetDeviceMTU() int {
	return 1500
}

// GetRouteMTU implements mtu.MTU.
func (*MTU) GetRouteMTU() int {
	return 1500
}

func (*MTU) IsEnableRouteMTUForCNIChaining() bool {
	return false
}

func (*MTU) IsEnablePacketizationLayerPMTUD() bool {
	return false
}
