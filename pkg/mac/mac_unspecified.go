// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package mac

// HasMacAddr returns true if the given network interface has L2 addr.
// This is not supported for non-linux environment
func HasMacAddr(iface string) bool {
	return false
}
