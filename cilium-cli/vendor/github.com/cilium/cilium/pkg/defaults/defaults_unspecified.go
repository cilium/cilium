// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package defaults

const (
	// AddressScopeMax controls the maximum address scope for addresses to be
	// considered local ones with HOST_ID in the ipcache
	// Use the raw value instead of constant as netlink.SCOPE_LINK is using unix.RT_SCOPE_LINK
	AddressScopeMax = 0xfd - 1 // netlink.SCOPE_LINK - 1
)
