// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package defaults

const (
	// AddressScopeMax controls the maximum address scope for addresses to be
	// considered local ones with HOST_ID in the ipcache
	// Use the raw value instead of constant as netlink.SCOPE_HOST is using unix.RT_SCOPE_HOST
	AddressScopeMax = 0xfe // netlink.SCOPE_HOST
)
