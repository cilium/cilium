// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"net/netip"
)

// AddressReleaseHook lets a component coordinate external state with address
// release. Initialization runs before allocator setup, including endpoint restore.
type AddressReleaseHook interface {
	Initialize(context.Context) error
	// BeforeRelease runs under the allocator mutex. An error keeps the address
	// allocated. Implementations must not call IPAM methods from this callback.
	BeforeRelease(netip.Addr, Pool) error
}

// SetAddressReleaseHook installs an optional address-release hook. Call it
// during construction, before ConfigureAllocator or any concurrent IPAM use.
func (ipam *IPAM) SetAddressReleaseHook(hook AddressReleaseHook) {
	ipam.addressReleaseHook = hook
}
