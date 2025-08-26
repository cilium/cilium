// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package serviceoption

// Default serves only as reference point for default values.
var Default = Options{
	MaxSendBufferSize:       65_536,
	AddressFamilyPreference: AddressPreferIPv4,
}
