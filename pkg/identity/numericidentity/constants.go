// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package numericidentity contains low-level constants shared by components
// that need to reason about numeric identity wire layout without importing the
// higher-level identity package.
package numericidentity

const (
	// Bitlength is the number of bits used on the wire for a numeric identity.
	Bitlength = 24

	// MinimalIdentity is the first numeric identity value that is not reserved.
	// Global identity allocation for cluster ID 0 starts at this value.
	MinimalIdentity = 256
)
