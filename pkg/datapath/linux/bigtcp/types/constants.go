// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

const (
	// Corresponds to the value of GRO_LEGACY_MAX_SIZE and GSO_LEGACY_MAX_SIZE in
	// the kernel. This is the maximum aggregation size of a packet pre BIG TCP.
	GROGSOLegacyMaxSize = 65536
)
