// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lb

const (
	// FirstFreeFrontendID is the first ID for which the frontends should be assigned.
	FirstFreeFrontendID = uint32(1)

	// MaxSetOfFrontendID is maximum number of set of frontend IDs that can be stored
	// in the kvstore or the local ID allocator.
	MaxSetOfFrontendID = uint32(0xFFFF)

	// FirstFreeBackendID is the first ID for which the backend should be assigned.
	// BPF datapath assumes that backend_id cannot be 0.
	FirstFreeBackendID = uint32(1)

	// MaxSetOfBackendID is maximum number of set of backendIDs IDs that can be
	// stored in the local ID allocator.
	MaxSetOfBackendID = uint32(0xFFFFFFFF)
)
