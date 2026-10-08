// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package ipam handles address allocation management: it hands out the
// addresses the local endpoints get, from the pools and CIDRs the node has
// been assigned.
//
// The allocation machinery here is registered by the cilium-agent only. The
// operator's counterpart, which decides what each node is assigned, lives in
// operator/pkg/ipam. A few shared types (Family, PoolSpecAccessors) are
// imported by the operator, but nothing else in this package is.
package ipam
