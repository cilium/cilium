// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package fragmap represents the BPF map used to associate IPv4 datagram
// fragments to the L4 ports of the datagram they belong to, in order to
// retrieve the full 5-tuple necessary to do L4-based lookups.
// +groupName=maps
package fragmap
