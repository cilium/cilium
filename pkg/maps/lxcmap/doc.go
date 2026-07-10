// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package lxcmap represents the endpoints BPF map in the BPF programs. It is
// implemented as a hash table containing an entry for all local endpoints.
// The hashtable can be accessed through the key EndpointKey and points which
// points to the value EndpointInfo.
// +groupName=maps
package lxcmap
