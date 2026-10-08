// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package metricsmap represents the BPF metrics map in the BPF programs. It is
// implemented as a hash table containing an entry of different drop and forward
// counts for different drop/forward reasons and directions.
// +groupName=maps
package metricsmap
