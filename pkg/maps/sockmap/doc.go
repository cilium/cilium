// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package Sockmap represents the map from 5-tuple to the socket. It
// is primarily managed from the datapath using a sockops program. Cilium
// side is primarily for pretty printing.
// +groupName=maps
package sockmap
