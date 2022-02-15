// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package eppolicymap represents the map from an endpoint ID to its policy map.
// This map is of type bpf.MapTypeHashOfMaps where the key is the endpoint ID.
// It is used to lookup the policy from the socket context where unlike in the
// L2/L3 context, where the program has a direct lookup of the policy because
// each program is attached to an endpoint, socket programs run on all sockets
// regardless of endpoint.
// +groupName=maps
package eppolicymap
