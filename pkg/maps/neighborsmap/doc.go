// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package neighborsmap represents the map that stores IP to mac address
// mappings for NodePort clients. It is primarily managed from the
// datapath; Cilium side is used to create the map only.
// +groupName=maps
package neighborsmap
