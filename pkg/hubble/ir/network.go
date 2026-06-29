// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package ir

import "github.com/cilium/cilium/api/v1/flow"

// NetworkInterface tracks network interface information.
type NetworkInterface struct {
	Name  string `json:"name,omitempty"`
	Index uint32 `json:"index,omitempty"`
}

// IsEmpty returns true if the network interface has no information set.
func (n NetworkInterface) IsEmpty() bool {
	return n.Name == "" && n.Index == 0
}

func (n NetworkInterface) toProto() *flow.NetworkInterface {
	if n.IsEmpty() {
		return nil
	}

	return &flow.NetworkInterface{
		Name:  n.Name,
		Index: n.Index,
	}
}

// ProtoToNetworkInterface converts a protobuf NetworkInterface to an internal representation.
func ProtoToNetworkInterface(n *flow.NetworkInterface) NetworkInterface {
	if n == nil {
		return NetworkInterface{}
	}

	return NetworkInterface{
		Name:  n.Name,
		Index: n.Index,
	}
}
