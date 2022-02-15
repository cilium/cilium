// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package trafficdirection

// TrafficDirection specifies the directionality of policy (ingress or egress).
type TrafficDirection uint8

const (
	// Invalid represents an invalid traffic direction.
	Invalid TrafficDirection = 2

	// Egress represents egress traffic.
	Egress TrafficDirection = 1

	// Ingress represents ingress traffic.
	Ingress TrafficDirection = 0
)

// Uint8 normalizes the TrafficDirection for insertion into BPF maps.
func (td TrafficDirection) Uint8() uint8 {
	return uint8(td)
}

func (td TrafficDirection) String() string {
	if td == Egress {
		return "Egress"
	} else if td == Ingress {
		return "Ingress"
	}

	return "Unknown"
}
