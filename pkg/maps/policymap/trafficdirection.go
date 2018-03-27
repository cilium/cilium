// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package policymap

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
