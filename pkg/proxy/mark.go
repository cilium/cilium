// Copyright 2016-2018 Authors of Cilium
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

package proxy

// Magic markers are attached to each packet.
//
//  1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
// +-----------------------------+-----------+-------+-------------+
// | identity-A                  | k8s       | mark  | identity-B  |
// +-----------------------------+-----------+-------+-------------+
//
// identity-A: [ identity & 0xFFFF ]
// identity-B: [ (identity >> 16) & 0xFF ]
// mark: Special marker to determine whether the packet is coming from a proxy
// at ingress or egress or from the host.
//
// The use of mark is compatible with Kubernetes's use of the packet mark.
const (
	// MagicMarkHostMask can be used to fetch the host/proxy-relevant magic
	// bits from a mark.
	MagicMarkHostMask int = 0x0F00
	// MagicMarkProxyMask can be used to fetch the proxy-relevant magic
	// bits from a mark.
	MagicMarkProxyMask int = 0x0E00
	// MagicMarkIsProxy can be used in conjunction with MagicMarkProxyMask
	// to determine whether the mark is indicating that traffic is peering
	// with a proxy.
	MagicMarkIsProxy int = 0x0A00

	// MagicMarkIngress determines that the traffic is sourced from the
	// proxy which is applying Ingress policy
	MagicMarkIngress int = 0x0A00
	// MagicMarkEgress determines that the traffic is sourced from the
	// proxy which is applying Egress policy
	MagicMarkEgress int = 0x0B00
	// MagicMarkHost determines that the traffic is sourced from the local
	// host and not from a proxy.
	MagicMarkHost int = 0x0C00
	// MagicMarkK8sMasq determines that the traffic should be masqueraded
	// by kube-proxy in kubernetes environments.
	MagicMarkK8sMasq int = 0x4000
	// MagicMarkK8sDrop determines that the traffic should be dropped in
	// kubernetes environments.
	MagicMarkK8sDrop int = 0x8000
)

// getMagicMark returns the magic marker with which each packet must be marked.
// The mark is different depending on whether the proxy is injected at ingress
// or egress.
func getMagicMark(isIngress bool, identity int) int {
	mark := 0

	if isIngress {
		mark = MagicMarkIngress
	} else {
		mark = MagicMarkEgress
	}

	if identity != 0 {
		mark |= (identity >> 16) & 0xFF
		mark |= (identity & 0xFFFF) << 16
	}

	return mark
}
