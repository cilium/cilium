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

// The skb mark is used to transmit both identity and special markers to
// identify traffic from and to proxies. The mark field is being used in the
// following way:
//
//  1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
// +-------------------------------+-------+-------+---------------+
// |L L L L L L L L L L L L L L L L|R R R R|M M M M|U U U U U U U U|
// +-------------------------------+-------+-------+---------------+
//  identity                        k8s     mark    identity
//
// Identity (24 bits):
// +-----------------------------------------------+
// |U U U U U U U U|L L L L L L L L L L L L L L L L|
// +-----------------------------------------------+
//  1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4
//
// Kubernetes Mark (4 bits):
// R R R R
// 0 1 0 0  Masquerade
// 1 0 0 0  Drop
//
// Cilium Mark (4 bits):
// M M M M
// 1 0 1 0 Ingress proxy
// 1 0 1 1 Egress proxy
// 1 1 0 0 From host
// 0 0 1 0 To Ingress Proxy
// 0 0 1 1 To Egress proxy
//
const (
	// MagicMarkHostMask can be used to fetch the host/proxy-relevant magic
	// bits from a mark.
	MagicMarkHostMask int = 0x0F00
	// MagicMarkProxyMask can be used to fetch the proxy-relevant magic
	// bits from a mark.
	MagicMarkProxyMask int = 0x0E00
	// MagicMarkIsProxy can be used in conjunction with MagicMarkProxyMask
	// to determine whether the mark is indicating that traffic is sourced
	// from a proxy.
	MagicMarkIsProxy int = 0x0A00
	// MagicMarkIsToProxy can be used in conjunction with MagicMarkHostMask
	// to determine whether the mark is indicating that traffic is destined
	// to a proxy.
	MagicMarkIsToProxy int = 0x0200

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
	var mark int

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
