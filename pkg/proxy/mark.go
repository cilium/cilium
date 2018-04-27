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

// Magic markers are attached to each packet. The lower 16 bits are used to
// identify packets which have gone through the proxy and to determine whether
// the packet is coming from a proxy at ingress or egress, or from the host.
// The marking is compatible with Kubernetes's use of the packet mark.  The
// upper 16 bits can be used to carry the security identity.
const (
	magicMarkIngress int = 0x0FEA
	magicMarkEgress  int = 0x0FEB
	magicMarkHost    int = 0x0FEC
	magicMarkK8sMasq int = 0x4000
	magicMarkK8sDrop int = 0x8000
)

// getMagicMark returns the magic marker with which each packet must be marked.
// The mark is different depending on whether the proxy is injected at ingress
// or egress.
func getMagicMark(isIngress bool, identity int) int {
	mark := 0

	if isIngress {
		mark = magicMarkIngress
	} else {
		mark = magicMarkEgress
	}

	if identity != 0 {
		mark |= identity << 16
	}

	return mark
}
