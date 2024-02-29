// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sniff

// TunnelFilter is a tcpdump filter which captures encapsulated packets.
//
// Some explanations:
//   - "udp[8:2] = 0x0800" compares the first two bytes of an UDP payload
//     against VXLAN commonly used flags. In addition we check against
//     the default Cilium's VXLAN port (8472).
//   - To catch Geneve traffic we cannot use the "geneve" filter, as it shifts
//     offset of a filtered packet, which invalidates a filter matching on the
//     outer headers. Thus this poor UDP/6081 check.
const TunnelFilter = "(udp and (udp[8:2] = 0x0800 or dst port 8472 or dst port 6081))"
