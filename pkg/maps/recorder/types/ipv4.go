// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package types

import "github.com/cilium/cilium/pkg/types"

type CaptureWcard4 struct {
	SrcAddr  types.IPv4 `align:"saddr"`
	DestAddr types.IPv4 `align:"daddr"`
	SrcPort  uint16     `align:"sport"`
	DestPort uint16     `align:"dport"`
	NextHdr  uint8      `align:"nexthdr"`
	SrcMask  uint8      `align:"smask"`
	DestMask uint8      `align:"dmask"`
	Flags    uint8      `align:"flags"`
}
