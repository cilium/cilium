// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package types

import "github.com/cilium/cilium/pkg/types"

type FragmentKey struct {
	DestAddr   types.IPv4 `align:"daddr"`
	SourceAddr types.IPv4 `align:"saddr"`
	Id         uint16     `align:"id"`
	Proto      uint8      `align:"proto"`
	Pad        uint8      `align:"pad"`
}

type FragmentValue struct {
	SourcePort uint16 `align:"sport"`
	DestPort   uint16 `align:"dport"`
}
