// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package types

import "github.com/cilium/cilium/pkg/types"

type SockmapKey struct {
	DIP    types.IPv6 `align:"$union0"`
	SIP    types.IPv6 `align:"$union1"`
	Family uint8      `align:"family"`
	Pad7   uint8      `align:"pad7"`
	Pad8   uint16     `align:"pad8"`
	SPort  uint32     `align:"sport"`
	DPort  uint32     `align:"dport"`
}

type SockmapValue struct {
	Fd uint32
}
