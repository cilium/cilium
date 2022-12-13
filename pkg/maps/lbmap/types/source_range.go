// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package types

import "github.com/cilium/cilium/pkg/types"

type SourceRangeKey4 struct {
	PrefixLen uint32     `align:"lpm_key"`
	RevNATID  uint16     `align:"rev_nat_id"`
	Pad       uint16     `align:"pad"`
	Address   types.IPv4 `align:"addr"`
}

type SourceRangeKey6 struct {
	PrefixLen uint32     `align:"lpm_key"`
	RevNATID  uint16     `align:"rev_nat_id"`
	Pad       uint16     `align:"pad"`
	Address   types.IPv6 `align:"addr"`
}

type SourceRangeValue struct {
	Pad uint8 // not used
}
