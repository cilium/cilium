// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package types

import "github.com/cilium/cilium/pkg/types"

type Key4 struct {
	PrefixLen uint32
	Address   types.IPv4
}

type Value struct {
	Pad uint8 // not used
}
