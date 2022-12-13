// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package types

import (
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/types"
)

type AffinityMatchKey struct {
	BackendID loadbalancer.BackendID `align:"backend_id"`
	RevNATID  uint16                 `align:"rev_nat_id"`
	Pad       uint16                 `align:"pad"`
}

type AffinityMatchValue struct {
	Pad uint8 `align:"pad"`
}

type Affinity4Key struct {
	ClientID    uint64 `align:"client_id"`
	RevNATID    uint16 `align:"rev_nat_id"`
	NetNSCookie uint8  `align:"netns_cookie"`
	Pad1        uint8  `align:"pad1"`
	Pad2        uint32 `align:"pad2"`
}

type Affinity6Key struct {
	ClientID    types.IPv6 `align:"client_id"`
	RevNATID    uint16     `align:"rev_nat_id"`
	NetNSCookie uint8      `align:"netns_cookie"`
	Pad1        uint8      `align:"pad1"`
	Pad2        uint32     `align:"pad2"`
}

type AffinityValue struct {
	LastUsed  uint64 `align:"last_used"`
	BackendID uint32 `align:"backend_id"`
	Pad       uint32 `align:"pad"`
}
