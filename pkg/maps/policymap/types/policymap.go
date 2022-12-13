// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package types

type PolicyKey struct {
	Identity         uint32 `align:"sec_label"`
	DestPort         uint16 `align:"dport"` // In network byte-order
	Nexthdr          uint8  `align:"protocol"`
	TrafficDirection uint8  `align:"egress"`
}

type PolicyEntry struct {
	ProxyPort uint16 `align:"proxy_port"` // In network byte-order
	Flags     uint8  `align:"deny"`
	AuthType  uint8  `align:"auth_type"`
	Pad1      uint16 `align:"pad1"`
	Pad2      uint16 `align:"pad2"`
	Packets   uint64 `align:"packets"`
	Bytes     uint64 `align:"bytes"`
}

type CallKey struct {
	Index uint32
}

type CallValue struct {
	ProgID uint32
}
