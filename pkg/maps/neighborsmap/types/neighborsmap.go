// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package types

import "github.com/cilium/cilium/pkg/types"

type Key4 struct {
	Ipv4 types.IPv4
}

type Key6 struct {
	Ipv6 types.IPv6
}

type Value struct {
	MacAddr types.MACAddr
	Pad     uint16
}
