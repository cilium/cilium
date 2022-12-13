// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package types

import "github.com/cilium/cilium/pkg/types"

type NatEntry6 struct {
	Created   uint64     `align:"created"`
	HostLocal uint64     `align:"host_local"`
	Pad1      uint64     `align:"pad1"`
	Pad2      uint64     `align:"pad2"`
	Addr      types.IPv6 `align:"to_saddr"`
	Port      uint16     `align:"to_sport"`
}
