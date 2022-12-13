// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package types

type Value struct {
	Count uint64 `align:"count"`
	Bytes uint64 `align:"bytes"`
}
type Key struct {
	Reason   uint8     `align:"reason"`
	Dir      uint8     `align:"dir"`
	Reserved [3]uint16 `align:"reserved"`
}
