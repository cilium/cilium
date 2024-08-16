// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build armbe || arm64be || mips || mips64 || ppc64

package byteorder

import "encoding/binary"

var Native binary.ByteOrder = binary.BigEndian

func HostToNetwork16(u uint16) uint16 { return u }
func HostToNetwork32(u uint32) uint32 { return u }
func HostToNetwork64(u uint64) uint64 { return u }
func NetworkToHost16(u uint16) uint16 { return u }
func NetworkToHost32(u uint32) uint32 { return u }
func NetworkToHost64(u uint64) uint64 { return u }
