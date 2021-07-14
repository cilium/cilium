// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

//+build 386 amd64 arm arm64 mips64le ppc64le riscv64 wasm

package byteorder

import "encoding/binary"

var Native binary.ByteOrder = binary.LittleEndian

func HostToNetwork16(u uint16) uint16 { return swap16(u) }
func HostToNetwork32(u uint32) uint32 { return swap32(u) }
func NetworkToHost16(u uint16) uint16 { return swap16(u) }
func NetworkToHost32(u uint32) uint32 { return swap32(u) }

func swap16(u uint16) uint16 {
	return (u&0xff00)>>8 | (u&0xff)<<8
}

func swap32(u uint32) uint32 {
	return (u&0xff000000)>>24 | (u&0xff0000)>>8 | (u&0xff00)<<8 | (u&0xff)<<24
}
