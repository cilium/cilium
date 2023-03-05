package tun

import "encoding/binary"

// TODO: Explore SIMD and/or other assembly optimizations.
func checksumNoFold(b []byte, initial uint64) uint64 {
	ac := initial
	i := 0
	n := len(b)
	for n >= 4 {
		ac += uint64(binary.BigEndian.Uint32(b[i : i+4]))
		n -= 4
		i += 4
	}
	for n >= 2 {
		ac += uint64(binary.BigEndian.Uint16(b[i : i+2]))
		n -= 2
		i += 2
	}
	if n == 1 {
		ac += uint64(b[i]) << 8
	}
	return ac
}

func checksum(b []byte, initial uint64) uint16 {
	ac := checksumNoFold(b, initial)
	ac = (ac >> 16) + (ac & 0xffff)
	ac = (ac >> 16) + (ac & 0xffff)
	ac = (ac >> 16) + (ac & 0xffff)
	ac = (ac >> 16) + (ac & 0xffff)
	return uint16(ac)
}

func pseudoHeaderChecksumNoFold(protocol uint8, srcAddr, dstAddr []byte, totalLen uint16) uint64 {
	sum := checksumNoFold(srcAddr, 0)
	sum = checksumNoFold(dstAddr, sum)
	sum = checksumNoFold([]byte{0, protocol}, sum)
	tmp := make([]byte, 2)
	binary.BigEndian.PutUint16(tmp, totalLen)
	return checksumNoFold(tmp, sum)
}
