/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package tun

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
)

const tcpFlagsOffset = 13

const (
	tcpFlagFIN uint8 = 0x01
	tcpFlagPSH uint8 = 0x08
	tcpFlagACK uint8 = 0x10
)

// virtioNetHdr is defined in the kernel in include/uapi/linux/virtio_net.h. The
// kernel symbol is virtio_net_hdr.
type virtioNetHdr struct {
	flags      uint8
	gsoType    uint8
	hdrLen     uint16
	gsoSize    uint16
	csumStart  uint16
	csumOffset uint16
}

func (v *virtioNetHdr) decode(b []byte) error {
	if len(b) < virtioNetHdrLen {
		return io.ErrShortBuffer
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(v)), virtioNetHdrLen), b[:virtioNetHdrLen])
	return nil
}

func (v *virtioNetHdr) encode(b []byte) error {
	if len(b) < virtioNetHdrLen {
		return io.ErrShortBuffer
	}
	copy(b[:virtioNetHdrLen], unsafe.Slice((*byte)(unsafe.Pointer(v)), virtioNetHdrLen))
	return nil
}

const (
	// virtioNetHdrLen is the length in bytes of virtioNetHdr. This matches the
	// shape of the C ABI for its kernel counterpart -- sizeof(virtio_net_hdr).
	virtioNetHdrLen = int(unsafe.Sizeof(virtioNetHdr{}))
)

// flowKey represents the key for a flow.
type flowKey struct {
	srcAddr, dstAddr [16]byte
	srcPort, dstPort uint16
	rxAck            uint32 // varying ack values should not be coalesced. Treat them as separate flows.
}

// tcpGROTable holds flow and coalescing information for the purposes of GRO.
type tcpGROTable struct {
	itemsByFlow map[flowKey][]tcpGROItem
	itemsPool   [][]tcpGROItem
}

func newTCPGROTable() *tcpGROTable {
	t := &tcpGROTable{
		itemsByFlow: make(map[flowKey][]tcpGROItem, conn.IdealBatchSize),
		itemsPool:   make([][]tcpGROItem, conn.IdealBatchSize),
	}
	for i := range t.itemsPool {
		t.itemsPool[i] = make([]tcpGROItem, 0, conn.IdealBatchSize)
	}
	return t
}

func newFlowKey(pkt []byte, srcAddr, dstAddr, tcphOffset int) flowKey {
	key := flowKey{}
	addrSize := dstAddr - srcAddr
	copy(key.srcAddr[:], pkt[srcAddr:dstAddr])
	copy(key.dstAddr[:], pkt[dstAddr:dstAddr+addrSize])
	key.srcPort = binary.BigEndian.Uint16(pkt[tcphOffset:])
	key.dstPort = binary.BigEndian.Uint16(pkt[tcphOffset+2:])
	key.rxAck = binary.BigEndian.Uint32(pkt[tcphOffset+8:])
	return key
}

// lookupOrInsert looks up a flow for the provided packet and metadata,
// returning the packets found for the flow, or inserting a new one if none
// is found.
func (t *tcpGROTable) lookupOrInsert(pkt []byte, srcAddrOffset, dstAddrOffset, tcphOffset, tcphLen, bufsIndex int) ([]tcpGROItem, bool) {
	key := newFlowKey(pkt, srcAddrOffset, dstAddrOffset, tcphOffset)
	items, ok := t.itemsByFlow[key]
	if ok {
		return items, ok
	}
	// TODO: insert() performs another map lookup. This could be rearranged to avoid.
	t.insert(pkt, srcAddrOffset, dstAddrOffset, tcphOffset, tcphLen, bufsIndex)
	return nil, false
}

// insert an item in the table for the provided packet and packet metadata.
func (t *tcpGROTable) insert(pkt []byte, srcAddrOffset, dstAddrOffset, tcphOffset, tcphLen, bufsIndex int) {
	key := newFlowKey(pkt, srcAddrOffset, dstAddrOffset, tcphOffset)
	item := tcpGROItem{
		key:       key,
		bufsIndex: uint16(bufsIndex),
		gsoSize:   uint16(len(pkt[tcphOffset+tcphLen:])),
		iphLen:    uint8(tcphOffset),
		tcphLen:   uint8(tcphLen),
		sentSeq:   binary.BigEndian.Uint32(pkt[tcphOffset+4:]),
		pshSet:    pkt[tcphOffset+tcpFlagsOffset]&tcpFlagPSH != 0,
	}
	items, ok := t.itemsByFlow[key]
	if !ok {
		items = t.newItems()
	}
	items = append(items, item)
	t.itemsByFlow[key] = items
}

func (t *tcpGROTable) updateAt(item tcpGROItem, i int) {
	items, _ := t.itemsByFlow[item.key]
	items[i] = item
}

func (t *tcpGROTable) deleteAt(key flowKey, i int) {
	items, _ := t.itemsByFlow[key]
	items = append(items[:i], items[i+1:]...)
	t.itemsByFlow[key] = items
}

// tcpGROItem represents bookkeeping data for a TCP packet during the lifetime
// of a GRO evaluation across a vector of packets.
type tcpGROItem struct {
	key       flowKey
	sentSeq   uint32 // the sequence number
	bufsIndex uint16 // the index into the original bufs slice
	numMerged uint16 // the number of packets merged into this item
	gsoSize   uint16 // payload size
	iphLen    uint8  // ip header len
	tcphLen   uint8  // tcp header len
	pshSet    bool   // psh flag is set
}

func (t *tcpGROTable) newItems() []tcpGROItem {
	var items []tcpGROItem
	items, t.itemsPool = t.itemsPool[len(t.itemsPool)-1], t.itemsPool[:len(t.itemsPool)-1]
	return items
}

func (t *tcpGROTable) reset() {
	for k, items := range t.itemsByFlow {
		items = items[:0]
		t.itemsPool = append(t.itemsPool, items)
		delete(t.itemsByFlow, k)
	}
}

// canCoalesce represents the outcome of checking if two TCP packets are
// candidates for coalescing.
type canCoalesce int

const (
	coalescePrepend     canCoalesce = -1
	coalesceUnavailable canCoalesce = 0
	coalesceAppend      canCoalesce = 1
)

// tcpPacketsCanCoalesce evaluates if pkt can be coalesced with the packet
// described by item. This function makes considerations that match the kernel's
// GRO self tests, which can be found in tools/testing/selftests/net/gro.c.
func tcpPacketsCanCoalesce(pkt []byte, iphLen, tcphLen uint8, seq uint32, pshSet bool, gsoSize uint16, item tcpGROItem, bufs [][]byte, bufsOffset int) canCoalesce {
	pktTarget := bufs[item.bufsIndex][bufsOffset:]
	if tcphLen != item.tcphLen {
		// cannot coalesce with unequal tcp options len
		return coalesceUnavailable
	}
	if tcphLen > 20 {
		if !bytes.Equal(pkt[iphLen+20:iphLen+tcphLen], pktTarget[item.iphLen+20:iphLen+tcphLen]) {
			// cannot coalesce with unequal tcp options
			return coalesceUnavailable
		}
	}
	if pkt[0]>>4 == 6 {
		if pkt[0] != pktTarget[0] || pkt[1]>>4 != pktTarget[1]>>4 {
			// cannot coalesce with unequal Traffic class values
			return coalesceUnavailable
		}
		if pkt[7] != pktTarget[7] {
			// cannot coalesce with unequal Hop limit values
			return coalesceUnavailable
		}
	} else {
		if pkt[1] != pktTarget[1] {
			// cannot coalesce with unequal ToS values
			return coalesceUnavailable
		}
		if pkt[6]>>5 != pktTarget[6]>>5 {
			// cannot coalesce with unequal DF or reserved bits. MF is checked
			// further up the stack.
			return coalesceUnavailable
		}
		if pkt[8] != pktTarget[8] {
			// cannot coalesce with unequal TTL values
			return coalesceUnavailable
		}
	}
	// seq adjacency
	lhsLen := item.gsoSize
	lhsLen += item.numMerged * item.gsoSize
	if seq == item.sentSeq+uint32(lhsLen) { // pkt aligns following item from a seq num perspective
		if item.pshSet {
			// We cannot append to a segment that has the PSH flag set, PSH
			// can only be set on the final segment in a reassembled group.
			return coalesceUnavailable
		}
		if len(pktTarget[iphLen+tcphLen:])%int(item.gsoSize) != 0 {
			// A smaller than gsoSize packet has been appended previously.
			// Nothing can come after a smaller packet on the end.
			return coalesceUnavailable
		}
		if gsoSize > item.gsoSize {
			// We cannot have a larger packet following a smaller one.
			return coalesceUnavailable
		}
		return coalesceAppend
	} else if seq+uint32(gsoSize) == item.sentSeq { // pkt aligns in front of item from a seq num perspective
		if pshSet {
			// We cannot prepend with a segment that has the PSH flag set, PSH
			// can only be set on the final segment in a reassembled group.
			return coalesceUnavailable
		}
		if gsoSize < item.gsoSize {
			// We cannot have a larger packet following a smaller one.
			return coalesceUnavailable
		}
		if gsoSize > item.gsoSize && item.numMerged > 0 {
			// There's at least one previous merge, and we're larger than all
			// previous. This would put multiple smaller packets on the end.
			return coalesceUnavailable
		}
		return coalescePrepend
	}
	return coalesceUnavailable
}

func tcpChecksumValid(pkt []byte, iphLen uint8, isV6 bool) bool {
	srcAddrAt := ipv4SrcAddrOffset
	addrSize := 4
	if isV6 {
		srcAddrAt = ipv6SrcAddrOffset
		addrSize = 16
	}
	tcpTotalLen := uint16(len(pkt) - int(iphLen))
	tcpCSumNoFold := pseudoHeaderChecksumNoFold(unix.IPPROTO_TCP, pkt[srcAddrAt:srcAddrAt+addrSize], pkt[srcAddrAt+addrSize:srcAddrAt+addrSize*2], tcpTotalLen)
	return ^checksum(pkt[iphLen:], tcpCSumNoFold) == 0
}

// coalesceResult represents the result of attempting to coalesce two TCP
// packets.
type coalesceResult int

const (
	coalesceInsufficientCap coalesceResult = 0
	coalescePSHEnding       coalesceResult = 1
	coalesceItemInvalidCSum coalesceResult = 2
	coalescePktInvalidCSum  coalesceResult = 3
	coalesceSuccess         coalesceResult = 4
)

// coalesceTCPPackets attempts to coalesce pkt with the packet described by
// item, returning the outcome. This function may swap bufs elements in the
// event of a prepend as item's bufs index is already being tracked for writing
// to a Device.
func coalesceTCPPackets(mode canCoalesce, pkt []byte, pktBuffsIndex int, gsoSize uint16, seq uint32, pshSet bool, item *tcpGROItem, bufs [][]byte, bufsOffset int, isV6 bool) coalesceResult {
	var pktHead []byte // the packet that will end up at the front
	headersLen := item.iphLen + item.tcphLen
	coalescedLen := len(bufs[item.bufsIndex][bufsOffset:]) + len(pkt) - int(headersLen)

	// Copy data
	if mode == coalescePrepend {
		pktHead = pkt
		if cap(pkt)-bufsOffset < coalescedLen {
			// We don't want to allocate a new underlying array if capacity is
			// too small.
			return coalesceInsufficientCap
		}
		if pshSet {
			return coalescePSHEnding
		}
		if item.numMerged == 0 {
			if !tcpChecksumValid(bufs[item.bufsIndex][bufsOffset:], item.iphLen, isV6) {
				return coalesceItemInvalidCSum
			}
		}
		if !tcpChecksumValid(pkt, item.iphLen, isV6) {
			return coalescePktInvalidCSum
		}
		item.sentSeq = seq
		extendBy := coalescedLen - len(pktHead)
		bufs[pktBuffsIndex] = append(bufs[pktBuffsIndex], make([]byte, extendBy)...)
		copy(bufs[pktBuffsIndex][bufsOffset+len(pkt):], bufs[item.bufsIndex][bufsOffset+int(headersLen):])
		// Flip the slice headers in bufs as part of prepend. The index of item
		// is already being tracked for writing.
		bufs[item.bufsIndex], bufs[pktBuffsIndex] = bufs[pktBuffsIndex], bufs[item.bufsIndex]
	} else {
		pktHead = bufs[item.bufsIndex][bufsOffset:]
		if cap(pktHead)-bufsOffset < coalescedLen {
			// We don't want to allocate a new underlying array if capacity is
			// too small.
			return coalesceInsufficientCap
		}
		if item.numMerged == 0 {
			if !tcpChecksumValid(bufs[item.bufsIndex][bufsOffset:], item.iphLen, isV6) {
				return coalesceItemInvalidCSum
			}
		}
		if !tcpChecksumValid(pkt, item.iphLen, isV6) {
			return coalescePktInvalidCSum
		}
		if pshSet {
			// We are appending a segment with PSH set.
			item.pshSet = pshSet
			pktHead[item.iphLen+tcpFlagsOffset] |= tcpFlagPSH
		}
		extendBy := len(pkt) - int(headersLen)
		bufs[item.bufsIndex] = append(bufs[item.bufsIndex], make([]byte, extendBy)...)
		copy(bufs[item.bufsIndex][bufsOffset+len(pktHead):], pkt[headersLen:])
	}

	if gsoSize > item.gsoSize {
		item.gsoSize = gsoSize
	}
	hdr := virtioNetHdr{
		flags:      unix.VIRTIO_NET_HDR_F_NEEDS_CSUM, // this turns into CHECKSUM_PARTIAL in the skb
		hdrLen:     uint16(headersLen),
		gsoSize:    uint16(item.gsoSize),
		csumStart:  uint16(item.iphLen),
		csumOffset: 16,
	}

	// Recalculate the total len (IPv4) or payload len (IPv6). Recalculate the
	// (IPv4) header checksum.
	if isV6 {
		hdr.gsoType = unix.VIRTIO_NET_HDR_GSO_TCPV6
		binary.BigEndian.PutUint16(pktHead[4:], uint16(coalescedLen)-uint16(item.iphLen)) // set new payload len
	} else {
		hdr.gsoType = unix.VIRTIO_NET_HDR_GSO_TCPV4
		pktHead[10], pktHead[11] = 0, 0                               // clear checksum field
		binary.BigEndian.PutUint16(pktHead[2:], uint16(coalescedLen)) // set new total length
		iphCSum := ^checksum(pktHead[:item.iphLen], 0)                // compute checksum
		binary.BigEndian.PutUint16(pktHead[10:], iphCSum)             // set checksum field
	}
	hdr.encode(bufs[item.bufsIndex][bufsOffset-virtioNetHdrLen:])

	// Calculate the pseudo header checksum and place it at the TCP checksum
	// offset. Downstream checksum offloading will combine this with computation
	// of the tcp header and payload checksum.
	addrLen := 4
	addrOffset := ipv4SrcAddrOffset
	if isV6 {
		addrLen = 16
		addrOffset = ipv6SrcAddrOffset
	}
	srcAddrAt := bufsOffset + addrOffset
	srcAddr := bufs[item.bufsIndex][srcAddrAt : srcAddrAt+addrLen]
	dstAddr := bufs[item.bufsIndex][srcAddrAt+addrLen : srcAddrAt+addrLen*2]
	psum := pseudoHeaderChecksumNoFold(unix.IPPROTO_TCP, srcAddr, dstAddr, uint16(coalescedLen-int(item.iphLen)))
	binary.BigEndian.PutUint16(pktHead[hdr.csumStart+hdr.csumOffset:], checksum([]byte{}, psum))

	item.numMerged++
	return coalesceSuccess
}

const (
	ipv4FlagMoreFragments uint8 = 0x20
)

const (
	ipv4SrcAddrOffset = 12
	ipv6SrcAddrOffset = 8
	maxUint16         = 1<<16 - 1
)

// tcpGRO evaluates the TCP packet at pktI in bufs for coalescing with
// existing packets tracked in table. It will return false when pktI is not
// coalesced, otherwise true. This indicates to the caller if bufs[pktI]
// should be written to the Device.
func tcpGRO(bufs [][]byte, offset int, pktI int, table *tcpGROTable, isV6 bool) (pktCoalesced bool) {
	pkt := bufs[pktI][offset:]
	if len(pkt) > maxUint16 {
		// A valid IPv4 or IPv6 packet will never exceed this.
		return false
	}
	iphLen := int((pkt[0] & 0x0F) * 4)
	if isV6 {
		iphLen = 40
		ipv6HPayloadLen := int(binary.BigEndian.Uint16(pkt[4:]))
		if ipv6HPayloadLen != len(pkt)-iphLen {
			return false
		}
	} else {
		totalLen := int(binary.BigEndian.Uint16(pkt[2:]))
		if totalLen != len(pkt) {
			return false
		}
	}
	if len(pkt) < iphLen {
		return false
	}
	tcphLen := int((pkt[iphLen+12] >> 4) * 4)
	if tcphLen < 20 || tcphLen > 60 {
		return false
	}
	if len(pkt) < iphLen+tcphLen {
		return false
	}
	if !isV6 {
		if pkt[6]&ipv4FlagMoreFragments != 0 || pkt[6]<<3 != 0 || pkt[7] != 0 {
			// no GRO support for fragmented segments for now
			return false
		}
	}
	tcpFlags := pkt[iphLen+tcpFlagsOffset]
	var pshSet bool
	// not a candidate if any non-ACK flags (except PSH+ACK) are set
	if tcpFlags != tcpFlagACK {
		if pkt[iphLen+tcpFlagsOffset] != tcpFlagACK|tcpFlagPSH {
			return false
		}
		pshSet = true
	}
	gsoSize := uint16(len(pkt) - tcphLen - iphLen)
	// not a candidate if payload len is 0
	if gsoSize < 1 {
		return false
	}
	seq := binary.BigEndian.Uint32(pkt[iphLen+4:])
	srcAddrOffset := ipv4SrcAddrOffset
	addrLen := 4
	if isV6 {
		srcAddrOffset = ipv6SrcAddrOffset
		addrLen = 16
	}
	items, existing := table.lookupOrInsert(pkt, srcAddrOffset, srcAddrOffset+addrLen, iphLen, tcphLen, pktI)
	if !existing {
		return false
	}
	for i := len(items) - 1; i >= 0; i-- {
		// In the best case of packets arriving in order iterating in reverse is
		// more efficient if there are multiple items for a given flow. This
		// also enables a natural table.deleteAt() in the
		// coalesceItemInvalidCSum case without the need for index tracking.
		// This algorithm makes a best effort to coalesce in the event of
		// unordered packets, where pkt may land anywhere in items from a
		// sequence number perspective, however once an item is inserted into
		// the table it is never compared across other items later.
		item := items[i]
		can := tcpPacketsCanCoalesce(pkt, uint8(iphLen), uint8(tcphLen), seq, pshSet, gsoSize, item, bufs, offset)
		if can != coalesceUnavailable {
			result := coalesceTCPPackets(can, pkt, pktI, gsoSize, seq, pshSet, &item, bufs, offset, isV6)
			switch result {
			case coalesceSuccess:
				table.updateAt(item, i)
				return true
			case coalesceItemInvalidCSum:
				// delete the item with an invalid csum
				table.deleteAt(item.key, i)
			case coalescePktInvalidCSum:
				// no point in inserting an item that we can't coalesce
				return false
			default:
			}
		}
	}
	// failed to coalesce with any other packets; store the item in the flow
	table.insert(pkt, srcAddrOffset, srcAddrOffset+addrLen, iphLen, tcphLen, pktI)
	return false
}

func isTCP4NoIPOptions(b []byte) bool {
	if len(b) < 40 {
		return false
	}
	if b[0]>>4 != 4 {
		return false
	}
	if b[0]&0x0F != 5 {
		return false
	}
	if b[9] != unix.IPPROTO_TCP {
		return false
	}
	return true
}

func isTCP6NoEH(b []byte) bool {
	if len(b) < 60 {
		return false
	}
	if b[0]>>4 != 6 {
		return false
	}
	if b[6] != unix.IPPROTO_TCP {
		return false
	}
	return true
}

// handleGRO evaluates bufs for GRO, and writes the indices of the resulting
// packets into toWrite. toWrite, tcp4Table, and tcp6Table should initially be
// empty (but non-nil), and are passed in to save allocs as the caller may reset
// and recycle them across vectors of packets.
func handleGRO(bufs [][]byte, offset int, tcp4Table, tcp6Table *tcpGROTable, toWrite *[]int) error {
	for i := range bufs {
		if offset < virtioNetHdrLen || offset > len(bufs[i])-1 {
			return errors.New("invalid offset")
		}
		var coalesced bool
		switch {
		case isTCP4NoIPOptions(bufs[i][offset:]): // ipv4 packets w/IP options do not coalesce
			coalesced = tcpGRO(bufs, offset, i, tcp4Table, false)
		case isTCP6NoEH(bufs[i][offset:]): // ipv6 packets w/extension headers do not coalesce
			coalesced = tcpGRO(bufs, offset, i, tcp6Table, true)
		}
		if !coalesced {
			hdr := virtioNetHdr{}
			err := hdr.encode(bufs[i][offset-virtioNetHdrLen:])
			if err != nil {
				return err
			}
			*toWrite = append(*toWrite, i)
		}
	}
	return nil
}

// tcpTSO splits packets from in into outBuffs, writing the size of each
// element into sizes. It returns the number of buffers populated, and/or an
// error.
func tcpTSO(in []byte, hdr virtioNetHdr, outBuffs [][]byte, sizes []int, outOffset int) (int, error) {
	iphLen := int(hdr.csumStart)
	srcAddrOffset := ipv6SrcAddrOffset
	addrLen := 16
	if hdr.gsoType == unix.VIRTIO_NET_HDR_GSO_TCPV4 {
		in[10], in[11] = 0, 0 // clear ipv4 header checksum
		srcAddrOffset = ipv4SrcAddrOffset
		addrLen = 4
	}
	tcpCSumAt := int(hdr.csumStart + hdr.csumOffset)
	in[tcpCSumAt], in[tcpCSumAt+1] = 0, 0 // clear tcp checksum
	firstTCPSeqNum := binary.BigEndian.Uint32(in[hdr.csumStart+4:])
	nextSegmentDataAt := int(hdr.hdrLen)
	i := 0
	for ; nextSegmentDataAt < len(in); i++ {
		if i == len(outBuffs) {
			return i - 1, ErrTooManySegments
		}
		nextSegmentEnd := nextSegmentDataAt + int(hdr.gsoSize)
		if nextSegmentEnd > len(in) {
			nextSegmentEnd = len(in)
		}
		segmentDataLen := nextSegmentEnd - nextSegmentDataAt
		totalLen := int(hdr.hdrLen) + segmentDataLen
		sizes[i] = totalLen
		out := outBuffs[i][outOffset:]

		copy(out, in[:iphLen])
		if hdr.gsoType == unix.VIRTIO_NET_HDR_GSO_TCPV4 {
			// For IPv4 we are responsible for incrementing the ID field,
			// updating the total len field, and recalculating the header
			// checksum.
			if i > 0 {
				id := binary.BigEndian.Uint16(out[4:])
				id += uint16(i)
				binary.BigEndian.PutUint16(out[4:], id)
			}
			binary.BigEndian.PutUint16(out[2:], uint16(totalLen))
			ipv4CSum := ^checksum(out[:iphLen], 0)
			binary.BigEndian.PutUint16(out[10:], ipv4CSum)
		} else {
			// For IPv6 we are responsible for updating the payload length field.
			binary.BigEndian.PutUint16(out[4:], uint16(totalLen-iphLen))
		}

		// TCP header
		copy(out[hdr.csumStart:hdr.hdrLen], in[hdr.csumStart:hdr.hdrLen])
		tcpSeq := firstTCPSeqNum + uint32(hdr.gsoSize*uint16(i))
		binary.BigEndian.PutUint32(out[hdr.csumStart+4:], tcpSeq)
		if nextSegmentEnd != len(in) {
			// FIN and PSH should only be set on last segment
			clearFlags := tcpFlagFIN | tcpFlagPSH
			out[hdr.csumStart+tcpFlagsOffset] &^= clearFlags
		}

		// payload
		copy(out[hdr.hdrLen:], in[nextSegmentDataAt:nextSegmentEnd])

		// TCP checksum
		tcpHLen := int(hdr.hdrLen - hdr.csumStart)
		tcpLenForPseudo := uint16(tcpHLen + segmentDataLen)
		tcpCSumNoFold := pseudoHeaderChecksumNoFold(unix.IPPROTO_TCP, in[srcAddrOffset:srcAddrOffset+addrLen], in[srcAddrOffset+addrLen:srcAddrOffset+addrLen*2], tcpLenForPseudo)
		tcpCSum := ^checksum(out[hdr.csumStart:totalLen], tcpCSumNoFold)
		binary.BigEndian.PutUint16(out[hdr.csumStart+hdr.csumOffset:], tcpCSum)

		nextSegmentDataAt += int(hdr.gsoSize)
	}
	return i, nil
}

func gsoNoneChecksum(in []byte, cSumStart, cSumOffset uint16) error {
	cSumAt := cSumStart + cSumOffset
	// The initial value at the checksum offset should be summed with the
	// checksum we compute. This is typically the pseudo-header checksum.
	initial := binary.BigEndian.Uint16(in[cSumAt:])
	in[cSumAt], in[cSumAt+1] = 0, 0
	binary.BigEndian.PutUint16(in[cSumAt:], ^checksum(in[cSumStart:], uint64(initial)))
	return nil
}
