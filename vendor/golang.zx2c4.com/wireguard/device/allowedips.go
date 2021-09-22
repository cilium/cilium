/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"container/list"
	"errors"
	"math/bits"
	"net"
	"sync"
	"unsafe"
)

type trieEntry struct {
	child        [2]*trieEntry
	peer         *Peer
	bits         net.IP
	cidr         uint
	bit_at_byte  uint
	bit_at_shift uint
	perPeerElem  *list.Element
}

func isLittleEndian() bool {
	one := uint32(1)
	return *(*byte)(unsafe.Pointer(&one)) != 0
}

func swapU32(i uint32) uint32 {
	if !isLittleEndian() {
		return i
	}

	return bits.ReverseBytes32(i)
}

func swapU64(i uint64) uint64 {
	if !isLittleEndian() {
		return i
	}

	return bits.ReverseBytes64(i)
}

func commonBits(ip1 net.IP, ip2 net.IP) uint {
	size := len(ip1)
	if size == net.IPv4len {
		a := (*uint32)(unsafe.Pointer(&ip1[0]))
		b := (*uint32)(unsafe.Pointer(&ip2[0]))
		x := *a ^ *b
		return uint(bits.LeadingZeros32(swapU32(x)))
	} else if size == net.IPv6len {
		a := (*uint64)(unsafe.Pointer(&ip1[0]))
		b := (*uint64)(unsafe.Pointer(&ip2[0]))
		x := *a ^ *b
		if x != 0 {
			return uint(bits.LeadingZeros64(swapU64(x)))
		}
		a = (*uint64)(unsafe.Pointer(&ip1[8]))
		b = (*uint64)(unsafe.Pointer(&ip2[8]))
		x = *a ^ *b
		return 64 + uint(bits.LeadingZeros64(swapU64(x)))
	} else {
		panic("Wrong size bit string")
	}
}

func (node *trieEntry) addToPeerEntries() {
	node.perPeerElem = node.peer.trieEntries.PushBack(node)
}

func (node *trieEntry) removeFromPeerEntries() {
	if node.perPeerElem != nil {
		node.peer.trieEntries.Remove(node.perPeerElem)
		node.perPeerElem = nil
	}
}

func (node *trieEntry) removeByPeer(p *Peer) *trieEntry {
	if node == nil {
		return node
	}

	// walk recursively

	node.child[0] = node.child[0].removeByPeer(p)
	node.child[1] = node.child[1].removeByPeer(p)

	if node.peer != p {
		return node
	}

	// remove peer & merge

	node.removeFromPeerEntries()
	node.peer = nil
	if node.child[0] == nil {
		return node.child[1]
	}
	return node.child[0]
}

func (node *trieEntry) choose(ip net.IP) byte {
	return (ip[node.bit_at_byte] >> node.bit_at_shift) & 1
}

func (node *trieEntry) maskSelf() {
	mask := net.CIDRMask(int(node.cidr), len(node.bits)*8)
	for i := 0; i < len(mask); i++ {
		node.bits[i] &= mask[i]
	}
}

func (node *trieEntry) insert(ip net.IP, cidr uint, peer *Peer) *trieEntry {

	// at leaf

	if node == nil {
		node := &trieEntry{
			bits:         ip,
			peer:         peer,
			cidr:         cidr,
			bit_at_byte:  cidr / 8,
			bit_at_shift: 7 - (cidr % 8),
		}
		node.maskSelf()
		node.addToPeerEntries()
		return node
	}

	// traverse deeper

	common := commonBits(node.bits, ip)
	if node.cidr <= cidr && common >= node.cidr {
		if node.cidr == cidr {
			node.removeFromPeerEntries()
			node.peer = peer
			node.addToPeerEntries()
			return node
		}
		bit := node.choose(ip)
		node.child[bit] = node.child[bit].insert(ip, cidr, peer)
		return node
	}

	// split node

	newNode := &trieEntry{
		bits:         ip,
		peer:         peer,
		cidr:         cidr,
		bit_at_byte:  cidr / 8,
		bit_at_shift: 7 - (cidr % 8),
	}
	newNode.maskSelf()
	newNode.addToPeerEntries()

	cidr = min(cidr, common)

	// check for shorter prefix

	if newNode.cidr == cidr {
		bit := newNode.choose(node.bits)
		newNode.child[bit] = node
		return newNode
	}

	// create new parent for node & newNode

	parent := &trieEntry{
		bits:         append([]byte{}, ip...),
		peer:         nil,
		cidr:         cidr,
		bit_at_byte:  cidr / 8,
		bit_at_shift: 7 - (cidr % 8),
	}
	parent.maskSelf()

	bit := parent.choose(ip)
	parent.child[bit] = newNode
	parent.child[bit^1] = node

	return parent
}

func (node *trieEntry) lookup(ip net.IP) *Peer {
	var found *Peer
	size := uint(len(ip))
	for node != nil && commonBits(node.bits, ip) >= node.cidr {
		if node.peer != nil {
			found = node.peer
		}
		if node.bit_at_byte == size {
			break
		}
		bit := node.choose(ip)
		node = node.child[bit]
	}
	return found
}

type AllowedIPs struct {
	IPv4  *trieEntry
	IPv6  *trieEntry
	mutex sync.RWMutex
}

func (table *AllowedIPs) EntriesForPeer(peer *Peer, cb func(ip net.IP, cidr uint) bool) {
	table.mutex.RLock()
	defer table.mutex.RUnlock()

	for elem := peer.trieEntries.Front(); elem != nil; elem = elem.Next() {
		node := elem.Value.(*trieEntry)
		if !cb(node.bits, node.cidr) {
			return
		}
	}
}

func (table *AllowedIPs) RemoveByPeer(peer *Peer) {
	table.mutex.Lock()
	defer table.mutex.Unlock()

	table.IPv4 = table.IPv4.removeByPeer(peer)
	table.IPv6 = table.IPv6.removeByPeer(peer)
}

func (table *AllowedIPs) Insert(ip net.IP, cidr uint, peer *Peer) {
	table.mutex.Lock()
	defer table.mutex.Unlock()

	switch len(ip) {
	case net.IPv6len:
		table.IPv6 = table.IPv6.insert(ip, cidr, peer)
	case net.IPv4len:
		table.IPv4 = table.IPv4.insert(ip, cidr, peer)
	default:
		panic(errors.New("inserting unknown address type"))
	}
}

func (table *AllowedIPs) LookupIPv4(address []byte) *Peer {
	table.mutex.RLock()
	defer table.mutex.RUnlock()
	return table.IPv4.lookup(address)
}

func (table *AllowedIPs) LookupIPv6(address []byte) *Peer {
	table.mutex.RLock()
	defer table.mutex.RUnlock()
	return table.IPv6.lookup(address)
}
