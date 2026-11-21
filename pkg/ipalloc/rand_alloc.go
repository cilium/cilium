// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipalloc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"maps"
	"math/big"
	"math/bits"
	mrand "math/rand/v2"
	"net/netip"

	"golang.org/x/crypto/hkdf"

	"github.com/cilium/cilium/pkg/lock"
)

// RandomAllocator is a pseudo-random IP allocator. This allocator stores ip-value pairs in a hash map, so memory usage
// grows proportionally to the amount of IPs allocated. The value type `T` is generic, larger types incur
// more memory usage. No artificial limits are placed on the range of the allocator other than inherent
// resource limits.
//
// Every IP is mapped to an index from [0, n) which is a bijection (a Feistel permutation with cycle walking,
// since a Feistel network always permutes 2^k values and we need [0, n)).
//
// Free indexes are kept as blocks (ranges) of indexes in a binary search tree (a treap) ordered by the start of the
// block. Every block is also linked to its left and right neighbour in index order, so adjacent blocks can be merged
// without searching. AllocAny always takes the lowest free index (the head of the list), which is O(1) apart from
// the Feistel rounds. Alloc and Free are O(log b) where b is the number of free blocks.
type RandomAllocator[T any] struct {
	mu lock.Mutex

	start netip.Addr
	stop  netip.Addr

	peakAllocations int
	randomizer      feistelRandomizer
	allocations     map[netip.Addr]T
	freeIndexes     *freeIndexTree
}

var _ Allocator[bool] = (*RandomAllocator[bool])(nil)

// NewRandomAllocator creates a new IP allocator which will allocate IPs between `start` and `stop`
// including `start` and `stop`.
// The `start` IP should be lower then or equal to `stop`. The `caphint` is passed to the backing
// hashmap to save on map resizing when initial IP count is broadly known.
func NewRandomAllocator[T any](start, stop netip.Addr, caphint int) (*RandomAllocator[T], error) {
	if !start.IsValid() {
		return nil, fmt.Errorf("can't use uninitialized addresses")
	}

	if start.BitLen() != stop.BitLen() {
		return nil, fmt.Errorf("'start' must be the same address family as 'stop'")
	}

	if start.Compare(stop) > 0 {
		return nil, fmt.Errorf("'start' must be less then or equal to 'stop'")
	}

	// number of IPs in the range, indexes are [0, maxAllocSize)
	maxAllocSize := addrDiff(start, stop).add(uint128{lo: 1})

	// seed for Feistel Cycle
	seed, err := newRandomSeed()
	if err != nil {
		return nil, fmt.Errorf("failed to create a random seed: %w", err)
	}

	alloc := &RandomAllocator[T]{
		start:       start,
		stop:        stop,
		randomizer:  newFeistelRandomizer(seed, maxAllocSize),
		allocations: make(map[netip.Addr]T, caphint),
		// initially the whole index range is one free block
		freeIndexes: newFreeIndexTree(uint128{}, maxAllocSize.sub(uint128{lo: 1})),
	}

	return alloc, nil
}

// AllocAny allocates an available IP and associates value `val` to it. The caller has no control over the
// exact IP that is allocated, which is decided from the Feistel permutation of the lowest free index.
// The chosen IP is returned, or the error is non-nil (ErrFull if every IP in the range is in use).
func (a *RandomAllocator[T]) AllocAny(val T) (netip.Addr, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.freeIndexes.head == nil {
		return netip.Addr{}, ErrFull
	}

	// Taking the first index of the first block only shrinks that block, it never splits it.
	index := a.freeIndexes.head.from
	ip := a.randomizer.toIP(index, a.start)
	if err := a.freeIndexes.take(index); err != nil {
		return netip.Addr{}, err
	}

	a.allocations[ip] = val
	if a.peakAllocations < len(a.allocations) {
		a.peakAllocations = len(a.allocations)
	}
	return ip, nil
}

// Alloc attempts to allocated the specific `ip` and associate value `val`. Allocation succeeded if the returned
// error is nil.
func (a *RandomAllocator[T]) Alloc(ip netip.Addr, val T) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if ip.Compare(a.start) < 0 || ip.Compare(a.stop) > 0 {
		return ErrOutOfRange
	}

	if _, ok := a.allocations[ip]; ok {
		return ErrInUse
	}

	if a.freeIndexes.head == nil {
		return ErrFull
	}

	index := a.randomizer.toIndex(ip, a.start)
	if err := a.freeIndexes.take(index); err != nil {
		return err
	}

	a.allocations[ip] = val
	if a.peakAllocations < len(a.allocations) {
		a.peakAllocations = len(a.allocations)
	}
	return nil
}

// Update updates the value `val` associated with the allocated `ip`.
func (a *RandomAllocator[T]) Update(ip netip.Addr, val T) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	_, ok := a.allocations[ip]
	if ok {
		a.allocations[ip] = val
		return nil
	}

	return ErrNotFound
}

// Free de-allocates the given `ip` so its available once again.
func (a *RandomAllocator[T]) Free(ip netip.Addr) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, ok := a.allocations[ip]; !ok {
		return ErrNotFound
	}

	index := a.randomizer.toIndex(ip, a.start)
	if err := a.freeIndexes.put(index); err != nil {
		return err
	}

	delete(a.allocations, ip)

	// If the current number of allocations is less then 1/3 of the peak, we can shrink the map
	// to save memory.
	if (len(a.allocations) * 3) < a.peakAllocations {
		// Make a new map with half the size of the peak, this should leave some room for growth
		// without needing to resize the map again, yet not waste too much memory.
		newAllocations := make(map[netip.Addr]T, a.peakAllocations/2)
		maps.Copy(newAllocations, a.allocations)
		a.allocations = newAllocations
		a.peakAllocations = len(a.allocations)
	}

	return nil
}

// Get returns the value for the given `ip` if it has been allocated. Otherwise the default value for `T` is
// returned. The boolean indicates if the `ip` has found.
func (a *RandomAllocator[T]) Get(ip netip.Addr) (T, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	val, ok := a.allocations[ip]
	return val, ok
}

// Stats returns the number of IPs that have been allocated and the amount of IPs that are still
// available for allocation.
func (a *RandomAllocator[T]) Stats() (allocated uint64, available *big.Int) {
	allocated = uint64(len(a.allocations))

	available = big.NewInt(0)
	available.SetBytes(a.stop.AsSlice())

	start := big.NewInt(0)
	start.SetBytes(a.start.AsSlice())

	// The range .10 to .20 has 11 IPs, so calc is #available = (end-start+1) - #allocated
	available = available.Sub(available, start)
	available = available.Add(available, big.NewInt(1))
	available = available.Sub(available, big.NewInt(int64(allocated)))

	return allocated, available
}

// Range returns the start and stop IP of the allocator.
func (a *RandomAllocator[T]) Range() (from, to netip.Addr) {
	return a.start, a.stop
}

// Call function fn for every allocated IP
func (a *RandomAllocator[T]) ForEach(fn func(addr netip.Addr, val T) error) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	for addr, val := range a.allocations {
		err := fn(addr, val)
		if err != nil {
			return err
		}
	}

	return nil
}

// indexBlock is a range [from, to] of free indexes. It is a node in a treap ordered by `from` (left, right),
// and also a node of a doubly linked list in index order (prev, next).
type indexBlock struct {
	from uint128
	to   uint128

	// treap heap-priority, random so the tree stays balanced in expectation
	prio        uint32
	left, right *indexBlock

	// neighbours in index order
	prev, next *indexBlock
}

func newIndexBlock(from, to uint128) *indexBlock {
	return &indexBlock{from: from, to: to, prio: mrand.Uint32()}
}

// freeIndexTree keeps disjoint, non-adjacent blocks of free indexes. `head` is the block with the lowest indexes.
type freeIndexTree struct {
	root *indexBlock
	head *indexBlock
}

func newFreeIndexTree(from, to uint128) *freeIndexTree {
	b := newIndexBlock(from, to)
	return &freeIndexTree{root: b, head: b}
}

// find returns the block containing `index` or nil.
func (t *freeIndexTree) find(index uint128) *indexBlock {
	n := t.root
	for n != nil {
		switch {
		case index.less(n.from):
			n = n.left
		case index.more(n.to):
			n = n.right
		default:
			return n
		}
	}
	return nil
}

// take removes `index` from the free indexes by shrinking a block, or splitting it in two if `index` is in the
// middle of the block. ErrInUse is returned if the index is not free.
func (t *freeIndexTree) take(index uint128) error {
	b := t.find(index)
	if b == nil {
		return ErrInUse
	}

	one := uint128{lo: 1}
	switch {
	case b.from == b.to:
		t.remove(b)
	case b.from == index:
		// key changes but stays ordered, blocks are disjoint
		b.from = b.from.add(one)
	case b.to == index:
		b.to = b.to.sub(one)
	default:
		right := newIndexBlock(index.add(one), b.to)
		b.to = index.sub(one)
		t.insertAfter(b, right)
	}
	return nil
}

// put returns `index` to the free indexes by growing a block, merging two blocks or adding a new block.
func (t *freeIndexTree) put(index uint128) error {
	// find the free blocks directly before and after index
	var pred, succ *indexBlock
	n := t.root
	for n != nil {
		switch {
		case index.less(n.from):
			succ = n
			n = n.left
		case index.more(n.to):
			pred = n
			n = n.right
		default:
			return fmt.Errorf("index is already free")
		}
	}

	one := uint128{lo: 1}
	adjPred := pred != nil && pred.to.add(one) == index
	adjSucc := succ != nil && index.add(one) == succ.from

	switch {
	case adjPred && adjSucc:
		pred.to = succ.to
		t.remove(succ)
	case adjPred:
		pred.to = index
	case adjSucc:
		succ.from = index
	default:
		b := newIndexBlock(index, index)
		if pred != nil {
			t.insertAfter(pred, b)
		} else {
			b.next = t.head
			if t.head != nil {
				t.head.prev = b
			}
			t.head = b
			t.root = insertNode(t.root, b)
		}
	}
	return nil
}

// insertAfter links `b` after `after` in the list and adds it to the tree.
func (t *freeIndexTree) insertAfter(after, b *indexBlock) {
	b.prev = after
	b.next = after.next
	if after.next != nil {
		after.next.prev = b
	}
	after.next = b
	t.root = insertNode(t.root, b)
}

// remove deletes `b` from the tree and the list. Must be called before `b.from` is changed.
func (t *freeIndexTree) remove(b *indexBlock) {
	t.root = eraseNode(t.root, b.from)

	if b.prev != nil {
		b.prev.next = b.next
	} else {
		t.head = b.next
	}
	if b.next != nil {
		b.next.prev = b.prev
	}
	b.prev, b.next, b.left, b.right = nil, nil, nil, nil
}

func cmp128(a, b uint128) int {
	switch {
	case a.less(b):
		return -1
	case a.more(b):
		return 1
	}
	return 0
}

// splitNode splits the treap into blocks with from < key and blocks with from >= key.
func splitNode(n *indexBlock, key uint128) (l, r *indexBlock) {
	if n == nil {
		return nil, nil
	}
	if n.from.less(key) {
		a, b := splitNode(n.right, key)
		n.right = a
		return n, b
	}
	a, b := splitNode(n.left, key)
	n.left = b
	return a, n
}

// mergeNodes joins two treaps where every key in a is smaller than every key in b.
func mergeNodes(a, b *indexBlock) *indexBlock {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	if a.prio > b.prio {
		a.right = mergeNodes(a.right, b)
		return a
	}
	b.left = mergeNodes(a, b.left)
	return b
}

func insertNode(root, n *indexBlock) *indexBlock {
	if root == nil {
		return n
	}
	if n.prio > root.prio {
		n.left, n.right = splitNode(root, n.from)
		return n
	}
	if n.from.less(root.from) {
		root.left = insertNode(root.left, n)
	} else {
		root.right = insertNode(root.right, n)
	}
	return root
}

func eraseNode(root *indexBlock, key uint128) *indexBlock {
	if root == nil {
		return nil
	}
	switch cmp128(key, root.from) {
	case -1:
		root.left = eraseNode(root.left, key)
	case 1:
		root.right = eraseNode(root.right, key)
	default:
		return mergeNodes(root.left, root.right)
	}
	return root
}

type feistelRandomizer struct {
	// total number of bits to permute, calculated from size of cycle
	totalBitCount uint
	// divide total bits to permute, maximum difference between low and high is 1
	highBitCount uint
	lowBitCount  uint

	// feistal cycle is valid on range, [0, size)
	size uint128

	seed uint128
	// round keys are derived from the seed for every round, 4 rounds in this case
	roundKeys [4]uint64
}

// Generate a new Feistel randomizer from seed which is valid on indexes from [0, size)
func newFeistelRandomizer(seed uint128, size uint128) feistelRandomizer {
	randomizer := feistelRandomizer{seed: seed, size: size}

	maxIdx := size.sub(uint128{lo: 1})
	if maxIdx.hi != 0 {
		randomizer.totalBitCount = 64 + uint(bits.Len64(maxIdx.hi))
	} else {
		randomizer.totalBitCount = uint(bits.Len64(maxIdx.lo))
	}

	// divide bits into two parts
	randomizer.highBitCount = randomizer.totalBitCount / 2
	randomizer.lowBitCount = randomizer.totalBitCount - randomizer.highBitCount

	// generate secret for Feistel
	secret := make([]byte, 16)

	binary.BigEndian.PutUint64(secret[0:8], seed.lo)
	binary.BigEndian.PutUint64(secret[8:16], seed.hi)

	// Generate per round key with hkdf
	r := hkdf.New(sha256.New, secret, nil, nil)

	// 4 rounds with 64 bit keys each
	var buf [4 * 8]byte

	io.ReadFull(r, buf[:])

	for i := range randomizer.roundKeys {
		randomizer.roundKeys[i] = binary.BigEndian.Uint64(buf[i*8:])
	}

	return randomizer
}

// toIP maps index to its address. Requires index < size.
func (fr *feistelRandomizer) toIP(index uint128, baseIP netip.Addr) netip.Addr {
	// Feistel and cycle-walking
	// re-encrypt until the value lands back in [0, size).
	res := fr.encryptBlock(index)

	maxIdx := fr.size.sub(uint128{lo: 1})
	for res.more(maxIdx) {
		res = fr.encryptBlock(res)
	}
	addr := uint128FromAddr(baseIP).add(res)
	return uint128ToAddr(addr)
}

// toIndex is the inverse of toIP. Requires ip to be inside the range.
func (fr *feistelRandomizer) toIndex(ip, baseIP netip.Addr) uint128 {
	v := uint128FromAddr(ip).sub(uint128FromAddr(baseIP))
	v = fr.decryptBlock(v)

	maxIdx := fr.size.sub(uint128{lo: 1})
	for v.more(maxIdx) {
		v = fr.decryptBlock(v)
	}
	return v
}

func lowMask(width uint) uint64 { return uint64(1)<<width - 1 }

// split cuts v into left = v >> lowBitCount and right = low lowBitCount bits.
func (fr *feistelRandomizer) split(v uint128) (left, right uint64) {
	rb := fr.lowBitCount
	right = v.lo & lowMask(rb)
	left = v.hi<<(64-rb) | v.lo>>rb
	return
}

// join puts the number split by `split` back together
func (fr *feistelRandomizer) join(left, right uint64) uint128 {
	rb := fr.lowBitCount
	return uint128{hi: left >> (64 - rb), lo: left<<rb | right}
}

// Encrypts the value given as per Feistal Algo
func (fr *feistelRandomizer) encryptBlock(v uint128) uint128 {
	leftBits, rightBits := fr.highBitCount, fr.lowBitCount
	left, right := fr.split(v)

	for _, key := range fr.roundKeys {
		out := mix64(right+key) & lowMask(leftBits)
		left, right = right, left^out

		// reverse it for next round
		leftBits, rightBits = rightBits, leftBits
	}
	return fr.join(left, right)
}

// Decrypts a value encrypted by encryptBlock, running the rounds in reverse
func (fr *feistelRandomizer) decryptBlock(v uint128) uint128 {
	leftBits, rightBits := fr.highBitCount, fr.lowBitCount
	left, right := fr.split(v)

	for i := len(fr.roundKeys) - 1; i >= 0; i-- {
		out := mix64(left+fr.roundKeys[i]) & lowMask(rightBits)
		left, right = right^out, left

		leftBits, rightBits = rightBits, leftBits
	}
	return fr.join(left, right)
}

// Generate a 128 bit random seed
func newRandomSeed() (uint128, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return uint128{}, err
	}

	return uint128{
		lo: binary.BigEndian.Uint64(buf[0:8]),
		hi: binary.BigEndian.Uint64(buf[8:16]),
	}, nil
}

// splitmix64 finalizer, hashing function for Feistel
func mix64(z uint64) uint64 {
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}
