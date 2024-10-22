// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipalloc

import (
	"container/heap"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"slices"
	"strings"

	"github.com/cilium/cilium/pkg/lock"
)

// Allocator allocates IP addresses, `T` is the type of value associated with the IP.
// The associated value can be used to store metadata about the IP, such as owner, purpose, etc.
type Allocator[T any] interface {
	// AllocAny allocates an available IP and associates value `val` to it. The caller has no control over the
	// exact IP that is allocated. The chosen IP is returned or error is non-nil.
	AllocAny(val T) (netip.Addr, error)

	// Alloc attempts to allocated the specific `ip` and associate value `val`. Allocation succeeded if the returned
	// error is nil.
	Alloc(ip netip.Addr, val T) error

	// Update updates the value `val` associated with the allocated `ip`.
	Update(ip netip.Addr, val T) error

	// Free de-allocates the given `ip` so its available once again.
	Free(ip netip.Addr) error

	// Get returns the value for the given `ip` if it has been allocated. Otherwise the default value for `T` is
	// returned. The boolean indicates if the `ip` has found.
	Get(ip netip.Addr) (T, bool)

	// ForEach calls `fn` for each allocated IP. The order of iteration is not guaranteed.
	// If `fn` return a non-nil error, the iteration is stopped and the error is returned.
	ForEach(fn func(addr netip.Addr, val T) error) error

	// Stats returns the number of IPs that have been allocated and the amount of IPs that are still
	// available for allocation.
	Stats() (allocated uint64, available *big.Int)

	// Range returns the start and stop IP of the allocator.
	Range() (from, to netip.Addr)
}

// HashAllocator is an IP allocator. This allocator stores ip-value pairs in a hash map, so memory usage
// grows proportionally to the amount of IPs allocated. The value type `T` is generic, larger types incur
// more memory usage. No artificial limits are placed on the range of the allocator other than inherent
// resource limits.
//
// The allocator uses a custom datatype to keep track of available IP blocks. Its both a min heap and
// a linked list. Blocks are linked in IP space order to optimize for block-merge detection. The block heap
// order in the slice is from smallest to largest. Allocating arbitrary IPs will take from the smallest blocks
// to decrease the block amount over the long term to reduce memory usage and allocation time.
//
// Due to this implementation, the AllocAny, Get, and Update methods are all O(1), these are expected to be the most
// commonly called methods. The Alloc and Free methods are O(n) where n is the amount of available blocks of IPs.
// So fragmented IP range utilization incurs more memory and cpu usage. These two are expected to be called way less
// since allocating specific IPs is assumed to be underutilized in k8s and freeing IPs will also be rare.
type HashAllocator[T any] struct {
	mu lock.Mutex

	start netip.Addr
	stop  netip.Addr

	allocations     map[netip.Addr]T
	availableBlocks availableBlockList
}

var _ Allocator[bool] = (*HashAllocator[bool])(nil)

// NewHashAllocator creates a new IP allocator which will allocate IPs between `start` and `stop`
// including `start` and `stop`.
// The `start` IP should be lower then or equal to `stop`. The `caphint` is passed to the backing
// hashmap to save on map resizing when initial IP count is broadly known.
func NewHashAllocator[T any](start, stop netip.Addr, caphint int) (*HashAllocator[T], error) {
	if !start.IsValid() {
		return nil, fmt.Errorf("can't use uninitialized addresses")
	}

	if start.BitLen() != stop.BitLen() {
		return nil, fmt.Errorf("'start' must be the same address family as 'stop'")
	}

	if start.Compare(stop) > 0 {
		return nil, fmt.Errorf("'start' must be less then or equal to 'stop'")
	}

	block := block{from: start, to: stop}
	block.calcSize()

	alloc := &HashAllocator[T]{
		start: start,
		stop:  stop,

		allocations:     make(map[netip.Addr]T, caphint),
		availableBlocks: availableBlockList{{block: block}},
	}

	return alloc, nil
}

var (
	ErrFull       = errors.New("cannot allocate IP, no more IPs available")
	ErrOutOfRange = errors.New("the requested IP is out of the allocators range")
	ErrInUse      = errors.New("the requested IP is already allocated")
	ErrNotFound   = errors.New("the requested IP cannot be found")
	ErrBadLoop    = errors.New("allocator detected a potentially infinite loop and broke free")
)

// AllocAny allocates an available IP and associates value `val` to it. The caller has no control over the
// exact IP that is allocated. The chosen IP is returned or error is non-nil.
func (a *HashAllocator[T]) AllocAny(val T) (netip.Addr, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.availableBlocks) == 0 {
		return netip.Addr{}, ErrFull
	}

	// Take the from IP from the first available block, blocks are min heap sorted from smallest to largest
	// so this tends to decrease the amount of blocks needed. Picking the first address from the
	// block will shrink it and not split it, thus being the fastest path.

	ip := a.availableBlocks[0].from
	err := a.availableBlocks.take(ip)
	if err != nil {
		return netip.Addr{}, err
	}

	a.allocations[ip] = val
	return ip, nil
}

// Alloc attempts to allocated the specific `ip` and associate value `val`. Allocation succeeded if the returned
// error is nil.
func (a *HashAllocator[T]) Alloc(ip netip.Addr, val T) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if ip.Compare(a.start) < 0 || ip.Compare(a.stop) > 0 {
		return ErrOutOfRange
	}

	if _, ok := a.allocations[ip]; ok {
		return ErrInUse
	}

	if len(a.availableBlocks) == 0 {
		return ErrFull
	}

	err := a.availableBlocks.take(ip)
	if err != nil {
		return err
	}

	a.allocations[ip] = val
	return nil
}

// Update updates the value `val` associated with the allocated `ip`.
func (a *HashAllocator[T]) Update(ip netip.Addr, val T) error {
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
func (a *HashAllocator[T]) Free(ip netip.Addr) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, ok := a.allocations[ip]; !ok {
		return ErrNotFound
	}

	err := a.availableBlocks.put(ip)
	if err != nil {
		return err
	}

	delete(a.allocations, ip)

	return nil
}

// Get returns the value for the given `ip` if it has been allocated. Otherwise the default value for `T` is
// returned. The boolean indicates if the `ip` has found.
func (a *HashAllocator[T]) Get(ip netip.Addr) (T, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	val, ok := a.allocations[ip]
	return val, ok
}

// Stats returns the number of IPs that have been allocated and the amount of IPs that are still
// available for allocation.
func (a *HashAllocator[T]) Stats() (allocated uint64, available *big.Int) {
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
func (a *HashAllocator[T]) Range() (from, to netip.Addr) {
	return a.start, a.stop
}

func (a *HashAllocator[T]) ForEach(fn func(addr netip.Addr, val T) error) error {
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

// A slice of blocks, min heap sorted by size from smallest to largest. But every element is also part of
// a linked list ordered according to adjacency in the IP space.
// When allocating, we always want to allocate from the smallest range so we reduce the amount
// of blocks to keep track of. And the links are used for merging blocks.
type availableBlockList []*linkedBlock

func (abl availableBlockList) String() string {
	var lines []string
	lines = append(lines, "linked-block-list[")
	for _, block := range abl {
		lines = append(lines, block.String())
	}
	lines = append(lines, "]")
	return strings.Join(lines, "\n")
}

// take removes `ip` from the list of available IPs by shrinking one of the blocks or by splitting a block
// in two if the `ip` appears in the middle of a range.
func (abl *availableBlockList) take(ip netip.Addr) error {
	var (
		availableBlock *linkedBlock
		index          int
	)

	// NOTE this search can be improved by traversing the linked list O(n) search
	for i, block := range *abl {
		if block.within(ip) {
			availableBlock = block
			index = i
			break
		}
	}
	if availableBlock == nil {
		return ErrInUse
	}

	// If its the first IP, we can shrink the block
	if availableBlock.from == ip {
		// If this is the last IP in the block, remove the block
		if availableBlock.from == availableBlock.to {
			abl.delete(index)
			return nil
		}

		availableBlock.from = availableBlock.from.Next()
		availableBlock.calcSize()
		heap.Fix(abl, index)
		return nil
	}

	// If its the last IP, we can shrink the block
	if availableBlock.to == ip {
		// If this is the last IP in the block, remove the block
		if availableBlock.from == availableBlock.to {
			abl.delete(index)
			return nil
		}

		availableBlock.to = availableBlock.to.Prev()
		availableBlock.calcSize()
		heap.Fix(abl, index)
		return nil
	}

	// At this point, it must be an IP in the middle of the block, so we need to split it

	// Remove the current block from the list
	heap.Remove(abl, index)

	leftBlock := linkedBlock{
		block: block{
			from: availableBlock.from,
			to:   ip.Prev(),
		},
	}
	leftBlock.calcSize()

	rightBlock := linkedBlock{
		block: block{
			from: ip.Next(),
			to:   availableBlock.to,
		},
	}
	rightBlock.calcSize()

	// Hooking up the doubly linked list pointers

	if availableBlock.prev != nil {
		availableBlock.prev.next = &leftBlock
		leftBlock.prev = availableBlock.prev
	}

	leftBlock.next = &rightBlock
	rightBlock.prev = &leftBlock

	if availableBlock.next != nil {
		rightBlock.next = availableBlock.next
		availableBlock.next.prev = &rightBlock
	}

	// Add new blocks to the list
	heap.Push(abl, &leftBlock)
	heap.Push(abl, &rightBlock)

	return nil
}

// put returns `ip` to the list of available IPs by growing a block or adding a new block.
func (abl *availableBlockList) put(ip netip.Addr) error {
	// If no blocks exist, create a new block
	if len(*abl) == 0 {
		heap.Push(abl, &linkedBlock{
			block: block{
				from: ip,
				to:   ip,
				size: uint128{lo: 1},
			},
		})
		return nil
	}

	// instead of a for {} loop, pick a unreasonably high iteration count and return an error
	// when reaching it to prevent infinite loops in case of bugs
	const maxIter = 1_000_000

	curr := (*abl)[0]
	var prev *linkedBlock
	for i := 0; i < maxIter; i++ {
		if ip.Compare(curr.from) < 0 {
			// Is `ip` on the left current block

			// if from is off by one, we can just grow this block to the left
			if curr.from.Prev() == ip {
				curr.from = curr.from.Prev()
				curr.calcSize()

				// if the growth makes this block contiguous with the block on the left, merge the two
				if curr.prev != nil && curr.prev.to == curr.from.Prev() {
					abl.merge(curr.prev, curr)
				}

				return nil
			}

			// The IP is not adjacent, check again on the block to the left, if there is one
			if curr.prev != nil {
				// If we are sent back to the block we just came from, `ip` is between these two, create a new block
				if curr.prev == prev {
					abl.insert(curr.prev, curr, ip)

					return nil
				}

				// move to the left for one iteration.
				prev = curr
				curr = curr.prev
				continue
			}

			// if there are no blocks on the left, and we are not adjacent, create a new block.

			abl.insert(nil, curr, ip)

			return nil
		}

		// Is `ip` on the right current block

		// if to is off by one, we can just grow this block to the right
		if curr.to.Next() == ip {
			curr.to = curr.to.Next()
			curr.calcSize()
			heap.Fix(abl, i)

			// if the growth makes this block contiguous with the block on the right, merge the two
			if curr.next != nil && curr.next.from == curr.to.Next() {
				abl.merge(curr, curr.next)
			}

			return nil
		}

		// The IP is not adjacent, check again on the block to the right, if there is one
		if curr.next != nil {
			// If we are sent back to the block we just came from, `ip` is between these two, create a new block
			if curr.next == prev {
				abl.insert(curr, curr.next, ip)

				return nil
			}

			// move to the right for one iteration
			prev = curr
			curr = curr.next
			continue
		}

		// if there are no blocks on the right, and we are not adjacent, create a new block.

		abl.insert(curr, nil, ip)

		return nil
	}

	return ErrBadLoop
}

// Len implements heap.Interface
func (abl availableBlockList) Len() int {
	return len(abl)
}

// Len implements heap.Interface
func (abl availableBlockList) Swap(i, j int) {
	abl[j], abl[i] = abl[i], abl[j]
}

// Len implements heap.Interface
func (abl availableBlockList) Less(i, j int) bool {
	return abl[i].less(&abl[j].block)
}

// Push implements heap.Interface
func (abl *availableBlockList) Push(x interface{}) {
	*abl = append(*abl, x.(*linkedBlock))
}

// Pop implements heap.Interface
func (abl *availableBlockList) Pop() interface{} {
	n := len(*abl) - 1
	elem := (*abl)[n]
	*abl = slices.Delete(*abl, n, n+1)
	return elem
}

// delete a block and patch the link pointers
func (abl *availableBlockList) delete(idx int) {
	elem := heap.Remove(abl, idx).(*linkedBlock)
	if elem.prev != nil {
		elem.prev.next = elem.next
	}
	if elem.next != nil {
		elem.next.prev = elem.prev
	}
}

// merge two blocks and patch the link pointers
func (abl *availableBlockList) merge(left, right *linkedBlock) {
	leftOfLeft := left.prev
	rightOfRight := right.next

	merged := linkedBlock{
		block: block{
			from: left.from,
			to:   right.to,
		},
		prev: leftOfLeft,
		next: rightOfRight,
	}
	merged.calcSize()

	if leftOfLeft != nil {
		leftOfLeft.next = &merged
	}
	if rightOfRight != nil {
		rightOfRight.prev = &merged
	}

	leftIdx := slices.Index(*abl, left)
	heap.Remove(abl, leftIdx)

	rightIdx := slices.Index(*abl, right)
	heap.Remove(abl, rightIdx)

	heap.Push(abl, &merged)
}

// insert a new block for a given `newIP` between `left` and `right` and patch the link pointers
func (abl *availableBlockList) insert(left, right *linkedBlock, newIP netip.Addr) {
	block := &linkedBlock{
		block: block{
			from: newIP,
			to:   newIP,
			size: uint128{lo: 1},
		},
		prev: left,
		next: right,
	}
	if left != nil {
		left.next = block
	}
	if right != nil {
		right.prev = block
	}

	heap.Push(abl, block)
}

type block struct {
	from netip.Addr
	to   netip.Addr
	size uint128
}

func (b *block) within(ip netip.Addr) bool {
	return ip.Compare(b.from) >= 0 && ip.Compare(b.to) <= 0
}

func (b *block) less(other *block) bool {
	return b.getSize().less(other.getSize())
}

func (b *block) bigIntSize() *big.Int {
	from := big.NewInt(0)
	from = from.SetBytes(b.from.AsSlice())

	to := big.NewInt(0)
	to = to.SetBytes(b.to.AsSlice())

	return to.Sub(to, from).Add(to, big.NewInt(1))
}

func (b *block) calcSize() {
	b.size = addrDiff(b.from, b.to)
}

func (b *block) getSize() uint128 {
	// Size is stored and not calculated since its more performant during sorting where the size
	// of the same block is frequently requested.
	return b.size
}

type linkedBlock struct {
	block

	prev *linkedBlock
	next *linkedBlock
}

func (lb linkedBlock) String() string {
	var sb strings.Builder
	if lb.prev != nil {
		fmt.Fprintf(&sb, "(%s - %s) <- ", lb.prev.from, lb.prev.to)
	}
	fmt.Fprintf(&sb, "(%s - %s)[%s]", lb.from, lb.to, lb.bigIntSize().String())
	if lb.next != nil {
		fmt.Fprintf(&sb, " -> (%s - %s)", lb.next.from, lb.next.to)
	}
	return sb.String()
}

// uint128 is inspired by the unexported variant in netip. Used in our case not to represent the IPs
// themselves but the size of blocks for sorting purposes.
type uint128 struct {
	hi uint64
	lo uint64
}

func addrDiff(from, to netip.Addr) uint128 {
	fromInt := uint128FromAddr(from)
	toInt := uint128FromAddr(to)
	return toInt.sub(fromInt)
}

func (u uint128) less(other uint128) bool {
	if u.hi == other.hi {
		return u.lo < other.lo
	}

	return u.hi < other.hi
}

func (u uint128) sub(other uint128) uint128 {
	return uint128{
		hi: u.hi - other.hi,
		lo: u.lo - other.lo,
	}
}

// uint128FromAddr extracts the uint128 value using a reflection hack.
func uint128FromAddr(addr netip.Addr) uint128 {
	bytes := addr.As16()
	return uint128{
		hi: binary.BigEndian.Uint64(bytes[:8]),
		lo: binary.BigEndian.Uint64(bytes[8:]),
	}
}
