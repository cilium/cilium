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
	"net/netip"

	"github.com/cilium/cilium/pkg/lock"
	"golang.org/x/crypto/hkdf"
)

// RandomAllocator is a pseudo-random IP allocator. This allocator stores ip-value pairs in a hash map, so memory usage
// grows proportionally to the amount of IPs allocated. The value type `T` is generic, larger types incur
// more memory usage. No artificial limits are placed on the range of the allocator other than inherent
// resource limits.
//
// Every IP is mapped to a index from [0, n) which is a bijection.
// Feistal always computes permutaions for 2^n values hence, for every value outside out range [0, m) we do cycle walking to reach in range permutation
// Due to this implementation, the AllocAny is O(n) and Get, Update, Free, Alloc methods are all O(1), these are expected to be the most
// commonly called methods.
type RandomAllocator[T any] struct {
	mu lock.Mutex

	start netip.Addr
	stop  netip.Addr

	// Current number of allocations
	allocSize    uint128
	maxAllocSize uint128
	index        uint128

	peakAllocations int
	randomizer      feistelRandomizer
	allocations     map[netip.Addr]T
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

	maxAllocSize := addrDiff(start, stop).add(uint128{lo: 1})

	// seed for Feistel Cycle
	seed, err := newRandomSeed()
	if err != nil {
		return nil, fmt.Errorf("Failed to create a random seed")
	}

	alloc := &RandomAllocator[T]{
		start:        start,
		stop:         stop,
		randomizer:   newFeistelRandomizer(seed, maxAllocSize),
		allocations:  make(map[netip.Addr]T, caphint),
		allocSize:    uint128{},
		maxAllocSize: maxAllocSize,
		index:        uint128{},
	}

	return alloc, nil
}

// AllocAny allocates an available IP and associates value `val` to it. The caller has no control over the
// exact IP that is allocated, which is decided from the Feistel cycle value corresponding to next free index.
// The chosen IP is returned or error is non-nil.
func (a *RandomAllocator[T]) AllocAny(val T) (netip.Addr, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.allocSize.less(a.maxAllocSize) {
		return netip.Addr{}, ErrFull
	}

	// Take the IP corresponding to the current index in possible range.

	ip := a.randomizer.toIP(a.index, a.start)

	for _, ok := a.allocations[ip]; ok; _, ok = a.allocations[ip] {
		a.index = a.index.add(uint128{lo: 1})
		ip = a.randomizer.toIP(a.index, a.start)
	}

	a.allocations[ip] = val
	if a.peakAllocations < len(a.allocations) {
		a.peakAllocations = len(a.allocations)
	}

	a.index = a.index.add(uint128{lo: 1})
	if a.index == a.maxAllocSize {
		a.index = uint128{lo: 0}
	}
	a.allocSize = a.allocSize.add(uint128{lo: 1})
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

	if !a.allocSize.less(a.maxAllocSize) {
		return ErrFull
	}

	a.allocations[ip] = val
	if a.peakAllocations < len(a.allocations) {
		a.peakAllocations = len(a.allocations)
	}

	a.allocSize = a.allocSize.add(uint128{lo: 1})
	a.index = a.index.add(uint128{lo: 1})
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

	a.allocSize = a.allocSize.sub(uint128{lo: 1})
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
		// if seed is more than 2^64
		randomizer.totalBitCount = 64 + uint(bits.Len64(maxIdx.hi))
	} else {
		// if seed is less than or equal to 2^64
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

	// keep conitinuing the cycle
	for res.more(fr.size.sub(uint128{lo: 1})) {
		res = fr.encryptBlock(res)
	}
	addr := uint128FromAddr(baseIP).add(res)
	return uint128ToAddr(addr)
}

func lowMask(width uint) uint64 { return uint64(1)<<width - 1 }

// split cuts v into left = v >> lowBitCount and right = low lowBitCount bits.
func (fr *feistelRandomizer) split(v uint128) (left, right uint64) {
	rb := fr.lowBitCount
	right = v.lo & lowMask(rb)
	left = v.hi<<(64-rb) | v.lo>>rb
	return
}

// joints the number split by `split` back
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
