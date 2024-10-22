// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipalloc

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBlockList_Take(t *testing.T) {
	list := availableBlockList{{block: block{
		from: netip.MustParseAddr("10.0.0.0"),
		to:   netip.MustParseAddr("10.0.0.255"),
	}}}

	err := list.take(netip.MustParseAddr("10.0.0.0"))
	sort.Sort(list)
	require.NoError(t, err)
	require.Equal(t, netip.MustParseAddr("10.0.0.1"), list[0].from)
	require.Len(t, list, 1)

	err = list.take(netip.MustParseAddr("10.0.0.1"))
	sort.Sort(list)
	require.NoError(t, err)
	require.Equal(t, netip.MustParseAddr("10.0.0.2"), list[0].from)
	require.Len(t, list, 1)

	err = list.take(netip.MustParseAddr("10.0.0.255"))
	sort.Sort(list)
	require.NoError(t, err)
	require.Equal(t, netip.MustParseAddr("10.0.0.254"), list[0].to)
	require.Len(t, list, 1)

	err = list.take(netip.MustParseAddr("10.0.0.11"))
	sort.Sort(list)
	require.NoError(t, err)
	require.Len(t, list, 2)
	//
	require.Equal(t, netip.MustParseAddr("10.0.0.2"), list[0].from)
	require.Equal(t, netip.MustParseAddr("10.0.0.10"), list[0].to)
	require.Nil(t, list[0].prev)
	require.Equal(t, list[1], list[0].next)
	//
	require.Equal(t, netip.MustParseAddr("10.0.0.12"), list[1].from)
	require.Equal(t, netip.MustParseAddr("10.0.0.254"), list[1].to)
	require.Equal(t, list[0], list[1].prev)
	require.Nil(t, list[1].next)

	err = list.take(netip.MustParseAddr("10.0.0.211"))
	sort.Sort(list)
	require.NoError(t, err)
	require.Len(t, list, 3)
	// Sorted according to block size
	require.Equal(t, netip.MustParseAddr("10.0.0.2"), list[0].from)
	require.Equal(t, netip.MustParseAddr("10.0.0.10"), list[0].to)
	require.Nil(t, list[0].prev)
	require.Equal(t, list[2], list[0].next)
	//
	require.Equal(t, netip.MustParseAddr("10.0.0.212"), list[1].from)
	require.Equal(t, netip.MustParseAddr("10.0.0.254"), list[1].to)
	require.Equal(t, list[2], list[1].prev)
	require.Nil(t, list[1].next)
	//
	require.Equal(t, netip.MustParseAddr("10.0.0.12"), list[2].from)
	require.Equal(t, netip.MustParseAddr("10.0.0.210"), list[2].to)
	require.Equal(t, list[0], list[2].prev)
	require.Equal(t, list[1], list[2].next)

	err = list.take(netip.MustParseAddr("10.0.0.100"))
	sort.Sort(list)
	require.NoError(t, err)
	require.Len(t, list, 4)
	// Sorted according to block size
	require.Equal(t, netip.MustParseAddr("10.0.0.2"), list[0].from)
	require.Equal(t, netip.MustParseAddr("10.0.0.10"), list[0].to)
	require.Nil(t, list[0].prev)
	require.Equal(t, list[2], list[0].next)
	//
	require.Equal(t, netip.MustParseAddr("10.0.0.212"), list[1].from)
	require.Equal(t, netip.MustParseAddr("10.0.0.254"), list[1].to)
	require.Equal(t, list[3], list[1].prev)
	require.Nil(t, list[1].next)
	//
	require.Equal(t, netip.MustParseAddr("10.0.0.12"), list[2].from)
	require.Equal(t, netip.MustParseAddr("10.0.0.99"), list[2].to)
	require.Equal(t, list[0], list[2].prev)
	require.Equal(t, list[3], list[2].next)
	//
	require.Equal(t, netip.MustParseAddr("10.0.0.101"), list[3].from)
	require.Equal(t, netip.MustParseAddr("10.0.0.210"), list[3].to)
	require.Equal(t, list[2], list[3].prev)
	require.Equal(t, list[1], list[3].next)
}

func TestBlockList_TakeLast(t *testing.T) {
	list := availableBlockList{
		{block: block{
			from: netip.MustParseAddr("10.0.0.0"),
			to:   netip.MustParseAddr("10.0.0.10"),
		}},
		{block: block{
			from: netip.MustParseAddr("10.0.0.20"),
			to:   netip.MustParseAddr("10.0.0.20"),
		}},
		{block: block{
			from: netip.MustParseAddr("10.0.0.30"),
			to:   netip.MustParseAddr("10.0.0.255"),
		}},
	}
	list[0].next = list[1]
	list[1].prev = list[0]
	list[1].next = list[2]
	list[2].prev = list[1]

	err := list.take(netip.MustParseAddr("10.0.0.20"))
	sort.Sort(list)
	require.NoError(t, err)
	require.Equal(t, netip.MustParseAddr("10.0.0.0"), list[0].from)
	require.Equal(t, netip.MustParseAddr("10.0.0.10"), list[0].to)
	require.Equal(t, netip.MustParseAddr("10.0.0.30"), list[1].from)
	require.Equal(t, netip.MustParseAddr("10.0.0.255"), list[1].to)
	require.Len(t, list, 2)
	require.Nil(t, list[0].prev)
	require.Equal(t, list[1], list[0].next)
	require.Equal(t, list[0], list[1].prev)
	require.Nil(t, list[1].next)
}

func TestBlockList_TakeInUse(t *testing.T) {
	list := availableBlockList{{block: block{
		from: netip.MustParseAddr("10.0.0.0"),
		to:   netip.MustParseAddr("10.0.0.255"),
	}}}

	err := list.take(netip.MustParseAddr("10.0.0.10"))
	require.NoError(t, err)

	err = list.take(netip.MustParseAddr("10.0.0.10"))
	require.ErrorIs(t, err, ErrInUse)
}

func TestBlockList_Put(t *testing.T) {
	list := availableBlockList{{block: block{
		from: netip.MustParseAddr("10.0.0.0"),
		to:   netip.MustParseAddr("10.0.0.255"),
	}}}

	err := list.take(netip.MustParseAddr("10.0.0.100"))
	sort.Sort(list)
	require.NoError(t, err)
	require.Len(t, list, 2)

	err = list.put(netip.MustParseAddr("10.0.0.100"))
	sort.Sort(list)
	require.NoError(t, err)
	require.Len(t, list, 1)

	err = list.take(netip.MustParseAddr("10.0.0.200"))
	sort.Sort(list)
	require.NoError(t, err)
	require.Len(t, list, 2)

	err = list.take(netip.MustParseAddr("10.0.0.201"))
	sort.Sort(list)
	require.NoError(t, err)
	require.Len(t, list, 2)

	err = list.take(netip.MustParseAddr("10.0.0.202"))
	sort.Sort(list)
	require.NoError(t, err)
	require.Len(t, list, 2)

	err = list.put(netip.MustParseAddr("10.0.0.201"))
	sort.Sort(list)
	require.NoError(t, err)
	require.Len(t, list, 3)

	err = list.put(netip.MustParseAddr("10.0.0.200"))
	sort.Sort(list)
	require.NoError(t, err)
	require.Len(t, list, 2)

	err = list.put(netip.MustParseAddr("10.0.0.202"))
	sort.Sort(list)
	require.NoError(t, err)
	require.Len(t, list, 1)
}

func TestBlockList_PutZero(t *testing.T) {
	list := availableBlockList{}

	err := list.put(netip.MustParseAddr("10.0.0.100"))
	require.NoError(t, err)
	require.Len(t, list, 1)
}

func TestBlockList_PutMoveRight(t *testing.T) {
	list := availableBlockList{{block: block{
		from: netip.MustParseAddr("10.0.0.0"),
		to:   netip.MustParseAddr("10.0.0.255"),
	}}}

	err := list.take(netip.MustParseAddr("10.0.0.50"))
	require.NoError(t, err)
	require.Len(t, list, 2)

	err = list.take(netip.MustParseAddr("10.0.0.51"))
	require.NoError(t, err)
	require.Len(t, list, 2)

	err = list.take(netip.MustParseAddr("10.0.0.52"))
	require.NoError(t, err)
	require.Len(t, list, 2)

	err = list.put(netip.MustParseAddr("10.0.0.51"))
	require.NoError(t, err)
	require.Len(t, list, 3)
}

func TestBlockList_PutOuterMost(t *testing.T) {
	list := availableBlockList{{block: block{
		from: netip.MustParseAddr("10.0.0.0"),
		to:   netip.MustParseAddr("10.0.0.255"),
	}}}

	err := list.take(netip.MustParseAddr("10.0.0.0"))
	require.NoError(t, err)
	require.Len(t, list, 1)

	err = list.take(netip.MustParseAddr("10.0.0.1"))
	require.NoError(t, err)
	require.Len(t, list, 1)

	err = list.put(netip.MustParseAddr("10.0.0.0"))
	require.NoError(t, err)
	require.Len(t, list, 2)

	err = list.take(netip.MustParseAddr("10.0.0.255"))
	require.NoError(t, err)
	require.Len(t, list, 2)

	err = list.take(netip.MustParseAddr("10.0.0.254"))
	require.NoError(t, err)
	require.Len(t, list, 2)

	err = list.put(netip.MustParseAddr("10.0.0.255"))
	require.NoError(t, err)
	require.Len(t, list, 3)
}

func TestBlockList_IPv6(t *testing.T) {
	list := availableBlockList{{block: block{
		from: netip.MustParseAddr("2001:db8::"),
		to:   netip.MustParseAddr("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"),
	}}}

	err := list.take(netip.MustParseAddr("2001:db8::1234"))
	require.NoError(t, err)
	require.Len(t, list, 2)
}

func TestHashAlloc_AllocAny(t *testing.T) {
	alloc, err := NewHashAllocator[bool](
		netip.MustParseAddr("10.0.0.0"),
		netip.MustParseAddr("10.0.0.100"),
		10,
	)
	require.NoError(t, err)

	ip, err := alloc.AllocAny(true)
	require.NoError(t, err)
	require.Equal(t, netip.MustParseAddr("10.0.0.0"), ip)
}

func TestHashAlloc_AllocAnyFull(t *testing.T) {
	alloc, err := NewHashAllocator[bool](
		netip.MustParseAddr("10.0.0.0"),
		netip.MustParseAddr("10.0.0.0"),
		10,
	)
	require.NoError(t, err)

	ip, err := alloc.AllocAny(true)
	require.NoError(t, err)
	require.Equal(t, netip.MustParseAddr("10.0.0.0"), ip)

	ip, err = alloc.AllocAny(true)
	require.ErrorIs(t, err, ErrFull)
	require.Equal(t, netip.Addr{}, ip)
}

func TestHashAlloc_Alloc(t *testing.T) {
	alloc, err := NewHashAllocator[bool](
		netip.MustParseAddr("10.0.0.0"),
		netip.MustParseAddr("10.0.0.100"),
		10,
	)
	require.NoError(t, err)

	err = alloc.Alloc(netip.MustParseAddr("10.0.0.50"), true)
	require.NoError(t, err)

	err = alloc.Alloc(netip.MustParseAddr("10.0.0.50"), true)
	require.ErrorIs(t, err, ErrInUse)

	err = alloc.Alloc(netip.MustParseAddr("10.0.0.200"), true)
	require.ErrorIs(t, err, ErrOutOfRange)
}

func TestHashAlloc_UpdateGet(t *testing.T) {
	alloc, err := NewHashAllocator[int](
		netip.MustParseAddr("10.0.0.0"),
		netip.MustParseAddr("10.0.0.100"),
		10,
	)
	require.NoError(t, err)

	err = alloc.Alloc(netip.MustParseAddr("10.0.0.50"), 1)
	require.NoError(t, err)

	err = alloc.Update(netip.MustParseAddr("10.0.0.50"), 2)
	require.NoError(t, err)

	val, exists := alloc.Get(netip.MustParseAddr("10.0.0.50"))
	require.Equal(t, val, 2)
	require.Equal(t, exists, true)

	err = alloc.Update(netip.MustParseAddr("10.0.0.51"), 2)
	require.ErrorIs(t, err, ErrNotFound)

	val, exists = alloc.Get(netip.MustParseAddr("10.0.0.51"))
	require.Equal(t, val, 0)
	require.Equal(t, exists, false)
}

func TestHashAlloc_Free(t *testing.T) {
	alloc, err := NewHashAllocator[bool](
		netip.MustParseAddr("10.0.0.0"),
		netip.MustParseAddr("10.0.0.100"),
		10,
	)
	require.NoError(t, err)

	err = alloc.Alloc(netip.MustParseAddr("10.0.0.50"), true)
	require.NoError(t, err)

	err = alloc.Free(netip.MustParseAddr("10.0.0.50"))
	require.NoError(t, err)

	val, exists := alloc.Get(netip.MustParseAddr("10.0.0.50"))
	require.Equal(t, val, false)
	require.Equal(t, exists, false)
}

func TestHashAlloc_NewBadPaths(t *testing.T) {
	_, err := NewHashAllocator[bool](
		netip.MustParseAddr("::FF"),
		netip.MustParseAddr("10.0.0.100"),
		10,
	)
	require.Error(t, err)

	_, err = NewHashAllocator[bool](
		netip.MustParseAddr("10.0.0.100"),
		netip.MustParseAddr("::FF"),
		10,
	)
	require.Error(t, err)

	_, err = NewHashAllocator[bool](
		netip.Addr{},
		netip.MustParseAddr("::FF"),
		10,
	)
	require.Error(t, err)

	_, err = NewHashAllocator[bool](
		netip.MustParseAddr("::FF"),
		netip.Addr{},
		10,
	)
	require.Error(t, err)

	_, err = NewHashAllocator[bool](
		netip.MustParseAddr("10.0.0.100"),
		netip.MustParseAddr("10.0.0.0"),
		10,
	)
	require.Error(t, err)

	_, err = NewHashAllocator[bool](
		netip.MustParseAddr("::FF00"),
		netip.MustParseAddr("::00FF"),
		10,
	)
	require.Error(t, err)
}

func TestHashAlloc_Stats(t *testing.T) {
	alloc, err := NewHashAllocator[bool](
		netip.MustParseAddr("10.0.0.0"),
		netip.MustParseAddr("10.0.0.255"),
		10,
	)
	require.NoError(t, err)

	allocated, available := alloc.Stats()
	require.Equal(t, uint64(0), allocated)
	require.Equal(t, uint64(256), available.Uint64())

	ip, err := alloc.AllocAny(true)
	require.NoError(t, err)

	allocated, available = alloc.Stats()
	require.Equal(t, uint64(1), allocated)
	require.Equal(t, uint64(255), available.Uint64())

	err = alloc.Free(ip)
	require.NoError(t, err)

	allocated, available = alloc.Stats()
	require.Equal(t, uint64(0), allocated)
	require.Equal(t, uint64(256), available.Uint64())
}

func BenchmarkHashAlloc_AllocFullRand(b *testing.B) {
	alloc, err := NewHashAllocator[bool](
		netip.MustParseAddr("0.0.0.0"),
		netip.MustParseAddr("255.255.255.255"),
		b.N,
	)
	if err != nil {
		b.Fatal(err)
	}

	buf := make([]byte, 4*b.N)
	_, err = rand.Read(buf)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		ip, ok := netip.AddrFromSlice(buf[i*4 : (i+1)*4])
		if !ok {
			b.Fatal("can't convert IP")
		}

		err = alloc.Alloc(ip, true)
		if err != nil && !errors.Is(err, ErrInUse) {
			b.Fatal(err)
		}
	}
}

func BenchmarkHashAlloc_AllocAny(b *testing.B) {
	alloc, err := NewHashAllocator[bool](
		netip.MustParseAddr("0.0.0.0"),
		netip.MustParseAddr("255.255.255.255"),
		b.N,
	)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err = alloc.AllocAny(true)
		if err != nil && !errors.Is(err, ErrInUse) {
			b.Fatal(err)
		}
	}
}

func BenchmarkHashAlloc_AllocBalanced(b *testing.B) {
	for r := 1; r <= 9; r++ {
		a := 10 - r
		b.Run(fmt.Sprintf("%d%% specific / %d%% any", r*10, a*10), func(bb *testing.B) {
			alloc, err := NewHashAllocator[bool](
				netip.MustParseAddr("0.0.0.0"),
				netip.MustParseAddr("0.255.255.255"),
				bb.N,
			)
			if err != nil {
				b.Fatal(err)
			}

			buf := make([]byte, 3*bb.N)
			_, err = rand.Read(buf)
			if err != nil {
				b.Fatal(err)
			}

			bb.ResetTimer()

			for i := 0; i < bb.N/r; i++ {
				ip, ok := netip.AddrFromSlice(append([]byte{0}, buf[i*3:(i+1)*3]...))
				if !ok {
					b.Fatal("can't convert IP")
				}

				err = alloc.Alloc(ip, true)
				if err != nil && !errors.Is(err, ErrInUse) {
					b.Fatal(err)
				}

				for ii := 0; ii < a; ii++ {
					_, err = alloc.AllocAny(true)
					if err != nil && !errors.Is(err, ErrInUse) {
						b.Fatal(err)
					}
				}
			}

			fmt.Println("block count: ", len(alloc.availableBlocks))
		})
	}
}

func BenchmarkHashAlloc_AllocPerStage(b *testing.B) {
	for _, p := range []int{10, 100, 1000, 10_000, 20_000, 50_000} {
		b.Run(fmt.Sprintf("pre-alloced-%d", p), func(bb *testing.B) {
			alloc, err := NewHashAllocator[bool](
				netip.MustParseAddr("0.0.0.0"),
				netip.MustParseAddr("0.255.255.255"),
				p+bb.N,
			)
			if err != nil {
				b.Fatal(err)
			}

			buf := make([]byte, 3*p)
			_, err = rand.Read(buf)
			if err != nil {
				b.Fatal(err)
			}

			for i := 0; i < p; i++ {
				ip, ok := netip.AddrFromSlice(append([]byte{0}, buf[i*3:(i+1)*3]...))
				if !ok {
					b.Fatal("can't convert IP")
				}

				err = alloc.Alloc(ip, true)
				if err != nil && !errors.Is(err, ErrInUse) {
					b.Fatal(err)
				}
			}

			buf = make([]byte, 3*bb.N)
			_, err = rand.Read(buf)
			if err != nil {
				b.Fatal(err)
			}

			bb.ResetTimer()

			for i := 0; i < bb.N; i++ {
				ip, ok := netip.AddrFromSlice(append([]byte{0}, buf[i*3:(i+1)*3]...))
				if !ok {
					b.Fatal("can't convert IP")
				}

				err = alloc.Alloc(ip, true)
				if err != nil && !errors.Is(err, ErrInUse) {
					b.Fatal(err)
				}
			}
		})
	}
}
