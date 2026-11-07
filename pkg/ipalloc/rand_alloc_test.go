// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipalloc

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRandAlloc_AllocAnyFull(t *testing.T) {
	alloc, err := NewRandomAllocator[bool](
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

func TestRandAlloc_Alloc(t *testing.T) {
	alloc, err := NewRandomAllocator[bool](
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

func TestRandAlloc_UpdateGet(t *testing.T) {
	alloc, err := NewRandomAllocator[int](
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
	require.Equal(t, 2, val)
	require.True(t, exists)

	err = alloc.Update(netip.MustParseAddr("10.0.0.51"), 2)
	require.ErrorIs(t, err, ErrNotFound)

	val, exists = alloc.Get(netip.MustParseAddr("10.0.0.51"))
	require.Equal(t, 0, val)
	require.False(t, exists)
}

func TestRandAlloc_Free(t *testing.T) {
	alloc, err := NewRandomAllocator[bool](
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
	require.False(t, val)
	require.False(t, exists)
}

func TestRandAlloc_AllocFreeThenAlloc(t *testing.T) {
	alloc, err := NewRandomAllocator[bool](
		netip.MustParseAddr("0.0.0.0"),
		netip.MustParseAddr("0.0.0.255"),
		100,
	)

	require.NoError(t, err)

	ip1, err := alloc.AllocAny(true)
	require.NoError(t, err)

	val, _ := alloc.Get(ip1)
	assert.True(t, val, "IP was allocatecd, but found false")

	alloc.Free(ip1)
	val, _ = alloc.Get(ip1)

	assert.False(t, val, "IP was freeed, but found true")

	ip2, err := alloc.AllocAny(true)
	require.NoError(t, err)

	val, _ = alloc.Get(ip2)
	assert.True(t, val, "IP was allocatecd, but found false")

	alloc.Free(ip2)
	val, _ = alloc.Get(ip2)
	assert.False(t, val, "IP was freeed, but found true")

}

func TestRandAlloc_NewBadPaths(t *testing.T) {
	_, err := NewRandomAllocator[bool](
		netip.MustParseAddr("::FF"),
		netip.MustParseAddr("10.0.0.100"),
		10,
	)
	require.Error(t, err)

	_, err = NewRandomAllocator[bool](
		netip.MustParseAddr("10.0.0.100"),
		netip.MustParseAddr("::FF"),
		10,
	)
	require.Error(t, err)

	_, err = NewRandomAllocator[bool](
		netip.Addr{},
		netip.MustParseAddr("::FF"),
		10,
	)
	require.Error(t, err)

	_, err = NewRandomAllocator[bool](
		netip.MustParseAddr("::FF"),
		netip.Addr{},
		10,
	)
	require.Error(t, err)

	_, err = NewRandomAllocator[bool](
		netip.MustParseAddr("10.0.0.100"),
		netip.MustParseAddr("10.0.0.0"),
		10,
	)
	require.Error(t, err)

	_, err = NewRandomAllocator[bool](
		netip.MustParseAddr("::FF00"),
		netip.MustParseAddr("::00FF"),
		10,
	)
	require.Error(t, err)
}

func TestRandAlloc_Stats(t *testing.T) {
	alloc, err := NewRandomAllocator[bool](
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

func BenchmarkRandAlloc_AllocFullRand(b *testing.B) {
	alloc, err := NewRandomAllocator[bool](
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

func BenchmarkRandAlloc_AllocAny(b *testing.B) {
	alloc, err := NewRandomAllocator[bool](
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

func BenchmarkRandAlloc_AllocBalanced(b *testing.B) {
	for r := 1; r <= 9; r++ {
		a := 10 - r
		b.Run(fmt.Sprintf("%d%% specific / %d%% any", r*10, a*10), func(bb *testing.B) {
			alloc, err := NewRandomAllocator[bool](
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

			for i := range bb.N / r {
				ip, ok := netip.AddrFromSlice(append([]byte{0}, buf[i*3:(i+1)*3]...))
				if !ok {
					b.Fatal("can't convert IP")
				}

				err = alloc.Alloc(ip, true)
				if err != nil && !errors.Is(err, ErrInUse) {
					b.Fatal(err)
				}

				for range a {
					_, err = alloc.AllocAny(true)
					if err != nil && !errors.Is(err, ErrInUse) {
						b.Fatal(err)
					}
				}
			}

		})
	}
}

func BenchmarkRandAlloc_AllocPerStage(b *testing.B) {
	for _, p := range []int{10, 100, 1000, 10_000, 20_000, 50_000} {
		b.Run(fmt.Sprintf("pre-alloced-%d", p), func(bb *testing.B) {
			alloc, err := NewRandomAllocator[bool](
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

			for i := range p {
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
