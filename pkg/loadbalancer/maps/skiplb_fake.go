// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package maps

import (
	"iter"
	"net/netip"

	"github.com/cilium/cilium/pkg/lock"
)

// FakeSkipLBMap is an in-memory SkipLBMap for tests. Its zero value is ready to use.
type FakeSkipLBMap struct {
	entries lock.Map[any, any]
}

// OpenOrCreate implements SkipLBMap.
func (f *FakeSkipLBMap) OpenOrCreate() error {
	return nil
}

// Close implements SkipLBMap.
func (f *FakeSkipLBMap) Close() error {
	return nil
}

// AddLB4 implements SkipLBMap.
func (f *FakeSkipLBMap) AddLB4(netnsCookie uint64, ip netip.Addr, port uint16) error {
	key := SkipLB4Key{
		NetnsCookie: netnsCookie,
		Address:     ip.As4(),
		Port:        port,
	}
	f.entries.Store(
		key,
		&SkipLB4Value{},
	)
	return nil
}

// AddLB6 implements SkipLBMap.
func (f *FakeSkipLBMap) AddLB6(netnsCookie uint64, ip netip.Addr, port uint16) error {
	key := SkipLB6Key{
		NetnsCookie: netnsCookie,
		Address:     ip.As16(),
		Port:        port,
	}
	f.entries.Store(
		key,
		&SkipLB6Value{},
	)
	return nil
}

// AllLB4 implements SkipLBMap.
func (f *FakeSkipLBMap) AllLB4() iter.Seq2[*SkipLB4Key, *SkipLB4Value] {
	return func(yield func(*SkipLB4Key, *SkipLB4Value) bool) {
		f.entries.Range(func(key any, value any) bool {
			switch key := key.(type) {
			case SkipLB4Key:
				if !yield(&key, value.(*SkipLB4Value)) {
					return false
				}
			}
			return true
		})
	}
}

// AllLB6 implements SkipLBMap.
func (f *FakeSkipLBMap) AllLB6() iter.Seq2[*SkipLB6Key, *SkipLB6Value] {
	return func(yield func(*SkipLB6Key, *SkipLB6Value) bool) {
		f.entries.Range(func(key any, value any) bool {
			switch key := key.(type) {
			case SkipLB6Key:
				if !yield(&key, value.(*SkipLB6Value)) {
					return false
				}
			}
			return true
		})
	}
}

// DeleteLB4 implements SkipLBMap.
func (f *FakeSkipLBMap) DeleteLB4(key *SkipLB4Key) error {
	f.entries.Delete(*key)
	return nil
}

// DeleteLB6 implements SkipLBMap.
func (f *FakeSkipLBMap) DeleteLB6(key *SkipLB6Key) error {
	f.entries.Delete(*key)
	return nil
}

var _ SkipLBMap = &FakeSkipLBMap{}
