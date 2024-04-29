// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/identity"
)

type DummyEndpoint struct {
	rev      uint64
	Endpoint // Implement methods of the interface that need to mock out real behavior.
}

func (d *DummyEndpoint) GetSecurityIdentity() (*identity.Identity, error) {
	return nil, nil
}

func (d *DummyEndpoint) PolicyRevisionBumpEvent(rev uint64) {
	d.rev = rev
}

func (d *DummyEndpoint) RLockAlive() error {
	return nil
}

func (d *DummyEndpoint) RUnlock() {
}

func TestNewEndpointSet(t *testing.T) {
	d := &DummyEndpoint{}
	epSet := NewEndpointSet(map[Endpoint]struct{}{
		d: {},
	})
	require.Equal(t, 1, epSet.Len())
	epSet.Delete(d)
	require.Equal(t, 0, epSet.Len())
}

func TestForEachGo(t *testing.T) {
	var wg sync.WaitGroup

	d0 := &DummyEndpoint{}
	d1 := &DummyEndpoint{}

	epSet := NewEndpointSet(map[Endpoint]struct{}{
		d0: {},
		d1: {},
	})
	epSet.ForEachGo(&wg, func(e Endpoint) {
		e.PolicyRevisionBumpEvent(100)
	})

	wg.Wait()

	require.Equal(t, uint64(100), d0.rev)
	require.Equal(t, uint64(100), d1.rev)
}

func BenchmarkForEachGo(b *testing.B) {
	m := make(map[Endpoint]struct{}, b.N)
	for i := uint64(0); i < uint64(b.N); i++ {
		m[&DummyEndpoint{rev: i}] = struct{}{}
	}
	epSet := NewEndpointSet(m)

	b.StartTimer()
	var wg sync.WaitGroup
	epSet.ForEachGo(&wg, func(e Endpoint) {
		e.PolicyRevisionBumpEvent(100)
	})
	wg.Wait()
	b.StopTimer()
}
