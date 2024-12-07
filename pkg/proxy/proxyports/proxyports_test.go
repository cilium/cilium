// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxyports

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/proxy/types"
	"github.com/cilium/cilium/pkg/time"
)

func (p *ProxyPorts) released(pp *ProxyPort) bool {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	return pp.nRedirects == 0 && pp.ProxyPort == 0 && !pp.configured && !pp.acknowledged
}

func TestPortAllocator(t *testing.T) {
	testRunDir := t.TempDir()
	socketDir := envoy.GetSocketDir(testRunDir)
	err := os.MkdirAll(socketDir, 0700)
	require.NoError(t, err)

	p, cleaner := proxyPortsForTest()
	defer cleaner()

	port, err := p.AllocateCRDProxyPort("listener1")
	require.NoError(t, err)
	require.NotEqual(t, 0, port)

	port1, _, err := p.GetProxyPort("listener1")
	require.NoError(t, err)
	require.Equal(t, port, port1)

	// Another allocation for the same name gets the same port
	port1a, err := p.AllocateCRDProxyPort("listener1")
	require.NoError(t, err)
	require.Equal(t, port1, port1a)

	name, pp := p.FindByTypeWithReference(types.ProxyTypeCRD, "listener1", false)
	require.Equal(t, "listener1", name)
	require.Equal(t, types.ProxyTypeCRD, pp.ProxyType)
	require.Equal(t, port, pp.ProxyPort)
	require.False(t, pp.Ingress)
	require.True(t, pp.configured)
	require.False(t, pp.acknowledged)
	require.False(t, pp.isStatic)
	require.Equal(t, 1, pp.nRedirects)
	require.Equal(t, uint16(0), pp.rulesPort)

	// Unacknowledged proxy port is released due to a NACK
	p.ResetUnacknowledged(pp)
	require.False(t, pp.configured)
	require.False(t, pp.acknowledged)
	require.Equal(t, uint16(0), pp.ProxyPort)

	err = p.releaseProxyPort("listener1", 10*time.Millisecond)
	require.NoError(t, err)

	// Proxy port is not released immediately
	require.Equal(t, 0, pp.nRedirects)
	require.Equal(t, uint16(0), pp.ProxyPort)
	port1a, _, err = p.GetProxyPort("listener1")
	require.NoError(t, err)
	require.Equal(t, uint16(0), port1a)

	require.Eventually(t, func() bool {
		return p.released(pp)
	}, 100*time.Millisecond, time.Millisecond)

	// ProxyPort lingers and can still be found, but it's port is zeroed
	port1b, _, err := p.GetProxyPort("listener1")
	require.NoError(t, err)
	require.Equal(t, uint16(0), port1b)
	require.Equal(t, uint16(0), pp.ProxyPort)
	require.False(t, pp.configured)
	require.False(t, pp.acknowledged)
	require.Equal(t, 0, pp.nRedirects)

	// the port was never acked, so rulesPort is 0
	require.Equal(t, uint16(0), pp.rulesPort)

	// Allocates a different port (due to port was never acked)
	port2, err := p.AllocateCRDProxyPort("listener1")
	require.NoError(t, err)
	require.NotEqual(t, port, port2)
	name2, pp2 := p.FindByTypeWithReference(types.ProxyTypeCRD, "listener1", false)
	require.Equal(t, name2, name)
	require.Equal(t, pp2, pp)
	require.Equal(t, types.ProxyTypeCRD, pp.ProxyType)
	require.False(t, pp.Ingress)
	require.Equal(t, port2, pp.ProxyPort)
	require.True(t, pp.configured)
	require.False(t, pp.acknowledged)
	require.False(t, pp.isStatic)
	require.Equal(t, 1, pp.nRedirects)
	require.Equal(t, uint16(0), pp.rulesPort)

	// Ack configures the port to the datapath
	err = p.AckProxyPort(context.TODO(), "listener1", pp)
	require.NoError(t, err)
	require.Equal(t, 1, pp.nRedirects)
	require.True(t, pp.acknowledged)
	require.Equal(t, port2, pp.rulesPort)

	// Another Ack takes another reference
	err = p.AckProxyPortWithReference(context.TODO(), "listener1")
	require.NoError(t, err)
	require.Equal(t, 2, pp.nRedirects)
	require.True(t, pp.acknowledged)
	require.Equal(t, port2, pp.rulesPort)

	// 1st release decreases the count
	err = p.ReleaseProxyPort("listener1")
	require.NoError(t, err)
	require.Equal(t, 1, pp.nRedirects)
	require.True(t, pp.configured)
	require.True(t, pp.acknowledged)
	require.Equal(t, port2, pp.ProxyPort)

	// Acknowledged proxy port is not released due to a NACK
	p.ResetUnacknowledged(pp)
	require.Equal(t, 1, pp.nRedirects)
	require.True(t, pp.configured)
	require.True(t, pp.acknowledged)
	require.Equal(t, port2, pp.ProxyPort)

	// 2nd release decreases the count to zero
	err = p.releaseProxyPort("listener1", time.Microsecond)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		return p.released(pp)
	}, 100*time.Millisecond, time.Millisecond)

	require.Equal(t, 0, pp.nRedirects)
	require.False(t, pp.configured)
	require.False(t, pp.acknowledged)
	require.Equal(t, uint16(0), pp.ProxyPort)
	require.Equal(t, port2, pp.rulesPort)

	// extra releases return an error
	err = p.ReleaseProxyPort("listener1")
	require.Error(t, err)

	// mimic some other process taking the port
	p.allocatedPorts[port2] = true

	// Allocate again, this time a different port is allocated
	port3, err := p.AllocateCRDProxyPort("listener1")
	require.NoError(t, err)
	require.NotEqual(t, uint16(0), port3)
	require.NotEqual(t, port2, port3)
	require.NotEqual(t, port1, port3)
	name2, pp2 = p.FindByTypeWithReference(types.ProxyTypeCRD, "listener1", false)
	require.Equal(t, name2, name)
	require.Equal(t, pp2, pp)
	require.Equal(t, types.ProxyTypeCRD, pp.ProxyType)
	require.False(t, pp.Ingress)
	require.Equal(t, port3, pp.ProxyPort)
	require.True(t, pp.configured)
	require.False(t, pp.acknowledged)
	require.False(t, pp.isStatic)
	require.Equal(t, 1, pp.nRedirects)
	require.Equal(t, port2, pp.rulesPort)

	// Ack configures the port to the datapath
	err = p.AckProxyPort(context.TODO(), "listener1", pp)
	require.NoError(t, err)
	require.Equal(t, 1, pp.nRedirects)
	require.True(t, pp.acknowledged)
	require.Equal(t, port3, pp.rulesPort)

	// Release marks the port as unallocated
	err = p.releaseProxyPort("listener1", time.Microsecond)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		return p.released(pp)
	}, 100*time.Millisecond, time.Millisecond)

	require.Equal(t, 0, pp.nRedirects)
	require.False(t, pp.configured)
	require.False(t, pp.acknowledged)
	require.Equal(t, uint16(0), pp.ProxyPort)
	require.Equal(t, port3, pp.rulesPort)

	inuse, exists := p.allocatedPorts[port3]
	require.True(t, exists)
	require.False(t, inuse)

	// No-one used the port so next allocation gets the same port again
	port4, err := p.AllocateCRDProxyPort("listener1")
	require.NoError(t, err)
	require.Equal(t, port3, port4)
	require.Equal(t, types.ProxyTypeCRD, pp.ProxyType)
	require.False(t, pp.Ingress)
	require.Equal(t, port4, pp.ProxyPort)
	require.True(t, pp.configured)
	require.False(t, pp.acknowledged)
	require.False(t, pp.isStatic)
	require.Equal(t, 0, pp.nRedirects)
	require.Equal(t, port3, pp.rulesPort)
}
