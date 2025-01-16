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
	if err == nil {
		defer func() {
			os.RemoveAll(socketDir)
		}()
	}
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
	require.Zero(t, pp.rulesPort)

	// Unacknowledged proxy port is released due to a NACK
	p.ResetUnacknowledged(pp)
	require.False(t, pp.configured)
	require.False(t, pp.acknowledged)
	require.Zero(t, pp.ProxyPort)

	err = p.releaseProxyPort("listener1", 10*time.Millisecond)
	require.NoError(t, err)

	// Proxy port is not released immediately
	require.Zero(t, pp.nRedirects)
	require.Zero(t, pp.ProxyPort)
	port1a, _, err = p.GetProxyPort("listener1")
	require.NoError(t, err)
	require.Zero(t, port1a)

	require.Eventually(t, func() bool {
		return p.released(pp)
	}, 100*time.Millisecond, time.Millisecond)

	// ProxyPort lingers and can still be found, but it's port is zeroed
	port1b, _, err := p.GetProxyPort("listener1")
	require.NoError(t, err)
	require.Zero(t, port1b)
	require.Zero(t, pp.ProxyPort)
	require.False(t, pp.configured)
	require.False(t, pp.acknowledged)
	require.Zero(t, pp.nRedirects)

	// the port was never acked, so rulesPort is 0
	require.Zero(t, pp.rulesPort)

	// Allocates a different port (due to port was never acked)
	port2, err := p.AllocateCRDProxyPort("listener1")
	require.NoError(t, err)
	require.NotEqual(t, port, port2)
	name2, pp2 := p.FindByTypeWithReference(types.ProxyTypeCRD, "listener1", false)
	require.Equal(t, name, name2)
	require.Equal(t, pp, pp2)
	require.Equal(t, types.ProxyTypeCRD, pp.ProxyType)
	require.False(t, pp.Ingress)
	require.Equal(t, port2, pp2.ProxyPort)
	require.True(t, pp2.configured)
	require.False(t, pp2.acknowledged)
	require.False(t, pp2.isStatic)
	require.Equal(t, 1, pp2.nRedirects)
	require.Zero(t, pp2.rulesPort)

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

	require.Zero(t, pp.nRedirects)
	require.False(t, pp.configured)
	require.False(t, pp.acknowledged)
	require.Zero(t, pp.ProxyPort)
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
	require.Equal(t, name, name2)
	require.Equal(t, pp, pp2)
	require.Equal(t, types.ProxyTypeCRD, pp.ProxyType)
	require.False(t, pp.Ingress)
	require.Equal(t, port3, pp2.ProxyPort)
	require.True(t, pp2.configured)
	require.False(t, pp2.acknowledged)
	require.False(t, pp2.isStatic)
	require.Equal(t, 1, pp2.nRedirects)
	require.Equal(t, port2, pp2.rulesPort)

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

	require.Zero(t, pp.nRedirects)
	require.False(t, pp.configured)
	require.False(t, pp.acknowledged)
	require.Zero(t, pp.ProxyPort)
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
	require.Zero(t, pp.nRedirects)
	require.Equal(t, port3, pp.rulesPort)
}

func TestRestoredPort(t *testing.T) {
	testRunDir := t.TempDir()
	socketDir := envoy.GetSocketDir(testRunDir)
	err := os.MkdirAll(socketDir, 0700)
	require.NoError(t, err)
	if err == nil {
		defer func() {
			os.RemoveAll(socketDir)
		}()
	}
	p, cleaner := proxyPortsForTest()
	defer cleaner()

	// simulate proxy port restored from file
	const ppName = string("cilium-http-egress")
	const restoredPort = uint16(14321)
	pp := p.proxyPorts[ppName]
	pp.ProxyPort = restoredPort

	require.False(t, pp.configured)
	require.False(t, pp.acknowledged)
	require.Zero(t, pp.rulesPort)

	// Test that first allocation returns the restored port and marks it as configured
	err = p.AllocatePort(pp, false)
	require.NoError(t, err)
	require.Equal(t, restoredPort, pp.ProxyPort)
	require.True(t, pp.configured, "restored proxy port not marked as configured")
	require.False(t, pp.acknowledged)

	// Test that HasProxyType is satisfied
	require.True(t, p.HasProxyType(pp, types.ProxyTypeHTTP))

	// Simulate a NACK
	p.ResetUnacknowledged(pp)
	require.Zero(t, pp.ProxyPort)
	require.False(t, pp.configured)
	require.False(t, pp.acknowledged)

	// Allocate again, check that a new port is allocated
	err = p.AllocatePort(pp, false)
	require.NoError(t, err)
	require.NotZero(t, pp.ProxyPort)
	require.NotEqual(t, restoredPort, pp.ProxyPort)
	require.True(t, pp.configured)
	require.False(t, pp.acknowledged)

	newPort := pp.ProxyPort

	// Simulate ACK
	err = p.AckProxyPortWithReference(context.TODO(), ppName)
	require.NoError(t, err)
	require.Equal(t, newPort, pp.ProxyPort)
	require.True(t, pp.configured)
	require.True(t, pp.acknowledged)
	require.Equal(t, 1, pp.nRedirects)

	// Release
	require.Nil(t, pp.releaseCancel)
	err = p.releaseProxyPort(ppName, time.Microsecond)
	require.NoError(t, err)
	require.Zero(t, pp.nRedirects)

	// wait for port reuse wait to pass
	time.Sleep(time.Millisecond)
	require.Zero(t, pp.ProxyPort)
	require.False(t, pp.configured)
	require.False(t, pp.acknowledged)

	// datapath port number is left as is
	require.Equal(t, newPort, pp.rulesPort)

	// Reallocation returns the previous datapath port and marks it as configured
	p.Restore(pp)
	err = p.AllocatePort(pp, false)
	require.NoError(t, err)
	require.Equal(t, newPort, pp.ProxyPort)
	require.True(t, pp.configured)
	require.False(t, pp.acknowledged)
}
