// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxy

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/policy"
	endpointtest "github.com/cilium/cilium/pkg/proxy/endpoint/test"
	"github.com/cilium/cilium/pkg/proxy/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

type MockDatapathUpdater struct{}

func (m *MockDatapathUpdater) InstallProxyRules(proxyPort uint16, localOnly bool, name string) {
}

func (m *MockDatapathUpdater) SupportsOriginalSourceAddr() bool {
	return true
}

func TestPortAllocator(t *testing.T) {
	mockDatapathUpdater := &MockDatapathUpdater{}

	testRunDir := t.TempDir()
	socketDir := envoy.GetSocketDir(testRunDir)
	err := os.MkdirAll(socketDir, 0700)
	require.NoError(t, err)

	p := createProxy(10000, 20000, mockDatapathUpdater, nil, nil)

	port, err := p.AllocateProxyPort("listener1", false, true)
	require.NoError(t, err)
	require.NotEqual(t, 0, port)

	port1, err := p.GetProxyPort("listener1")
	require.NoError(t, err)
	require.Equal(t, port, port1)

	// Another allocation for the same name gets the same port
	port1a, err := p.AllocateProxyPort("listener1", false, true)
	require.NoError(t, err)
	require.Equal(t, port1, port1a)

	name, pp := p.findProxyPortByType(types.ProxyTypeCRD, "listener1", false)
	require.Equal(t, "listener1", name)
	require.Equal(t, types.ProxyTypeCRD, pp.proxyType)
	require.Equal(t, port, pp.proxyPort)
	require.Equal(t, false, pp.ingress)
	require.Equal(t, true, pp.localOnly)
	require.Equal(t, true, pp.configured)
	require.Equal(t, false, pp.isStatic)
	require.Equal(t, 0, pp.nRedirects)
	require.Equal(t, uint16(0), pp.rulesPort)

	err = p.ReleaseProxyPort("listener1")
	require.NoError(t, err)

	// ProxyPort lingers and can still be found, but it's port is zeroed
	port1b, err := p.GetProxyPort("listener1")
	require.NoError(t, err)
	require.Equal(t, uint16(0), port1b)
	require.Equal(t, uint16(0), pp.proxyPort)
	require.Equal(t, false, pp.configured)
	require.Equal(t, 0, pp.nRedirects)

	// the port was never acked, so rulesPort is 0
	require.Equal(t, uint16(0), pp.rulesPort)

	// Allocates a different port (due to port was never acked)
	port2, err := p.AllocateProxyPort("listener1", true, false)
	require.NoError(t, err)
	require.NotEqual(t, port, port2)
	require.Equal(t, types.ProxyTypeCRD, pp.proxyType)
	require.Equal(t, false, pp.ingress)
	require.Equal(t, true, pp.localOnly)
	require.Equal(t, port2, pp.proxyPort)
	require.Equal(t, true, pp.configured)
	require.Equal(t, false, pp.isStatic)
	require.Equal(t, 0, pp.nRedirects)
	require.Equal(t, uint16(0), pp.rulesPort)

	// Ack configures the port to the datapath
	err = p.AckProxyPort(context.TODO(), "listener1")
	require.NoError(t, err)
	require.Equal(t, 1, pp.nRedirects)
	require.Equal(t, port2, pp.rulesPort)

	// Another Ack takes another reference
	err = p.AckProxyPort(context.TODO(), "listener1")
	require.NoError(t, err)
	require.Equal(t, 2, pp.nRedirects)
	require.Equal(t, port2, pp.rulesPort)

	// 1st release decreases the count
	err = p.ReleaseProxyPort("listener1")
	require.NoError(t, err)
	require.Equal(t, 1, pp.nRedirects)
	require.Equal(t, true, pp.configured)
	require.Equal(t, port2, pp.proxyPort)

	// 2nd release decreases the count to zero
	err = p.ReleaseProxyPort("listener1")
	require.NoError(t, err)
	require.Equal(t, 0, pp.nRedirects)
	require.Equal(t, false, pp.configured)
	require.Equal(t, uint16(0), pp.proxyPort)
	require.Equal(t, port2, pp.rulesPort)

	// extra releases are idempotent
	err = p.ReleaseProxyPort("listener1")
	require.NoError(t, err)
	require.Equal(t, 0, pp.nRedirects)
	require.Equal(t, false, pp.configured)
	require.Equal(t, uint16(0), pp.proxyPort)
	require.Equal(t, port2, pp.rulesPort)

	// mimic some other process taking the port
	p.allocatedPorts[port2] = true

	// Allocate again, this time a different port is allocated
	port3, err := p.AllocateProxyPort("listener1", true, true)
	require.NoError(t, err)
	require.NotEqual(t, uint16(0), port3)
	require.NotEqual(t, port2, port3)
	require.NotEqual(t, port1, port3)
	require.Equal(t, types.ProxyTypeCRD, pp.proxyType)
	require.Equal(t, false, pp.ingress)
	require.Equal(t, true, pp.localOnly)
	require.Equal(t, port3, pp.proxyPort)
	require.Equal(t, true, pp.configured)
	require.Equal(t, false, pp.isStatic)
	require.Equal(t, 0, pp.nRedirects)
	require.Equal(t, port2, pp.rulesPort)

	// Ack configures the port to the datapath
	err = p.AckProxyPort(context.TODO(), "listener1")
	require.NoError(t, err)
	require.Equal(t, 1, pp.nRedirects)
	require.Equal(t, port3, pp.rulesPort)

	// Release marks the port as unallocated
	err = p.ReleaseProxyPort("listener1")
	require.NoError(t, err)
	require.Equal(t, 0, pp.nRedirects)
	require.Equal(t, false, pp.configured)
	require.Equal(t, uint16(0), pp.proxyPort)
	require.Equal(t, port3, pp.rulesPort)

	inuse, exists := p.allocatedPorts[port3]
	require.Equal(t, true, exists)
	require.Equal(t, false, inuse)

	// No-one used the port so next allocation gets the same port again
	port4, err := p.AllocateProxyPort("listener1", true, true)
	require.NoError(t, err)
	require.Equal(t, port3, port4)
	require.Equal(t, types.ProxyTypeCRD, pp.proxyType)
	require.Equal(t, false, pp.ingress)
	require.Equal(t, true, pp.localOnly)
	require.Equal(t, port4, pp.proxyPort)
	require.Equal(t, true, pp.configured)
	require.Equal(t, false, pp.isStatic)
	require.Equal(t, 0, pp.nRedirects)
	require.Equal(t, port3, pp.rulesPort)
}

type fakeProxyPolicy struct{}

func (p *fakeProxyPolicy) CopyL7RulesPerEndpoint() policy.L7DataMap {
	return policy.L7DataMap{}
}

func (p *fakeProxyPolicy) GetL7Parser() policy.L7ParserType {
	return policy.ParserTypeCRD
}

func (p *fakeProxyPolicy) GetIngress() bool {
	return false
}

func (p *fakeProxyPolicy) GetPort() uint16 {
	return uint16(80)
}

func (p *fakeProxyPolicy) GetProtocol() uint8 {
	return uint8(u8proto.UDP)
}

func (p *fakeProxyPolicy) GetListener() string {
	return "nonexisting-listener"
}

func TestCreateOrUpdateRedirectMissingListener(t *testing.T) {
	mockDatapathUpdater := &MockDatapathUpdater{}

	testRunDir := t.TempDir()
	socketDir := envoy.GetSocketDir(testRunDir)
	err := os.MkdirAll(socketDir, 0700)
	require.NoError(t, err)

	p := createProxy(10000, 20000, mockDatapathUpdater, nil, nil)

	ep := &endpointtest.ProxyUpdaterMock{
		Id:   1000,
		Ipv4: "10.0.0.1",
		Ipv6: "f00d::1",
	}

	l4 := &fakeProxyPolicy{}

	ctx := context.TODO()
	wg := completion.NewWaitGroup(ctx)

	proxyPort, err, finalizeFunc, revertFunc := p.CreateOrUpdateRedirect(ctx, l4, "dummy-proxy-id", ep, wg)
	require.Equal(t, uint16(0), proxyPort)
	require.Error(t, err)
	require.Nil(t, finalizeFunc)
	require.Nil(t, revertFunc)
}
