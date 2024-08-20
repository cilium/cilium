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
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/trigger"
	"github.com/cilium/cilium/pkg/u8proto"
)

type MockDatapathUpdater struct{}

func (m *MockDatapathUpdater) InstallProxyRules(proxyPort uint16, name string) {
}

func (m *MockDatapathUpdater) GetProxyPorts() map[string]uint16 {
	return nil
}

func proxyForTest() (*Proxy, func()) {
	mockDatapathUpdater := &MockDatapathUpdater{}
	p := createProxy(10000, 20000, mockDatapathUpdater, nil, nil)
	triggerDone := make(chan struct{})
	p.proxyPortsTrigger, _ = trigger.NewTrigger(trigger.Parameters{
		MinInterval:  10 * time.Second,
		TriggerFunc:  func(reasons []string) {},
		ShutdownFunc: func() { close(triggerDone) },
	})
	return p, func() {
		p.proxyPortsTrigger.Shutdown()
		<-triggerDone
	}
}

func TestPortAllocator(t *testing.T) {
	testRunDir := t.TempDir()
	socketDir := envoy.GetSocketDir(testRunDir)
	err := os.MkdirAll(socketDir, 0700)
	require.NoError(t, err)

	p, cleaner := proxyForTest()
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

	name, pp := p.findProxyPortByType(types.ProxyTypeCRD, "listener1", false)
	require.Equal(t, "listener1", name)
	require.Equal(t, types.ProxyTypeCRD, pp.ProxyType)
	require.Equal(t, port, pp.ProxyPort)
	require.Equal(t, false, pp.Ingress)
	require.Equal(t, true, pp.configured)
	require.Equal(t, false, pp.isStatic)
	require.Equal(t, 0, pp.nRedirects)
	require.Equal(t, uint16(0), pp.rulesPort)

	err = p.ReleaseProxyPort("listener1")
	require.NoError(t, err)

	// ProxyPort lingers and can still be found, but it's port is zeroed
	port1b, _, err := p.GetProxyPort("listener1")
	require.NoError(t, err)
	require.Equal(t, uint16(0), port1b)
	require.Equal(t, uint16(0), pp.ProxyPort)
	require.Equal(t, false, pp.configured)
	require.Equal(t, 0, pp.nRedirects)

	// the port was never acked, so rulesPort is 0
	require.Equal(t, uint16(0), pp.rulesPort)

	// Allocates a different port (due to port was never acked)
	port2, err := p.AllocateCRDProxyPort("listener1")
	require.NoError(t, err)
	require.NotEqual(t, port, port2)
	name2, pp2 := p.findProxyPortByType(types.ProxyTypeCRD, "listener1", false)
	require.Equal(t, name2, name)
	require.Equal(t, pp2, pp)
	require.Equal(t, types.ProxyTypeCRD, pp.ProxyType)
	require.Equal(t, false, pp.Ingress)
	require.Equal(t, port2, pp.ProxyPort)
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
	require.Equal(t, port2, pp.ProxyPort)

	// 2nd release decreases the count to zero
	err = p.ReleaseProxyPort("listener1")
	require.NoError(t, err)
	require.Equal(t, 0, pp.nRedirects)
	require.Equal(t, false, pp.configured)
	require.Equal(t, uint16(0), pp.ProxyPort)
	require.Equal(t, port2, pp.rulesPort)

	// extra releases are idempotent
	err = p.ReleaseProxyPort("listener1")
	require.NoError(t, err)
	require.Equal(t, 0, pp.nRedirects)
	require.Equal(t, false, pp.configured)
	require.Equal(t, uint16(0), pp.ProxyPort)
	require.Equal(t, port2, pp.rulesPort)

	// mimic some other process taking the port
	p.allocatedPorts[port2] = true

	// Allocate again, this time a different port is allocated
	port3, err := p.AllocateCRDProxyPort("listener1")
	require.NoError(t, err)
	require.NotEqual(t, uint16(0), port3)
	require.NotEqual(t, port2, port3)
	require.NotEqual(t, port1, port3)
	name2, pp2 = p.findProxyPortByType(types.ProxyTypeCRD, "listener1", false)
	require.Equal(t, name2, name)
	require.Equal(t, pp2, pp)
	require.Equal(t, types.ProxyTypeCRD, pp.ProxyType)
	require.Equal(t, false, pp.Ingress)
	require.Equal(t, port3, pp.ProxyPort)
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
	require.Equal(t, uint16(0), pp.ProxyPort)
	require.Equal(t, port3, pp.rulesPort)

	inuse, exists := p.allocatedPorts[port3]
	require.Equal(t, true, exists)
	require.Equal(t, false, inuse)

	// No-one used the port so next allocation gets the same port again
	port4, err := p.AllocateCRDProxyPort("listener1")
	require.NoError(t, err)
	require.Equal(t, port3, port4)
	require.Equal(t, types.ProxyTypeCRD, pp.ProxyType)
	require.Equal(t, false, pp.Ingress)
	require.Equal(t, port4, pp.ProxyPort)
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

func (p *fakeProxyPolicy) GetProtocol() u8proto.U8proto {
	return u8proto.UDP
}

func (p *fakeProxyPolicy) GetListener() string {
	return "nonexisting-listener"
}

func TestCreateOrUpdateRedirectMissingListener(t *testing.T) {
	testRunDir := t.TempDir()
	socketDir := envoy.GetSocketDir(testRunDir)
	err := os.MkdirAll(socketDir, 0700)
	require.NoError(t, err)

	p, cleaner := proxyForTest()
	defer cleaner()

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
