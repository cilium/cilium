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
	"github.com/cilium/cilium/pkg/proxy/proxyports"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/trigger"
	"github.com/cilium/cilium/pkg/u8proto"
)

func proxyForTest() (*Proxy, func()) {
	mockDatapathUpdater := &proxyports.MockDatapathUpdater{}
	p := createProxy(10000, 20000, mockDatapathUpdater, nil, nil)
	triggerDone := make(chan struct{})
	p.proxyPorts.Trigger, _ = trigger.NewTrigger(trigger.Parameters{
		MinInterval:  10 * time.Second,
		TriggerFunc:  func(reasons []string) {},
		ShutdownFunc: func() { close(triggerDone) },
	})
	return p, func() {
		p.proxyPorts.Trigger.Shutdown()
		<-triggerDone
	}
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
