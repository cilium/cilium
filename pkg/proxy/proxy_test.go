// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxy

import (
	"context"
	"os"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/proxyports"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/trigger"
	"github.com/cilium/cilium/pkg/u8proto"
)

func proxyForTest(t *testing.T) (*Proxy, func()) {
	mockDatapathUpdater := &proxyports.MockIPTablesManager{}
	ppConfig := proxyports.ProxyPortsConfig{
		ProxyPortrangeMin:          10000,
		ProxyPortrangeMax:          20000,
		RestoredProxyPortsAgeLimit: 0,
	}
	pp := proxyports.NewProxyPorts(hivetest.Logger(t), ppConfig, mockDatapathUpdater)
	p := createProxy(hivetest.Logger(t), nil, pp, nil, nil)
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

func (p *fakeProxyPolicy) GetPerSelectorPolicies() policy.L7DataMap {
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

	p, cleaner := proxyForTest(t)
	defer cleaner()

	l4 := &fakeProxyPolicy{}

	ctx := context.TODO()
	wg := completion.NewWaitGroup(ctx)

	proxyPort, err, revertFunc := p.CreateOrUpdateRedirect(ctx, l4, "dummy-proxy-id", 1000, wg)
	require.Equal(t, uint16(0), proxyPort)
	require.Error(t, err)
	require.Nil(t, revertFunc)
}
