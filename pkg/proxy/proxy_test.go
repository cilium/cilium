// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxy

import (
	"context"
	"os"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/completion"
	datapath "github.com/cilium/cilium/pkg/datapath/fake/types"
	"github.com/cilium/cilium/pkg/datapath/linux/route/reconciler"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/proxyports"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/u8proto"
)

func proxyForTest(t *testing.T) *Proxy {
	var drm *reconciler.DesiredRouteManager
	hive.New(
		reconciler.TableCell,
		cell.Invoke(func(m *reconciler.DesiredRouteManager) {
			drm = m
		}),
	).Populate(hivetest.Logger(t))
	fakeIPTablesManager := &datapath.FakeIptablesManager{}
	ppConfig := proxyports.ProxyPortsConfig{
		ProxyPortrangeMin:          10000,
		ProxyPortrangeMax:          20000,
		RestoredProxyPortsAgeLimit: 0,
	}
	pp := proxyports.NewProxyPorts(hivetest.Logger(t), ppConfig, fakeIPTablesManager)
	p, err := createProxy(true, hivetest.Logger(t), nil, pp, nil, nil, nil, nil, drm)
	require.NoError(t, err)

	p.proxyPorts.Trigger = job.NewTrigger(job.WithDebounce(10 * time.Second))
	return p
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
	err := os.MkdirAll(socketDir, 0o700)
	require.NoError(t, err)

	p := proxyForTest(t)

	l4 := &fakeProxyPolicy{}

	ctx := context.TODO()
	wg := completion.NewWaitGroup(ctx)

	proxyPort, err, revertFunc := p.CreateOrUpdateRedirect(ctx, l4, "dummy-proxy-id", 1000, wg)
	require.Equal(t, uint16(0), proxyPort)
	require.Error(t, err)
	require.Nil(t, revertFunc)
}
