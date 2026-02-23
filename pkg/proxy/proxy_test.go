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
	cilium "github.com/cilium/proxy/go/cilium/api"
	statedbReconciler "github.com/cilium/statedb/reconciler"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/completion"
	datapath "github.com/cilium/cilium/pkg/datapath/fake/types"
	"github.com/cilium/cilium/pkg/datapath/iptables"
	"github.com/cilium/cilium/pkg/datapath/linux/route/reconciler"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/endpoint"
	"github.com/cilium/cilium/pkg/proxy/proxyports"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/u8proto"
)

func proxyForTest(t *testing.T, envoyIntegration *envoyProxyIntegration) *Proxy {
	var drm *reconciler.DesiredRouteManager
	hive.New(
		reconciler.TableCell,
		cell.Provide(func() (_ statedbReconciler.Reconciler[*reconciler.DesiredRoute]) {
			return nil
		}),
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
	p, err := createProxy(true, hivetest.Logger(t), nil, pp, envoyIntegration, nil, nil, nil, drm)
	require.NoError(t, err)

	p.proxyPorts.Trigger = job.NewTrigger(job.WithDebounce(10 * time.Second))
	return p
}

type fakeProxyPolicy struct {
	parserType policy.L7ParserType
}

func (p *fakeProxyPolicy) GetPerSelectorPolicies() policy.L7DataMap {
	return policy.L7DataMap{}
}

func (p *fakeProxyPolicy) GetL7Parser() policy.L7ParserType {
	return p.parserType
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

	p := proxyForTest(t, nil)

	l4 := &fakeProxyPolicy{policy.ParserTypeCRD}

	ctx := t.Context()
	wg := completion.NewWaitGroup(ctx)

	proxyPort, err, revertFunc := p.CreateOrUpdateRedirect(ctx, l4, "dummy-proxy-id", 1000, wg)
	require.Equal(t, uint16(0), proxyPort)
	require.Error(t, err)
	require.Nil(t, revertFunc)
}

func TestCreateOrUpdateRedirectMissingListenerWithUseOriginalSourceAddrFlagEnabled(t *testing.T) {
	testRunDir := t.TempDir()
	socketDir := envoy.GetSocketDir(testRunDir)
	err := os.MkdirAll(socketDir, 0o700)
	require.NoError(t, err)
	ipTablesManager := &iptables.Manager{}
	xdsServer := &fakeXdsServer{}
	envoyIntegrationConfig := EnvoyProxyIntegrationConfig{
		ProxyUseOriginalSourceAddress: true,
	}
	envoyIntegrationParams := envoyProxyIntegrationParams{
		IptablesManager: ipTablesManager,
		XdsServer:       xdsServer,
		Cfg:             envoyIntegrationConfig,
	}
	envoyIntegration := newEnvoyProxyIntegration(envoyIntegrationParams)
	p := proxyForTest(t, envoyIntegration)

	l4 := &fakeProxyPolicy{policy.ParserTypeHTTP}

	ctx := t.Context()
	wg := completion.NewWaitGroup(ctx)

	p.CreateOrUpdateRedirect(ctx, l4, "dummy-proxy-id", 1000, wg)
	require.True(t, envoyIntegration.proxyUseOriginalSourceAddress)
}

func TestCreateOrUpdateRedirectMissingListenerWithUseOriginalSourceAddrFlagDisabled(t *testing.T) {
	testRunDir := t.TempDir()
	socketDir := envoy.GetSocketDir(testRunDir)
	err := os.MkdirAll(socketDir, 0o700)
	require.NoError(t, err)
	ipTablesManager := &iptables.Manager{}
	xdsServer := &fakeXdsServer{}
	envoyIntegrationConfig := EnvoyProxyIntegrationConfig{
		ProxyUseOriginalSourceAddress: false,
	}
	envoyIntegrationParams := envoyProxyIntegrationParams{
		IptablesManager: ipTablesManager,
		XdsServer:       xdsServer,
		Cfg:             envoyIntegrationConfig,
	}
	envoyIntegration := newEnvoyProxyIntegration(envoyIntegrationParams)
	p := proxyForTest(t, envoyIntegration)

	l4 := &fakeProxyPolicy{policy.ParserTypeHTTP}

	ctx := t.Context()
	wg := completion.NewWaitGroup(ctx)

	p.CreateOrUpdateRedirect(ctx, l4, "dummy-proxy-id", 1000, wg)
	require.False(t, envoyIntegration.proxyUseOriginalSourceAddress)
	require.False(t, xdsServer.ObservedMayUseOriginalSourceAddr)
}

type fakeXdsServer struct {
	ObservedMayUseOriginalSourceAddr bool
}

func (r *fakeXdsServer) UpdateEnvoyResources(ctx context.Context, old envoy.Resources, new envoy.Resources) error {
	panic("unimplemented")
}

func (r *fakeXdsServer) DeleteEnvoyResources(ctx context.Context, resources envoy.Resources) error {
	panic("unimplemented")
}

func (r *fakeXdsServer) UpsertEnvoyResources(ctx context.Context, resources envoy.Resources) error {
	panic("unimplemented")
}

func (s *fakeXdsServer) AddListener(name string, kind policy.L7ParserType, port uint16, isIngress bool, mayUseOriginalSourceAddr bool, wg *completion.WaitGroup, cb func(err error)) error {
	s.ObservedMayUseOriginalSourceAddr = mayUseOriginalSourceAddr
	return nil
}

func (*fakeXdsServer) AddAdminListener(port uint16, wg *completion.WaitGroup) {
	panic("unimplemented")
}

func (*fakeXdsServer) AddMetricsListener(port uint16, wg *completion.WaitGroup) {
	panic("unimplemented")
}

func (*fakeXdsServer) GetNetworkPolicies(resourceNames []string) (map[string]*cilium.NetworkPolicy, error) {
	panic("unimplemented")
}

func (*fakeXdsServer) RemoveAllNetworkPolicies() {
	panic("unimplemented")
}

func (*fakeXdsServer) RemoveListener(name string, wg *completion.WaitGroup) xds.AckingResourceMutatorRevertFunc {
	panic("unimplemented")
}

func (*fakeXdsServer) RemoveNetworkPolicy(ep endpoint.EndpointInfoSource) {
	panic("unimplemented")
}

func (*fakeXdsServer) UpdateNetworkPolicy(ep endpoint.EndpointUpdater, policy *policy.EndpointPolicy, wg *completion.WaitGroup) (error, func() error) {
	panic("unimplemented")
}

func (*fakeXdsServer) UseCurrentNetworkPolicy(ep endpoint.EndpointUpdater, policy *policy.EndpointPolicy, wg *completion.WaitGroup) {
	panic("unimplemented")
}

func (*fakeXdsServer) GetPolicySecretSyncNamespace() string {
	panic("unimplemented")
}

func (*fakeXdsServer) SetPolicySecretSyncNamespace(string) {
	panic("unimplemented")
}

var _ envoy.XDSServer = &fakeXdsServer{}
