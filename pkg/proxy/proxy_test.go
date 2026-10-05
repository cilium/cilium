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
	statedbReconciler "github.com/cilium/statedb/reconciler"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/completion"
	iptables "github.com/cilium/cilium/pkg/datapath/iptables/fake"
	"github.com/cilium/cilium/pkg/datapath/linux/route/reconciler"
	fqdnendpoint "github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/envoy"
	util "github.com/cilium/cilium/pkg/envoy/util"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/endpoint"
	"github.com/cilium/cilium/pkg/proxy/proxyports"
	"github.com/cilium/cilium/pkg/revert"
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
	fakeIPTablesManager := iptables.NewManager()
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
	socketDir := util.GetSocketDir(testRunDir)
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
	socketDir := util.GetSocketDir(testRunDir)
	err := os.MkdirAll(socketDir, 0o700)
	require.NoError(t, err)
	xdsServer := &fakeXdsServer{}
	envoyIntegrationConfig := EnvoyProxyIntegrationConfig{
		ProxyUseOriginalSourceAddress: true,
	}
	envoyIntegrationParams := envoyProxyIntegrationParams{
		IptablesManager: iptables.NewManager(),
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
	socketDir := util.GetSocketDir(testRunDir)
	err := os.MkdirAll(socketDir, 0o700)
	require.NoError(t, err)
	xdsServer := &fakeXdsServer{}
	envoyIntegrationConfig := EnvoyProxyIntegrationConfig{
		ProxyUseOriginalSourceAddress: false,
	}
	envoyIntegrationParams := envoyProxyIntegrationParams{
		IptablesManager: iptables.NewManager(),
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

func (r *fakeXdsServer) UpdateEnvoyResources(ctx context.Context, old xds.Resources, new xds.Resources, waitGroup *completion.WaitGroup) error {
	panic("unimplemented")
}

func (r *fakeXdsServer) DeleteEnvoyResources(ctx context.Context, resources xds.Resources, waitGroup *completion.WaitGroup) error {
	panic("unimplemented")
}

func (r *fakeXdsServer) UpsertEnvoyResources(ctx context.Context, resources xds.Resources, waitGroup *completion.WaitGroup) error {
	panic("unimplemented")
}

func (s *fakeXdsServer) AddListener(ctx context.Context, name string, kind policy.L7ParserType, port uint16, isIngress bool, mayUseOriginalSourceAddr bool, wg *completion.WaitGroup, cb func(err error)) error {
	s.ObservedMayUseOriginalSourceAddr = mayUseOriginalSourceAddr
	return nil
}

func (*fakeXdsServer) AddAdminListener(ctx context.Context, port uint16, wg *completion.WaitGroup) {
	panic("unimplemented")
}

func (*fakeXdsServer) AddMetricsListener(ctx context.Context, port uint16, wg *completion.WaitGroup) {
	panic("unimplemented")
}

func (*fakeXdsServer) RemoveAllNetworkPolicies() {
	panic("unimplemented")
}

func (*fakeXdsServer) RemoveListener(ctx context.Context, name string, wg *completion.WaitGroup) xds.AckingResourceMutatorRevertFunc {
	panic("unimplemented")
}

func (*fakeXdsServer) RemoveNetworkPolicy(ctx context.Context, ep endpoint.EndpointInfoSource) {
	panic("unimplemented")
}

func (*fakeXdsServer) UpdateNetworkPolicy(ctx context.Context, ep endpoint.EndpointUpdater, policy *policy.EndpointPolicy, wg *completion.WaitGroup) (error, revert.Revertible) {
	panic("unimplemented")
}

func (*fakeXdsServer) GetPolicySecretSyncNamespace() string {
	panic("unimplemented")
}

func (*fakeXdsServer) SetPolicySecretSyncNamespace(string) {
	panic("unimplemented")
}

var _ envoy.XDSServer = &fakeXdsServer{}

// fakeDNSProxier is a no-op DNSProxier so a DNS redirect can be driven past the
// readiness barrier in unit tests without a real proxy.
type fakeDNSProxier struct{}

func (fakeDNSProxier) GetRules(uint16) (restore.DNSRules, error) { return nil, nil }
func (fakeDNSProxier) RemoveRestoredRules(uint16)                {}
func (fakeDNSProxier) UpdateAllowed(uint64, restore.PortProto, policy.L7DataMap) (revert.RevertFunc, error) {
	return func() error { return nil }, nil
}
func (fakeDNSProxier) GetBindPort() uint16                 { return 0 }
func (fakeDNSProxier) RestoreRules(*fqdnendpoint.Endpoint) {}
func (fakeDNSProxier) Cleanup()                            {}
func (fakeDNSProxier) Listen(uint16) error                 { return nil }

func dnsProxyForTest(t *testing.T) *Proxy {
	p := proxyForTest(t, nil)
	p.dnsIntegration = &dnsProxyIntegration{dnsProxy: fakeDNSProxier{}}
	return p
}

// A DNS redirect must not be created until the DNS proxy signals ready; once
// signalled, the call proceeds.
func TestCreateOrUpdateRedirectWaitsForDNSProxyReady(t *testing.T) {
	p := dnsProxyForTest(t)
	l4 := &fakeProxyPolicy{policy.ParserTypeDNS}

	ctx := t.Context()
	wg := completion.NewWaitGroup(ctx)

	done := make(chan struct{})
	go func() {
		defer close(done)
		p.CreateOrUpdateRedirect(ctx, l4, "dns-proxy-id", 1000, wg)
	}()

	// Must still be blocked on the readiness barrier.
	select {
	case <-done:
		require.Fail(t, "CreateOrUpdateRedirect returned before DNS proxy was ready")
	case <-time.After(100 * time.Millisecond):
	}

	p.proxyPorts.SignalDNSProxyReady()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		require.Fail(t, "CreateOrUpdateRedirect did not return after DNS proxy became ready")
	}
}

// A DNS redirect waiting on readiness returns ctx.Err() when the context is
// cancelled, rather than hanging.
func TestCreateOrUpdateRedirectDNSReadyCtxCancel(t *testing.T) {
	p := dnsProxyForTest(t)
	l4 := &fakeProxyPolicy{policy.ParserTypeDNS}

	ctx, cancel := context.WithCancel(t.Context())
	wg := completion.NewWaitGroup(ctx)

	type result struct {
		port uint16
		err  error
	}
	res := make(chan result, 1)
	go func() {
		port, err, _ := p.CreateOrUpdateRedirect(ctx, l4, "dns-proxy-id", 1000, wg)
		res <- result{port, err}
	}()

	select {
	case <-res:
		require.Fail(t, "CreateOrUpdateRedirect returned before context cancellation")
	case <-time.After(100 * time.Millisecond):
	}

	cancel()

	select {
	case r := <-res:
		require.Equal(t, uint16(0), r.port)
		require.ErrorIs(t, r.err, context.Canceled)
	case <-time.After(5 * time.Second):
		require.Fail(t, "CreateOrUpdateRedirect did not return after context cancellation")
	}
}

// A non-DNS redirect is not gated by DNS proxy readiness and returns without
// waiting even though the signal was never sent.
func TestCreateOrUpdateRedirectNonDNSNotGated(t *testing.T) {
	p := proxyForTest(t, nil)
	l4 := &fakeProxyPolicy{policy.ParserTypeCRD}

	ctx := t.Context()
	wg := completion.NewWaitGroup(ctx)

	done := make(chan struct{})
	go func() {
		defer close(done)
		p.CreateOrUpdateRedirect(ctx, l4, "crd-proxy-id", 1000, wg)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		require.Fail(t, "non-DNS CreateOrUpdateRedirect blocked on DNS proxy readiness")
	}
}
