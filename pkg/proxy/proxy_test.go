// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxy

import (
	"context"
	"errors"
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
	"github.com/cilium/cilium/pkg/envoy"
	util "github.com/cilium/cilium/pkg/envoy/util"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/endpoint"
	"github.com/cilium/cilium/pkg/proxy/proxyports"
	"github.com/cilium/cilium/pkg/revert"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/u8proto"
)

type recordingProxyDatapath struct {
	*iptables.Manager
	rules map[string]uint16
}

func (d *recordingProxyDatapath) InstallProxyRules(port uint16, name string) {
	d.rules[name] = port
}

func (d *recordingProxyDatapath) GetProxyPorts() map[string]uint16 { return d.rules }

func proxyForTest(t *testing.T, envoyIntegration *envoyProxyIntegration) (*Proxy, *recordingProxyDatapath) {
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
	datapath := &recordingProxyDatapath{Manager: iptables.NewManager(), rules: make(map[string]uint16)}
	ppConfig := proxyports.ProxyPortsConfig{
		ProxyPortrangeMin:          10000,
		ProxyPortrangeMax:          20000,
		RestoredProxyPortsAgeLimit: 0,
	}
	pp := proxyports.NewProxyPorts(hivetest.Logger(t), ppConfig, datapath)
	p, err := createProxy(true, hivetest.Logger(t), nil, pp, envoyIntegration, nil, nil, nil, drm)
	require.NoError(t, err)

	p.proxyPorts.Trigger = job.NewTrigger(job.WithDebounce(10 * time.Second))
	return p, datapath
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

	p, _ := proxyForTest(t, nil)

	l4 := &fakeProxyPolicy{policy.ParserTypeCRD}

	ctx := t.Context()
	wg := completion.NewWaitGroup(ctx)
	defer wg.Cancel()

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
	p, _ := proxyForTest(t, envoyIntegration)

	l4 := &fakeProxyPolicy{policy.ParserTypeHTTP}

	ctx := t.Context()
	wg := completion.NewWaitGroup(ctx)
	defer wg.Cancel()

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
	p, _ := proxyForTest(t, envoyIntegration)

	l4 := &fakeProxyPolicy{policy.ParserTypeHTTP}

	ctx := t.Context()
	wg := completion.NewWaitGroup(ctx)
	defer wg.Cancel()

	p.CreateOrUpdateRedirect(ctx, l4, "dummy-proxy-id", 1000, wg)
	require.False(t, envoyIntegration.proxyUseOriginalSourceAddress)
	require.False(t, xdsServer.ObservedMayUseOriginalSourceAddr)
}

func TestProxyPortSettlement(t *testing.T) {
	nack := errors.New("listener rejected")
	for _, tt := range []struct {
		name       string
		firstError error
		lastError  error
		earlyError bool
		syncError  bool
		cecOwned   bool
	}{
		{name: "both-ack"},
		{name: "first-nack", firstError: nack},
		{name: "first-canceled", firstError: context.Canceled},
		{name: "early-error", firstError: context.Canceled, earlyError: true},
		{name: "last-nack", lastError: nack},
		{name: "both-nack", firstError: nack, lastError: nack},
		{name: "both-canceled", firstError: context.Canceled, lastError: context.Canceled},
		{name: "synchronous-error", syncError: true},
		{name: "cec-owned", cecOwned: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := &fakeXdsServer{}
			integration := &envoyProxyIntegration{xdsServer: server, iptablesManager: iptables.NewManager()}
			p, datapath := proxyForTest(t, integration)
			l4 := &fakeProxyPolicy{parserType: policy.ParserTypeHTTP}
			portName := "cilium-http-egress"
			if tt.cecOwned {
				l4.parserType = policy.ParserTypeCRD
				portName = l4.GetListener()
				_, err := p.proxyPorts.AllocateCRDProxyPort(portName)
				require.NoError(t, err)
			}
			if tt.syncError {
				server.addListenerErr = nack
				wg := completion.NewWaitGroup(t.Context())
				defer wg.Cancel()
				port, err, rollback := p.CreateOrUpdateRedirect(t.Context(), l4, "failed", 100, wg)
				require.ErrorIs(t, err, nack)
				require.Zero(t, port)
				require.Nil(t, rollback)
				allocated, _, err := p.proxyPorts.GetProxyPort(portName)
				require.NoError(t, err)
				require.Zero(t, allocated)
				require.Empty(t, server.listeners)
				require.Empty(t, datapath.rules)
				return
			}

			ids := []string{"first", "last"}
			var waits [2]*completion.WaitGroup
			var cancels [2]context.CancelFunc
			var rollbacks [2]revert.RevertFunc
			var ports [2]uint16
			for i, id := range ids {
				ctx, cancel := context.WithCancel(t.Context())
				cancels[i] = cancel
				t.Cleanup(cancel)
				waits[i] = completion.NewWaitGroup(ctx)
				t.Cleanup(waits[i].Cancel)
				var err error
				ports[i], err, rollbacks[i] = p.CreateOrUpdateRedirect(t.Context(), l4, id, uint16(100+i), waits[i])
				require.NoError(t, err)
				require.NotZero(t, ports[i])
			}
			require.Equal(t, ports[0], ports[1], "both endpoints must share one listener allocation")
			require.Empty(t, datapath.rules)
			accepted := false
			for i, cause := range []error{tt.firstError, tt.lastError} {
				if errors.Is(cause, context.Canceled) {
					// This also covers early failures which drain the group before
					// reaching the ordinary regeneration wait.
					if tt.earlyError {
						waits[i].Cancel()
					} else {
						cancels[i]()
						require.ErrorIs(t, waits[i].Wait(), cause)
					}
				} else {
					if !tt.cecOwned {
						server.completions[i].Complete(cause)
					}
					require.ErrorIs(t, waits[i].Wait(), cause)
				}
				if !accepted {
					require.Empty(t, datapath.rules, "an ACK must not install rules before post-Wait settlement")
				}
				if cause != nil {
					require.NoError(t, rollbacks[i]())
				} else {
					require.NoError(t, p.AckRedirects(t.Context(), map[string]uint16{ids[i]: ports[i]}))
					require.NoError(t, p.AckRedirects(t.Context(), map[string]uint16{ids[i]: ports[i]}), "settlement is idempotent")
					accepted = !tt.cecOwned
				}
				allocated, _, err := p.proxyPorts.GetProxyPort(portName)
				require.NoError(t, err)
				if i == 1 && !accepted && !tt.cecOwned {
					require.Zero(t, allocated, "the final failed reference must reset the allocation")
					require.Empty(t, server.listeners)
				} else {
					require.Equal(t, ports[i], allocated, "another endpoint still owns this allocation")
				}
				if accepted {
					require.Equal(t, map[string]uint16{portName: ports[i]}, datapath.rules)
				} else {
					require.Empty(t, datapath.rules)
				}
			}
		})
	}
}

type fakeXdsServer struct {
	ObservedMayUseOriginalSourceAddr bool
	completions                      []*completion.Completion
	listeners                        map[string]int
	addListenerErr                   error
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

func (s *fakeXdsServer) AddListener(ctx context.Context, name string, kind policy.L7ParserType, port uint16, isIngress bool, mayUseOriginalSourceAddr bool, wg *completion.WaitGroup) error {
	s.ObservedMayUseOriginalSourceAddr = mayUseOriginalSourceAddr
	if s.addListenerErr != nil {
		return s.addListenerErr
	}
	if s.listeners == nil {
		s.listeners = make(map[string]int)
	}
	s.listeners[name]++
	if wg != nil {
		s.completions = append(s.completions, wg.AddCompletionWithCallback(nil, nil))
	}
	return nil
}

func (*fakeXdsServer) AddAdminListener(ctx context.Context, port uint16, wg *completion.WaitGroup) {
	panic("unimplemented")
}

func (*fakeXdsServer) AddMetricsListener(ctx context.Context, port uint16, wg *completion.WaitGroup) {
	panic("unimplemented")
}

func (s *fakeXdsServer) RemoveListener(ctx context.Context, name string, wg *completion.WaitGroup) {
	s.listeners[name]--
	if s.listeners[name] == 0 {
		delete(s.listeners, name)
	}
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
