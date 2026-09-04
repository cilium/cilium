// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package test

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/models"
	apiv1 "github.com/cilium/cilium/api/v1/models"
	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/crypto/certificatemanager"
	fakeiptables "github.com/cilium/cilium/pkg/datapath/iptables/fake"
	"github.com/cilium/cilium/pkg/datapath/loader"
	fakeloader "github.com/cilium/cilium/pkg/datapath/loader/fake"
	"github.com/cilium/cilium/pkg/endpoint"
	fakeendpoint "github.com/cilium/cilium/pkg/endpoint/fake"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/endpointstate"
	envoypolicy "github.com/cilium/cilium/pkg/envoy/policy"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	identitycache "github.com/cilium/cilium/pkg/identity/cache/cell"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/ipcache"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	fakepolicymap "github.com/cilium/cilium/pkg/maps/policymap/fake"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/monitor/agent"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	policycell "github.com/cilium/cilium/pkg/policy/cell"
	"github.com/cilium/cilium/pkg/policy/compute"
	"github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/proxy/proxyports"
	proxytypes "github.com/cilium/cilium/pkg/proxy/types"
	"github.com/cilium/cilium/pkg/revert"
	testcertificatemanager "github.com/cilium/cilium/pkg/testutils/certificatemanager"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	testmonitor "github.com/cilium/cilium/pkg/testutils/monitor"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
)

type testFixture struct {
	hive *hive.Hive

	idmgr      identitymanager.IDManager
	allocator  cache.IdentityAllocator
	epm        endpointmanager.EndpointManager
	repo       policy.PolicyRepository
	computer   compute.PolicyRecomputer
	importer   policycell.PolicyImporter
	ipcache    *ipcache.IPCache
	templateEP *endpoint.Endpoint
}

func newTestFixture(t testing.TB, log *slog.Logger, certMgr certificatemanager.CertificateManager) *testFixture {
	if certMgr == nil {
		certMgr = &testcertificatemanager.Fake{}
	}

	f := &testFixture{}

	f.hive = hive.New(
		k8sClient.FakeClientCell(),
		daemonk8s.ResourcesCell,
		metrics.Cell,

		cell.Provide(
			func() *option.DaemonConfig {
				return &option.DaemonConfig{
					EnableIPv4: true,
					EnableIPv6: true,
				}
			},
		),

		cell.Invoke(
			func(client *k8sClient.FakeClientset, repo policy.PolicyRepository, idmgr identitymanager.IDManager,
				alloc cache.IdentityAllocator, comp compute.PolicyRecomputer,
				imp policycell.PolicyImporter, epm endpointmanager.EndpointManager) error {
				f.repo = repo
				f.idmgr = idmgr
				f.allocator = alloc
				f.computer = comp
				f.importer = imp
				f.epm = epm

				option.Config.IdentityAllocationMode = option.IdentityAllocationModeCRD

				<-f.allocator.(*cache.CachingIdentityAllocator).InitIdentityAllocator(client, nil)

				f.repo.GetSelectorCache().SetLocalIdentityNotifier(testidentity.NewDummyIdentityNotifier())

				var err error
				f.templateEP, err = endpoint.NewEndpointFromChangeModel(
					endpoint.EndpointParams{
						Logger:              log,
						EPBuildQueue:        endpoint.NewEndpointBuildQueue(),
						Loader:              &fakeloader.Loader{},
						Orchestrator:        &fakeendpoint.FakeOrchestrator{},
						CompilationLock:     loader.NewCompilationLock(),
						IdentityManager:     f.idmgr,
						MonitorAgent:        &testmonitor.TestMonitorAgent{},
						PolicyMapFactory:    &fakePolicyMapFactory{},
						PolicyRepo:          f.repo,
						PolicyFetcher:       f.computer,
						Allocator:           f.allocator,
						CTMapGC:             ctmap.NewFakeGCRunner(),
						KVStoreSynchronizer: ipcache.NewIPIdentitySynchronizer(log, kvstore.SetupDummy(t, kvstore.DisabledBackendName)),
						LocalNodeStore:      node.NewTestLocalNodeStore(node.LocalNode{}),
						LxcMap:              &fakeLXCMap{},
					},
					&fakeDNSAPI{},
					newTestProxy(t, log),
					&apiv1.EndpointChangeRequest{
						ContainerID:            "foo",
						ContainerInterfaceName: "bar",
						State:                  models.NewEndpointState(models.EndpointStateWaitingDashForDashIdentity),
					},
					t.Output(),
				)
				return err
			},
		),

		cell.ProvidePrivate(func() certificatemanager.CertificateManager { return certMgr }),
		cell.ProvidePrivate(func() cmtypes.ClusterInfo { return cmtypes.DefaultClusterInfo }),
		cell.ProvidePrivate(func() envoypolicy.EnvoyL7RulesTranslator {
			return envoypolicy.NewEnvoyL7RulesTranslator(log, nil)
		}),
		cell.ProvidePrivate(func() types.PolicyMetrics { return testpolicy.NewPolicyMetricsNoop() }),
		cell.ProvidePrivate(func() agent.Agent { return &testmonitor.TestMonitorAgent{} }),
		cell.ProvidePrivate(func() synced.CacheStatus {
			ch := make(chan struct{}, 1)
			ch <- struct{}{}
			return ch
		}),
		cell.ProvidePrivate(func() *ipcache.IPCache {
			f.ipcache = ipcache.NewIPCache(&ipcache.Configuration{
				Context:           t.Context(),
				Logger:            log,
				IdentityAllocator: f.allocator,
				IdentityUpdater:   &mockUpdater{},
			})
			return f.ipcache
		}),
		cell.ProvidePrivate(regeneration.NewFence),
		cell.ProvidePrivate(func() promise.Promise[endpointstate.Restorer] { return &fakeRestorer{} }),
		identitymanager.Cell,
		identitycache.Cell,
		policycell.Cell,
		endpointmanager.TestCell,
		node.LocalNodeStoreTestCell,

		cell.Provide(func(params compute.Params) compute.PolicyRecomputer {
			return compute.NewIdentityPolicyComputer(params)
		}),
		cell.ProvidePrivate(compute.NewPolicyComputationTable),
	)

	require.NoError(t, f.hive.Start(log, context.Background()))
	t.Cleanup(func() {
		for _, ep := range f.epm.GetEndpoints() {
			f.epm.RemoveEndpoint(ep, endpoint.DeleteConfig{})
		}
		assert.NoError(t, f.hive.Stop(log, context.TODO()))
		// The fixture builds the IPCache directly rather than through its cell,
		// so the ipcache-inject-labels controller is not reaped by hive.Stop.
		// Mirror the cell's OnStop hook so it does not leak across test runs.
		assert.NoError(t, f.ipcache.Shutdown())
	})

	return f
}

// staticProxyPorts pins each proxy port so a golden file can name it.
var staticProxyPorts = []struct {
	name      string
	proxyType proxytypes.ProxyType
	ingress   bool
	port      uint16
}{
	{proxytypes.DNSProxyName, proxytypes.ProxyTypeDNS, false, 19002},
	{"cilium-http-ingress", proxytypes.ProxyTypeHTTP, true, 19001},
	{"cilium-http-egress", proxytypes.ProxyTypeHTTP, false, 19003},
}

// newTestProxy returns a proxy that resolves redirects through the real
// ProxyPorts allocator, the way the agent does once a proxy has registered
// the port it bound.
func newTestProxy(t testing.TB, log *slog.Logger) *testProxy {
	ports := proxyports.NewProxyPorts(log, proxyports.ProxyPortsConfig{}, fakeiptables.NewManager())
	// ackProxyPort fires this trigger. Nothing consumes it, so the ports file
	// is never written.
	ports.Trigger = job.NewTrigger()

	for _, pp := range staticProxyPorts {
		require.NoError(t, ports.SetProxyPort(pp.name, pp.proxyType, pp.port, pp.ingress))
	}

	return &testProxy{ports: ports}
}

// testProxy implements endpoint.EndpointProxy far enough to realize redirects.
type testProxy struct {
	endpoint.FakeEndpointProxy

	ports *proxyports.ProxyPorts
}

// CreateOrUpdateRedirect fails for a parser with no port configured, the way
// the real proxy does, instead of inventing one.
func (p *testProxy) CreateOrUpdateRedirect(ctx context.Context, l4 policy.ProxyPolicy, id string, epID uint16, wg *completion.WaitGroup) (uint16, error, revert.RevertFunc) {
	parser := proxytypes.ProxyType(l4.GetL7Parser())
	name, pp := p.ports.FindByTypeWithReference(parser, l4.GetListener(), l4.GetIngress())
	if pp == nil {
		return 0, fmt.Errorf("no proxy port for %s listener %q", parser, l4.GetListener()), nil
	}
	if err := p.ports.AckProxyPort(ctx, name, pp); err != nil {
		return 0, err, nil
	}
	// FindByTypeWithReference took a reference. The real proxy releases it from
	// the revert func, so do the same or the refcount grows every regeneration.
	return pp.ProxyPort, nil, func() error {
		p.ports.ReleaseProxyPort(name)
		return nil
	}
}

type fakeDNSAPI struct{}

func (*fakeDNSAPI) GetDNSRules(epID uint16) restore.DNSRules { return nil }
func (*fakeDNSAPI) RemoveRestoredDNSRules(epID uint16)       {}

type fakePolicyMapFactory struct{}

func (*fakePolicyMapFactory) OpenEndpoint(id uint16) (policymap.PolicyMap, error) {
	return fakepolicymap.NewFakePolicyMap(), nil
}
func (*fakePolicyMapFactory) RemoveEndpoint(id uint16) error      { return nil }
func (*fakePolicyMapFactory) RemoveGlobalMapping(id uint32) error { return nil }
func (*fakePolicyMapFactory) PolicyMaxEntries() int               { return 0 }
func (*fakePolicyMapFactory) StatsMaxEntries() int                { return 0 }

type fakeLXCMap struct{}

func (*fakeLXCMap) WriteEndpoint(f lxcmap.EndpointFrontend) error                        { return nil }
func (*fakeLXCMap) SyncHostEntry(addr netip.Addr) (bool, error)                          { return false, nil }
func (*fakeLXCMap) DeleteEntry(addr netip.Addr) error                                    { return nil }
func (*fakeLXCMap) DeleteElement(logger *slog.Logger, f lxcmap.EndpointFrontend) []error { return nil }
func (*fakeLXCMap) Dump(hash map[string][]string) error                                  { return nil }
func (*fakeLXCMap) DumpToMap() (map[netip.Addr]lxcmap.EndpointInfo, error)               { return nil, nil }

type mockUpdater struct{}

func (m *mockUpdater) UpdateIdentities(_, _ identity.IdentityMap) <-chan struct{} {
	out := make(chan struct{})
	close(out)
	return out
}

type fakeRestorer struct{}

func (r *fakeRestorer) Await(context.Context) (endpointstate.Restorer, error) {
	return r, nil
}

func (r *fakeRestorer) WaitForEndpointRestoreWithoutRegeneration(_ context.Context) error {
	return nil
}

func (r *fakeRestorer) WaitForEndpointRestore(_ context.Context) error {
	return nil
}

func (r *fakeRestorer) WaitForInitialPolicy(_ context.Context) error {
	return nil
}
