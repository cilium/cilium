// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package test

import (
	"context"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/models"
	apiv1 "github.com/cilium/cilium/api/v1/models"
	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/crypto/certificatemanager"
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
	"github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/promise"
	testcertificatemanager "github.com/cilium/cilium/pkg/testutils/certificatemanager"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	testipcache "github.com/cilium/cilium/pkg/testutils/ipcache"
	testmonitor "github.com/cilium/cilium/pkg/testutils/monitor"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
)

type testFixture struct {
	hive *hive.Hive

	idmgr      identitymanager.IDManager
	allocator  cache.IdentityAllocator
	epm        endpointmanager.EndpointManager
	repo       policy.PolicyRepository
	importer   policycell.PolicyImporter
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
			func(client_ *k8sClient.FakeClientset, repo_ policy.PolicyRepository, idmgr_ identitymanager.IDManager,
				alloc_ cache.IdentityAllocator,
				imp_ policycell.PolicyImporter, epm_ endpointmanager.EndpointManager) error {
				f.repo = repo_
				f.idmgr = idmgr_
				f.allocator = alloc_
				f.importer = imp_
				f.epm = epm_

				option.Config.IdentityAllocationMode = option.IdentityAllocationModeCRD
				defer func() { option.Config.IdentityAllocationMode = option.IdentityAllocationModeKVstore }()

				<-f.allocator.(*cache.CachingIdentityAllocator).InitIdentityAllocator(client_, nil)

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
						NamedPortsGetter:    testipcache.NewMockIPCache(),
						Allocator:           f.allocator,
						CTMapGC:             ctmap.NewFakeGCRunner(),
						KVStoreSynchronizer: ipcache.NewIPIdentitySynchronizer(log, kvstore.SetupDummy(t, kvstore.DisabledBackendName)),
						LocalNodeStore:      node.NewTestLocalNodeStore(node.LocalNode{}),
						LxcMap:              &fakeLXCMap{},
					},
					&fakeDNSAPI{},
					&endpoint.FakeEndpointProxy{},
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
			return ipcache.NewIPCache(&ipcache.Configuration{
				Context:           t.Context(),
				Logger:            log,
				IdentityAllocator: f.allocator,
				IdentityUpdater:   &mockUpdater{},
			})
		}),
		cell.ProvidePrivate(regeneration.NewFence),
		cell.ProvidePrivate(func() promise.Promise[endpointstate.Restorer] { return &fakeRestorer{} }),
		identitymanager.Cell,
		identitycache.Cell,
		policycell.Cell,
		endpointmanager.TestCell,
		node.LocalNodeStoreTestCell,
	)

	require.NoError(t, f.hive.Start(log, context.Background()))
	t.Cleanup(func() {
		for _, ep := range f.epm.GetEndpoints() {
			f.epm.RemoveEndpoint(ep, endpoint.DeleteConfig{})
		}
		assert.NoError(t, f.hive.Stop(log, context.TODO()))
	})

	return f
}

type fakeDNSAPI struct{}

func (*fakeDNSAPI) GetDNSRules(epID uint16) restore.DNSRules { return nil }
func (*fakeDNSAPI) RemoveRestoredDNSRules(epID uint16)       {}

type fakePolicyMapFactory struct{}

func (*fakePolicyMapFactory) OpenEndpoint(id uint16) (policymap.PolicyMap, error) {
	return fakepolicymap.NewFakePolicyMap(), nil
}
func (*fakePolicyMapFactory) RemoveEndpoint(id uint16) error { return nil }
func (*fakePolicyMapFactory) PolicyMaxEntries() int          { return 0 }
func (*fakePolicyMapFactory) StatsMaxEntries() int           { return 0 }

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
