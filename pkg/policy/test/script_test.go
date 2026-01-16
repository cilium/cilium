// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package test

import (
	"context"
	"flag"
	"log/slog"
	"maps"
	"net/netip"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/models"
	apiv1 "github.com/cilium/cilium/api/v1/models"
	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/crypto/certificatemanager"
	datapathfaketypes "github.com/cilium/cilium/pkg/datapath/fake/types"
	"github.com/cilium/cilium/pkg/datapath/loader"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/endpointmanager"
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
	testk8s "github.com/cilium/cilium/pkg/k8s/testutils"
	"github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/logging"
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
	"github.com/cilium/cilium/pkg/testutils"
	testcertificatemanager "github.com/cilium/cilium/pkg/testutils/certificatemanager"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	testipcache "github.com/cilium/cilium/pkg/testutils/ipcache"
	testmonitor "github.com/cilium/cilium/pkg/testutils/monitor"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
	"github.com/cilium/cilium/pkg/time"
)

var debug = flag.Bool("debug", false, "Enable debug logging")

func TestScript(t *testing.T) {
	defer testutils.GoleakVerifyNone(t)

	version.Force(testk8s.DefaultVersion)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	var opts []hivetest.LogOption
	if *debug {
		opts = append(opts, hivetest.LogLevel(slog.LevelDebug))
		logging.SetLogLevelToDebug()
	}

	var idmgr identitymanager.IDManager
	var allocator cache.IdentityAllocator
	var epm endpointmanager.EndpointManager
	var p policy.PolicyRepository
	var c compute.PolicyRecomputer
	var importer policycell.PolicyImporter
	var templateEP *endpoint.Endpoint
	log := hivetest.Logger(t, opts...)
	scripttest.Test(t,
		ctx,
		func(t testing.TB, args []string) *script.Engine {
			h := hive.New(
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
					func(client_ *k8sClient.FakeClientset, p_ policy.PolicyRepository, idmgr_ identitymanager.IDManager,
						alloc_ cache.IdentityAllocator, c_ compute.PolicyRecomputer,
						i_ policycell.PolicyImporter, epm_ endpointmanager.EndpointManager) error {
						p = p_
						idmgr = idmgr_
						allocator = alloc_
						c = c_
						importer = i_
						epm = epm_

						option.Config.IdentityAllocationMode = option.IdentityAllocationModeCRD
						defer func() { option.Config.IdentityAllocationMode = option.IdentityAllocationModeKVstore }()

						// Init the identity allocator.
						<-allocator.(*cache.CachingIdentityAllocator).InitIdentityAllocator(client_, nil)

						p.GetSelectorCache().SetLocalIdentityNotifier(testidentity.NewDummyIdentityNotifier())

						var err error
						templateEP, err = endpoint.NewEndpointFromChangeModel(
							context.Background(),
							log,
							&fakeDNSAPI{},
							endpoint.NewEndpointBuildQueue(),
							&datapathfaketypes.FakeLoader{},
							&datapathfaketypes.FakeOrchestrator{},
							loader.NewCompilationLock(),
							nil,
							nil,
							idmgr,
							&testmonitor.TestMonitorAgent{},
							&fakePolicyMapFactory{},
							p,
							c,
							testipcache.NewMockIPCache(),
							&endpoint.FakeEndpointProxy{},
							allocator,
							ctmap.NewFakeGCRunner(),
							ipcache.NewIPIdentitySynchronizer(log, kvstore.SetupDummy(t, kvstore.DisabledBackendName)),
							&apiv1.EndpointChangeRequest{
								ContainerID:            "foo",
								ContainerInterfaceName: "bar",
								State:                  models.NewEndpointState(models.EndpointStateWaitingDashForDashIdentity),
							},
							nil,
							nil,
							t.Output(),
							&fakeLXCMap{},
						)

						return err
					},
				),

				cell.ProvidePrivate(func() certificatemanager.CertificateManager {
					return &testcertificatemanager.Fake{}
				}),
				cell.ProvidePrivate(func() cmtypes.ClusterInfo {
					return cmtypes.DefaultClusterInfo
				}),
				cell.ProvidePrivate(func() envoypolicy.EnvoyL7RulesTranslator {
					return envoypolicy.NewEnvoyL7RulesTranslator(log, nil)
				}),
				cell.ProvidePrivate(func() types.PolicyMetrics {
					return testpolicy.NewPolicyMetricsNoop()
				}),
				cell.ProvidePrivate(func() agent.Agent {
					return &testmonitor.TestMonitorAgent{}
				}),
				cell.ProvidePrivate(func() synced.CacheStatus {
					ch := make(chan struct{}, 1)
					ch <- struct{}{}
					return ch
				}),
				cell.ProvidePrivate(func() *ipcache.IPCache {
					return ipcache.NewIPCache(&ipcache.Configuration{
						Context:           t.Context(),
						Logger:            log,
						IdentityAllocator: allocator,
						IdentityUpdater:   &mockUpdater{},
					})
				}),
				cell.ProvidePrivate(regeneration.NewFence),
				identitymanager.Cell,
				identitycache.Cell,
				policycell.Cell,
				endpointmanager.TestCell,
				node.LocalNodeStoreTestCell,

				cell.Provide(
					func(params compute.Params) compute.PolicyRecomputer {
						return compute.NewIdentityPolicyComputer(params)
					},
				),
				cell.ProvidePrivate(compute.NewPolicyComputationTable),
			)

			flags := pflag.NewFlagSet("", pflag.ContinueOnError)
			h.RegisterFlags(flags)

			t.Cleanup(func() {
				for _, ep := range epm.GetEndpoints() {
					epm.RemoveEndpoint(ep, endpoint.DeleteConfig{})
				}
				assert.NoError(t, h.Stop(log, context.TODO()))
			})
			cmds, err := h.ScriptCommands(log)
			require.NoError(t, err, "ScriptCommands")
			maps.Insert(cmds, maps.All(script.DefaultCmds()))
			maps.Insert(cmds, maps.All(compute.PolicyComputerScriptCmds(c.(*compute.IdentityPolicyComputer))))
			maps.Insert(cmds, maps.All(policy.RepositoryScriptCmds(p.(*policy.Repository))))
			maps.Insert(cmds, maps.All(identitymanager.ScriptCmds(idmgr.(*identitymanager.IdentityManager))))
			maps.Insert(cmds, maps.All(cache.ScriptCmds(allocator.(*cache.CachingIdentityAllocator))))
			maps.Insert(cmds, maps.All(policycell.PolicyImporterScriptCmds(importer.(*policycell.Importer))))
			maps.Insert(cmds, maps.All(endpointmanager.ScriptCmds(epm, templateEP)))
			return &script.Engine{
				Cmds:          cmds,
				RetryInterval: 10 * time.Millisecond,
			}
		}, []string{}, "testdata/*.txtar")
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
