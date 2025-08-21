// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package test

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"maps"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/crypto/certificatemanager"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/endpointmanager"
	envoypolicy "github.com/cilium/cilium/pkg/envoy/policy"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/identity/cache"
	identitycache "github.com/cilium/cilium/pkg/identity/cache/cell"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/ipcache"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/testutils"
	"github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/monitor/agent"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	policycell "github.com/cilium/cilium/pkg/policy/cell"
	"github.com/cilium/cilium/pkg/policy/compute"
	"github.com/cilium/cilium/pkg/policy/types"
	testcertificatemanager "github.com/cilium/cilium/pkg/testutils/certificatemanager"
	testendpointmanager "github.com/cilium/cilium/pkg/testutils/endpointmanager"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	testipcache "github.com/cilium/cilium/pkg/testutils/ipcache"
	testmonitor "github.com/cilium/cilium/pkg/testutils/monitor"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
	"github.com/cilium/cilium/pkg/time"
)

var debug = flag.Bool("debug", false, "Enable debug logging")

func TestScript(t *testing.T) {
	defer goleak.VerifyNone(t)

	version.Force(testutils.DefaultVersion)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	var opts []hivetest.LogOption
	if *debug {
		opts = append(opts, hivetest.LogLevel(slog.LevelDebug))
		logging.SetLogLevelToDebug()
	}

	var idmgr identitymanager.IDManager
	var allocator cache.IdentityAllocator
	var p policy.PolicyRepository
	var c compute.PolicyRecomputer
	var importer policycell.PolicyImporter
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
						i_ policycell.PolicyImporter) error {
						p = p_
						idmgr = idmgr_
						allocator = alloc_
						c = c_
						importer = i_

						option.Config.IdentityAllocationMode = option.IdentityAllocationModeCRD
						defer func() { option.Config.IdentityAllocationMode = option.IdentityAllocationModeKVstore }()

						// Init the identity allocator.
						<-allocator.(*cache.CachingIdentityAllocator).InitIdentityAllocator(client_, nil)

						p.GetSelectorCache().SetLocalIdentityNotifier(testidentity.NewDummyIdentityNotifier())

						return nil
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
				cell.ProvidePrivate(func() endpointmanager.EndpointManager {
					return &testendpointmanager.TestEndpointManager{}
				}),
				cell.ProvidePrivate(func() agent.Agent {
					return &testmonitor.TestMonitorAgent{}
				}),
				cell.ProvidePrivate(func() synced.CacheStatus {
					ch := make(chan struct{}, 1)
					ch <- struct{}{}
					return ch
				}),
				cell.ProvidePrivate(func() ipcache.MetadataBatchAPI {
					return testipcache.NewMockIPCache()
				}),
				cell.ProvidePrivate(regeneration.NewFence),
				identitymanager.Cell,
				identitycache.Cell,
				policycell.Cell,

				cell.Provide(
					func(params compute.Params) compute.PolicyRecomputer {
						return compute.NewIdentityPolicyRecomputer(params)
					},
				),
				cell.ProvidePrivate(compute.NewPolicyComputationTable),
			)

			flags := pflag.NewFlagSet("", pflag.ContinueOnError)
			h.RegisterFlags(flags)

			t.Cleanup(func() {
				assert.NoError(t, h.Stop(log, context.TODO()))
			})
			cmds, err := h.ScriptCommands(log)
			require.NoError(t, err, "ScriptCommands")
			maps.Insert(cmds, maps.All(script.DefaultCmds()))
			maps.Insert(cmds, maps.All(policy.RepositoryScriptCmds(p.(*policy.Repository))))
			maps.Insert(cmds, maps.All(identitymanager.ScriptCmds(idmgr.(*identitymanager.IdentityManager))))
			maps.Insert(cmds, maps.All(cache.ScriptCmds(allocator.(*cache.CachingIdentityAllocator))))
			maps.Insert(cmds, maps.All(policycell.PolicyImporterScriptCmds(importer.(*policycell.Importer))))
			fmt.Println(c)
			return &script.Engine{
				Cmds:          cmds,
				RetryInterval: 10 * time.Millisecond,
			}
		}, []string{}, "testdata/*.txtar")
}
