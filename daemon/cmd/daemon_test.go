// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	statedbReconciler "github.com/cilium/statedb/reconciler"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/api/v1/server"
	cnicell "github.com/cilium/cilium/daemon/cmd/cni"
	fakecni "github.com/cilium/cilium/daemon/cmd/cni/fake"
	"github.com/cilium/cilium/daemon/cmd/legacy"
	"github.com/cilium/cilium/pkg/controller"
	fakeDatapath "github.com/cilium/cilium/pkg/datapath/fake"
	"github.com/cilium/cilium/pkg/datapath/linux/route/reconciler"
	"github.com/cilium/cilium/pkg/datapath/neighbor"
	"github.com/cilium/cilium/pkg/datapath/prefilter"
	"github.com/cilium/cilium/pkg/dial"
	endpointapi "github.com/cilium/cilium/pkg/endpoint/api"
	endpointcreator "github.com/cilium/cilium/pkg/endpoint/creator"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/hive"
	identitycell "github.com/cilium/cilium/pkg/identity/cache/cell"
	"github.com/cilium/cilium/pkg/ipam"
	ipcachetypes "github.com/cilium/cilium/pkg/ipcache/types"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	k8sFakeClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	k8sSynced "github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/maps/subnet"
	"github.com/cilium/cilium/pkg/metrics"
	monitorAgent "github.com/cilium/cilium/pkg/monitor/agent"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	policyAPI "github.com/cilium/cilium/pkg/policy/api"
	policycell "github.com/cilium/cilium/pkg/policy/cell"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
	policyUtils "github.com/cilium/cilium/pkg/policy/utils"
	"github.com/cilium/cilium/pkg/testutils"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
)

type DaemonSuite struct {
	hive *hive.Hive
	log  *slog.Logger

	// oldPolicyEnabled is the policy enforcement mode that was set before the test,
	// as returned by policy.GetPolicyEnabled().
	oldPolicyEnabled string

	identityAllocator  identitycell.CachingIdentityAllocator
	policyRepository   policy.PolicyRepository
	PolicyImporter     policycell.PolicyImporter
	envoyXdsServer     envoy.XDSServer
	endpointManager    endpointmanager.EndpointManager
	endpointAPIManager endpointapi.EndpointAPIManager
	endpointCreator    endpointcreator.EndpointCreator
	ipamManager        *ipam.IPAM
}

func setupTestDirectories() string {
	tempRunDir, err := os.MkdirTemp("", "cilium-test-run")
	if err != nil {
		panic("TempDir() failed.")
	}

	err = os.Mkdir(filepath.Join(tempRunDir, "globals"), 0o777)
	if err != nil {
		panic("Mkdir failed")
	}

	socketDir := envoy.GetSocketDir(tempRunDir)
	err = os.MkdirAll(socketDir, 0o700)
	if err != nil {
		panic("creating envoy socket directory failed")
	}

	return tempRunDir
}

func TestMain(m *testing.M) {
	if !testutils.IntegrationTests() {
		// Immediately run the test suite without manipulating the environment
		// if integration tests are not requested.
		os.Exit(m.Run())
	}

	time.Local = time.UTC

	os.Exit(m.Run())
}

func setupDaemonEtcdSuite(tb testing.TB) *DaemonSuite {
	testutils.IntegrationTest(tb)

	client := kvstore.SetupDummy(tb, kvstore.EtcdBackendName)

	ds := &DaemonSuite{
		log: hivetest.Logger(tb),
	}
	ctx := context.Background()

	ds.oldPolicyEnabled = policy.GetPolicyEnabled()
	policy.SetPolicyEnabled(option.DefaultEnforcement)

	ds.hive = hive.New(
		cell.Provide(
			func() (_ statedbReconciler.Reconciler[*reconciler.DesiredRoute]) {
				return nil
			},
			func(log *slog.Logger) (k8sClient.Clientset, k8sClient.Config) {
				cs, _ := k8sFakeClient.NewFakeClientset(log)
				cs.Disable()
				return cs, cs.Config()
			},
			func() kvstore.Config { return kvstore.Config{KVStore: kvstore.EtcdBackendName} },
			func() kvstore.Client { return client },
			func() cnicell.CNIConfigManager { return &fakecni.FakeCNIConfigManager{} },
			func() ctmap.GCRunner { return ctmap.NewFakeGCRunner() },
			func() policymap.Factory { return nil },
			k8sSynced.RejectedCRDSyncPromise,
			func() *loadbalancer.TestConfig {
				return &loadbalancer.TestConfig{}
			},
			func() *server.Server { return nil },
			func() statedb.RWTable[subnet.SubnetTableEntry] {
				return nil
			},
		),
		fakeDatapath.Cell,
		neighbor.ForwardableIPCell,
		reconciler.TableCell,
		cell.Provide(neighbor.NewCommonTestConfig(true, false)),
		prefilter.Cell,
		monitorAgent.Cell,
		dial.ServiceResolverCell,
		ControlPlane,
		metrics.Cell,
		store.Cell,
		cell.Invoke(func(legacy.DaemonInitialization) {
			// with dry-run enabled it's enough to depend on DaemonInitialization
		}),
		cell.Invoke(func(pi policycell.PolicyImporter) {
			ds.PolicyImporter = pi
		}),
		cell.Invoke(func(envoyXdsServer envoy.XDSServer) {
			ds.envoyXdsServer = envoyXdsServer
		}),
		cell.Invoke(func(endpointAPIManager endpointapi.EndpointAPIManager) {
			ds.endpointAPIManager = endpointAPIManager
		}),
		cell.Invoke(func(identityAllocator identitycell.CachingIdentityAllocator) {
			ds.identityAllocator = identityAllocator
		}),
		cell.Invoke(func(policyRepository policy.PolicyRepository) {
			ds.policyRepository = policyRepository
		}),
		cell.Invoke(func(endpointCreator endpointcreator.EndpointCreator) {
			ds.endpointCreator = endpointCreator
		}),
		cell.Invoke(func(ipamManager *ipam.IPAM) {
			ds.ipamManager = ipamManager
		}),
		cell.Invoke(func(endpointManager endpointmanager.EndpointManager) {
			ds.endpointManager = endpointManager
		}),
	)

	// bootstrap global config
	ds.setupConfigOptions()

	// create temporary test directories and update global config accordingly
	testRunDir := setupTestDirectories()
	option.Config.RunDir = testRunDir
	option.Config.StateDir = testRunDir

	err := ds.hive.Start(ds.log, ctx)
	require.NoError(tb, err)

	ds.policyRepository.GetSelectorCache().SetLocalIdentityNotifier(testidentity.NewDummyIdentityNotifier())

	// Ensure that the identity allocator is synchronized before starting the
	// actual tests, to prevent flakes caused by the goroutine started by
	// [(*CachingIdentityAllocator).InitIdentityAllocator] still lingering
	// around when the Hive gets stopped.
	ds.identityAllocator.WaitForInitialGlobalIdentities(tb.Context())

	// Reset the most common endpoint states before each test.
	for _, s := range []string{
		string(models.EndpointStateReady),
		string(models.EndpointStateWaitingDashForDashIdentity),
		string(models.EndpointStateWaitingDashToDashRegenerate),
	} {
		metrics.EndpointStateCount.WithLabelValues(s).Set(0.0)
	}

	tb.Cleanup(func() {
		controller.NewManager().RemoveAllAndWait()

		// It's helpful to keep the directories around if a test failed; only delete
		// them if tests succeed.
		if !tb.Failed() {
			os.RemoveAll(option.Config.RunDir)
		}

		// Restore the policy enforcement mode.
		policy.SetPolicyEnabled(ds.oldPolicyEnabled)

		err := ds.hive.Stop(ds.log, ctx)
		require.NoError(tb, err)
	})

	return ds
}

func (ds *DaemonSuite) setupConfigOptions() {
	// Set up all configuration options which are global to the entire test
	// run.
	mockCmd := &cobra.Command{}
	ds.hive.RegisterFlags(mockCmd.Flags())
	InitGlobalFlags(ds.log, mockCmd, ds.hive.Viper())
	option.Config.Populate(ds.log, ds.hive.Viper())
	option.Config.PopulateEnableCiliumNodeCRD(ds.log, ds.hive.Viper())
	option.Config.IdentityAllocationMode = option.IdentityAllocationModeKVstore
	option.Config.DryMode = true
	option.Config.Opts = option.NewIntOptions(&option.DaemonMutableOptionLibrary)
	// GetConfig the default labels prefix filter
	err := labelsfilter.ParseLabelPrefixCfg(ds.log, nil, nil, "")
	if err != nil {
		panic("ParseLabelPrefixCfg() failed")
	}
	option.Config.Opts.SetBool(option.DropNotify, true)
	option.Config.Opts.SetBool(option.TraceNotify, true)
	option.Config.Opts.SetBool(option.PolicyVerdictNotify, true)
}

// convenience wrapper that adds a single policy
func (ds *DaemonSuite) policyImport(rules policyAPI.Rules) {
	ds.updatePolicy(&policyTypes.PolicyUpdate{
		Rules:    policyUtils.RulesToPolicyEntries(rules),
		Resource: ipcachetypes.ResourceID("policy"),
	})
}

// convenience wrapper that synchronously performs a policy update
func (ds *DaemonSuite) updatePolicy(upd *policyTypes.PolicyUpdate) {
	dc := make(chan uint64, 1)
	upd.DoneChan = dc
	ds.PolicyImporter.UpdatePolicy(upd)
	<-dc
}
