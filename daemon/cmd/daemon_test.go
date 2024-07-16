// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/models"
	cnicell "github.com/cilium/cilium/daemon/cmd/cni"
	fakecni "github.com/cilium/cilium/daemon/cmd/cni/fake"
	"github.com/cilium/cilium/pkg/controller"
	fakeDatapath "github.com/cilium/cilium/pkg/datapath/fake"
	"github.com/cilium/cilium/pkg/datapath/prefilter"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/envoy"
	fqdnproxy "github.com/cilium/cilium/pkg/fqdn/proxy"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/identity"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	k8sSynced "github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/labelsfilter"
	ctmapgc "github.com/cilium/cilium/pkg/maps/ctmap/gc"
	"github.com/cilium/cilium/pkg/metrics"
	monitorAgent "github.com/cilium/cilium/pkg/monitor/agent"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/proxy"
	"github.com/cilium/cilium/pkg/testutils"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	"github.com/cilium/cilium/pkg/types"
)

type DaemonSuite struct {
	hive *hive.Hive
	log  *slog.Logger

	d *Daemon

	// oldPolicyEnabled is the policy enforcement mode that was set before the test,
	// as returned by policy.GetPolicyEnabled().
	oldPolicyEnabled string

	// Owners interface mock
	OnGetPolicyRepository  func() *policy.Repository
	OnGetNamedPorts        func() (npm types.NamedPortMultiMap)
	OnQueueEndpointBuild   func(ctx context.Context, epID uint64) (func(), error)
	OnGetCompilationLock   func() datapath.CompilationLock
	OnSendNotification     func(typ monitorAPI.AgentNotifyMessage) error
	OnGetCIDRPrefixLengths func() ([]int, []int)
}

func setupTestDirectories() string {
	tempRunDir, err := os.MkdirTemp("", "cilium-test-run")
	if err != nil {
		panic("TempDir() failed.")
	}

	err = os.Mkdir(filepath.Join(tempRunDir, "globals"), 0777)
	if err != nil {
		panic("Mkdir failed")
	}

	socketDir := envoy.GetSocketDir(tempRunDir)
	err = os.MkdirAll(socketDir, 0700)
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

	proxy.DefaultDNSProxy = fqdnproxy.MockFQDNProxy{}

	time.Local = time.UTC

	os.Exit(m.Run())
}

type dummyEpSyncher struct{}

func (epSync *dummyEpSyncher) RunK8sCiliumEndpointSync(e *endpoint.Endpoint, h cell.Health) {
}

func (epSync *dummyEpSyncher) DeleteK8sCiliumEndpointSync(e *endpoint.Endpoint) {
}

func setupDaemonSuite(tb testing.TB) *DaemonSuite {
	testutils.IntegrationTest(tb)

	ds := &DaemonSuite{}
	ctx := context.Background()

	ds.oldPolicyEnabled = policy.GetPolicyEnabled()
	policy.SetPolicyEnabled(option.DefaultEnforcement)

	var daemonPromise promise.Promise[*Daemon]
	ds.hive = hive.New(
		cell.Provide(
			func() k8sClient.Clientset {
				cs, _ := k8sClient.NewFakeClientset()
				cs.Disable()
				return cs
			},
			func() *option.DaemonConfig { return option.Config },
			func() cnicell.CNIConfigManager { return &fakecni.FakeCNIConfigManager{} },
			func() ctmapgc.Enabler { return ctmapgc.NewFake() },
			k8sSynced.RejectedCRDSyncPromise,
		),
		fakeDatapath.Cell,
		prefilter.Cell,
		monitorAgent.Cell,
		ControlPlane,
		metrics.Cell,
		store.Cell,
		cell.Invoke(func(p promise.Promise[*Daemon]) {
			daemonPromise = p
		}),
	)

	// bootstrap global config
	ds.setupConfigOptions()

	// create temporary test directories and update global config accordingly
	testRunDir := setupTestDirectories()
	option.Config.RunDir = testRunDir
	option.Config.StateDir = testRunDir

	ds.log = hivetest.Logger(tb)
	err := ds.hive.Start(ds.log, ctx)
	require.Nil(tb, err)

	ds.d, err = daemonPromise.Await(ctx)
	require.Nil(tb, err)

	kvstore.Client().DeletePrefix(ctx, kvstore.OperationalPath)
	kvstore.Client().DeletePrefix(ctx, kvstore.BaseKeyPrefix)

	ds.d.policy.GetSelectorCache().SetLocalIdentityNotifier(testidentity.NewDummyIdentityNotifier())

	ds.OnGetPolicyRepository = ds.d.GetPolicyRepository
	ds.OnQueueEndpointBuild = nil
	ds.OnGetCompilationLock = ds.d.GetCompilationLock
	ds.OnSendNotification = ds.d.SendNotification
	ds.OnGetCIDRPrefixLengths = nil

	// Reset the most common endpoint states before each test.
	for _, s := range []string{
		string(models.EndpointStateReady),
		string(models.EndpointStateWaitingDashForDashIdentity),
		string(models.EndpointStateWaitingDashToDashRegenerate)} {
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
		require.Nil(tb, err)

		ds.d.Close()
	})

	return ds
}

func (ds *DaemonSuite) setupConfigOptions() {
	// Set up all configuration options which are global to the entire test
	// run.
	mockCmd := &cobra.Command{}
	ds.hive.RegisterFlags(mockCmd.Flags())
	InitGlobalFlags(mockCmd, ds.hive.Viper())
	option.Config.Populate(ds.hive.Viper())
	option.Config.IdentityAllocationMode = option.IdentityAllocationModeKVstore
	option.Config.DryMode = true
	option.Config.Opts = option.NewIntOptions(&option.DaemonMutableOptionLibrary)
	// GetConfig the default labels prefix filter
	err := labelsfilter.ParseLabelPrefixCfg(nil, nil, "")
	if err != nil {
		panic("ParseLabelPrefixCfg() failed")
	}
	option.Config.Opts.SetBool(option.DropNotify, true)
	option.Config.Opts.SetBool(option.TraceNotify, true)
	option.Config.Opts.SetBool(option.PolicyVerdictNotify, true)

	// Disable the replacement, as its initialization function execs bpftool
	// which requires root privileges. This would require marking the test suite
	// as privileged.
	option.Config.KubeProxyReplacement = option.KubeProxyReplacementFalse
}

type DaemonEtcdSuite struct {
	DaemonSuite
}

func setupDaemonEtcdSuite(tb testing.TB) *DaemonEtcdSuite {
	testutils.IntegrationTest(tb)
	kvstore.SetupDummy(tb, "etcd")

	ds := setupDaemonSuite(tb)
	return &DaemonEtcdSuite{
		DaemonSuite: *ds,
	}
}

type DaemonConsulSuite struct {
	DaemonSuite
}

func setupDaemonConsulSuite(tb testing.TB) *DaemonConsulSuite {
	testutils.IntegrationTest(tb)
	kvstore.SetupDummy(tb, "consul")

	ds := setupDaemonSuite(tb)
	return &DaemonConsulSuite{
		DaemonSuite: *ds,
	}
}

func TestMinimumWorkerThreadsIsSet(t *testing.T) {
	require.Equal(t, true, numWorkerThreads() >= 2)
	require.Equal(t, true, numWorkerThreads() >= runtime.NumCPU())
}

func (ds *DaemonSuite) GetPolicyRepository() *policy.Repository {
	if ds.OnGetPolicyRepository != nil {
		return ds.OnGetPolicyRepository()
	}
	panic("GetPolicyRepository should not have been called")
}

func (ds *DaemonSuite) GetNamedPorts() (npm types.NamedPortMultiMap) {
	if ds.OnGetNamedPorts != nil {
		return ds.OnGetNamedPorts()
	}
	panic("GetNamedPorts should not have been called")
}

func (ds *DaemonSuite) QueueEndpointBuild(ctx context.Context, epID uint64) (func(), error) {
	if ds.OnQueueEndpointBuild != nil {
		return ds.OnQueueEndpointBuild(ctx, epID)
	}

	return nil, nil
}

func (ds *DaemonSuite) GetCompilationLock() datapath.CompilationLock {
	if ds.OnGetCompilationLock != nil {
		return ds.OnGetCompilationLock()
	}
	panic("GetCompilationLock should not have been called")
}

func (ds *DaemonSuite) SendNotification(msg monitorAPI.AgentNotifyMessage) error {
	if ds.OnSendNotification != nil {
		return ds.OnSendNotification(msg)
	}
	panic("SendNotification should not have been called")
}

func (ds *DaemonSuite) GetCIDRPrefixLengths() ([]int, []int) {
	if ds.OnGetCIDRPrefixLengths != nil {
		return ds.OnGetCIDRPrefixLengths()
	}
	panic("GetCIDRPrefixLengths should not have been called")
}

func (ds *DaemonSuite) Datapath() datapath.Datapath {
	return ds.d.datapath
}

func (ds *DaemonSuite) GetDNSRules(epID uint16) restore.DNSRules {
	return nil
}

func (ds *DaemonSuite) RemoveRestoredDNSRules(epID uint16) {}

func (ds *DaemonSuite) AddIdentity(id *identity.Identity)                   {}
func (ds *DaemonSuite) RemoveIdentity(id *identity.Identity)                {}
func (ds *DaemonSuite) RemoveOldAddNewIdentity(old, new *identity.Identity) {}

func TestMemoryMap(t *testing.T) {
	pid := os.Getpid()
	m := memoryMap(pid)
	require.NotEqual(t, "", m)
}
