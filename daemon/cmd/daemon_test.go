// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	. "github.com/cilium/checkmate"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/cilium/api/v1/models"
	cnicell "github.com/cilium/cilium/daemon/cmd/cni"
	fakecni "github.com/cilium/cilium/daemon/cmd/cni/fake"
	"github.com/cilium/cilium/pkg/controller"
	fakeDatapath "github.com/cilium/cilium/pkg/datapath/fake"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/envoy"
	fqdnproxy "github.com/cilium/cilium/pkg/fqdn/proxy"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/maps/authmap"
	fakeauthmap "github.com/cilium/cilium/pkg/maps/authmap/fake"
	"github.com/cilium/cilium/pkg/maps/egressmap"
	"github.com/cilium/cilium/pkg/maps/signalmap"
	fakesignalmap "github.com/cilium/cilium/pkg/maps/signalmap/fake"
	"github.com/cilium/cilium/pkg/metrics"
	monitorAgent "github.com/cilium/cilium/pkg/monitor/agent"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/proxy"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/types"
)

type DaemonSuite struct {
	hive *hive.Hive

	d *Daemon

	// oldPolicyEnabled is the policy enforcement mode that was set before the test,
	// as returned by policy.GetPolicyEnabled().
	oldPolicyEnabled string

	kvstoreInit bool

	// Owners interface mock
	OnGetPolicyRepository  func() *policy.Repository
	OnGetNamedPorts        func() (npm types.NamedPortMultiMap)
	OnQueueEndpointBuild   func(ctx context.Context, epID uint64) (func(), error)
	OnGetCompilationLock   func() *lock.RWMutex
	OnSendNotification     func(typ monitorAPI.AgentNotifyMessage) error
	OnGetCIDRPrefixLengths func() ([]int, []int)

	// Metrics
	collectors []prometheus.Collector
}

func setupTestDirectories() {
	tempRunDir, err := os.MkdirTemp("", "cilium-test-run")
	if err != nil {
		panic("TempDir() failed.")
	}

	err = os.Mkdir(filepath.Join(tempRunDir, "globals"), 0777)
	if err != nil {
		panic("Mkdir failed")
	}

	option.Config.RunDir = tempRunDir
	option.Config.StateDir = tempRunDir

	socketDir := envoy.GetSocketDir(tempRunDir)
	err = os.MkdirAll(socketDir, 0700)
	if err != nil {
		panic("creating envoy socket directory failed")
	}
}

func TestMain(m *testing.M) {
	if !testutils.IntegrationTests() {
		// Immediately run the test suite without manipulating the environment
		// if integration tests are not requested.
		os.Exit(m.Run())
	}

	proxy.DefaultDNSProxy = fqdnproxy.MockFQDNProxy{}

	// Set up all configuration options which are global to the entire test
	// run.
	option.Config.Populate(Vp)
	option.Config.IdentityAllocationMode = option.IdentityAllocationModeKVstore
	option.Config.DryMode = true
	option.Config.Opts = option.NewIntOptions(&option.DaemonMutableOptionLibrary)
	// GetConfig the default labels prefix filter
	err := labelsfilter.ParseLabelPrefixCfg(nil, "")
	if err != nil {
		panic("ParseLabelPrefixCfg() failed")
	}
	option.Config.Opts.SetBool(option.DropNotify, true)
	option.Config.Opts.SetBool(option.TraceNotify, true)
	option.Config.Opts.SetBool(option.PolicyVerdictNotify, true)

	// Disable restore of host IPs for unit tests. There can be arbitrary
	// state left on disk.
	option.Config.EnableHostIPRestore = false

	// Disable the replacement, as its initialization function execs bpftool
	// which requires root privileges. This would require marking the test suite
	// as privileged.
	option.Config.KubeProxyReplacement = option.KubeProxyReplacementDisabled

	time.Local = time.UTC

	os.Exit(m.Run())
}

type dummyEpSyncher struct{}

func (epSync *dummyEpSyncher) RunK8sCiliumEndpointSync(e *endpoint.Endpoint, conf endpoint.EndpointStatusConfiguration) {
}

func (epSync *dummyEpSyncher) DeleteK8sCiliumEndpointSync(e *endpoint.Endpoint) {
}

func (ds *DaemonSuite) SetUpSuite(c *C) {
	testutils.IntegrationCheck(c)

	// Register metrics once before running the suite
	_, ds.collectors = metrics.CreateConfiguration([]string{"cilium_endpoint_state"})
	metrics.MustRegister(ds.collectors...)
}

func (ds *DaemonSuite) TearDownSuite(c *C) {
	// Unregister the metrics after the suite has finished
	for _, c := range ds.collectors {
		metrics.Unregister(c)
	}
}

func (ds *DaemonSuite) SetUpTest(c *C) {
	ctx := context.Background()

	setupTestDirectories()

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
			func() datapath.Datapath { return fakeDatapath.NewDatapath() },
			func() *option.DaemonConfig { return option.Config },
			func() cnicell.CNIConfigManager { return &fakecni.FakeCNIConfigManager{} },
			func() signalmap.Map { return fakesignalmap.NewFakeSignalMap([][]byte{}, time.Second) },
			func() authmap.Map { return fakeauthmap.NewFakeAuthMap() },
			func() egressmap.PolicyMap { return nil },
		),
		monitorAgent.Cell,
		ControlPlane,
		cell.Invoke(func(p promise.Promise[*Daemon]) {
			daemonPromise = p
		}),
	)

	err := ds.hive.Start(ctx)
	c.Assert(err, IsNil)

	ds.d, err = daemonPromise.Await(ctx)
	c.Assert(err, IsNil)

	kvstore.Client().DeletePrefix(ctx, kvstore.OperationalPath)
	kvstore.Client().DeletePrefix(ctx, kvstore.BaseKeyPrefix)

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
}

func (ds *DaemonSuite) TearDownTest(c *C) {
	ctx := context.Background()

	controller.NewManager().RemoveAllAndWait()
	ds.d.endpointManager.RemoveAll()

	// It's helpful to keep the directories around if a test failed; only delete
	// them if tests succeed.
	if !c.Failed() {
		os.RemoveAll(option.Config.RunDir)
	}

	if ds.kvstoreInit {
		kvstore.Client().DeletePrefix(ctx, kvstore.OperationalPath)
		kvstore.Client().DeletePrefix(ctx, kvstore.BaseKeyPrefix)
	}

	// Restore the policy enforcement mode.
	policy.SetPolicyEnabled(ds.oldPolicyEnabled)

	err := ds.hive.Stop(ctx)
	c.Assert(err, IsNil)

	ds.d.Close()
}

type DaemonEtcdSuite struct {
	DaemonSuite
}

var _ = Suite(&DaemonEtcdSuite{})

func (e *DaemonEtcdSuite) SetUpSuite(c *C) {
	testutils.IntegrationCheck(c)

	kvstore.SetupDummy("etcd")
	e.DaemonSuite.kvstoreInit = true
}

func (e *DaemonEtcdSuite) SetUpTest(c *C) {
	e.DaemonSuite.SetUpTest(c)
}

func (e *DaemonEtcdSuite) TearDownTest(c *C) {
	e.DaemonSuite.TearDownTest(c)
}

type DaemonConsulSuite struct {
	DaemonSuite
}

var _ = Suite(&DaemonConsulSuite{})

func (e *DaemonConsulSuite) SetUpSuite(c *C) {
	testutils.IntegrationCheck(c)

	kvstore.SetupDummy("consul")
	e.DaemonSuite.kvstoreInit = true
}

func (e *DaemonConsulSuite) SetUpTest(c *C) {
	e.DaemonSuite.SetUpTest(c)
}

func (e *DaemonConsulSuite) TearDownTest(c *C) {
	e.DaemonSuite.TearDownTest(c)
}

func (ds *DaemonSuite) TestMinimumWorkerThreadsIsSet(c *C) {
	c.Assert(numWorkerThreads() >= 2, Equals, true)
	c.Assert(numWorkerThreads() >= runtime.NumCPU(), Equals, true)
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

func (ds *DaemonSuite) GetCompilationLock() *lock.RWMutex {
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

func (ds *DaemonSuite) RemoveRestoredDNSRules(epID uint16) {
}

func (ds *DaemonSuite) TestMemoryMap(c *C) {
	pid := os.Getpid()
	m := memoryMap(pid)
	c.Assert(m, Not(Equals), "")
}
