// Copyright 2016-2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package cmd

import (
	"context"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath"
	fakedatapath "github.com/cilium/cilium/pkg/datapath/fake"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/metrics"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"

	"github.com/prometheus/client_golang/prometheus"
	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type DaemonSuite struct {
	d *Daemon

	// oldPolicyEnabled is the policy enforcement mode that was set before the test,
	// as returned by policy.GetPolicyEnabled().
	oldPolicyEnabled string

	kvstoreInit bool

	// Owners interface mock
	OnGetPolicyRepository  func() *policy.Repository
	OnQueueEndpointBuild   func(ctx context.Context, epID uint64) (func(), error)
	OnGetCompilationLock   func() *lock.RWMutex
	OnSendNotification     func(typ monitorAPI.AgentNotification, text string) error
	OnGetCIDRPrefixLengths func() ([]int, []int)

	// Metrics
	collectors []prometheus.Collector
}

func setupTestDirectories() {
	tempRunDir, err := ioutil.TempDir("", "cilium-test-run")
	if err != nil {
		panic("TempDir() failed.")
	}

	err = os.Mkdir(filepath.Join(tempRunDir, "globals"), 0777)
	if err != nil {
		panic("Mkdir failed")
	}

	option.Config.RunDir = tempRunDir
	option.Config.StateDir = tempRunDir
}

func TestMain(m *testing.M) {
	// Set up all configuration options which are global to the entire test
	// run.
	option.Config.Populate()
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

func (ds *DaemonSuite) SetUpSuite(c *C) {
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

	setupTestDirectories()

	ds.oldPolicyEnabled = policy.GetPolicyEnabled()
	policy.SetPolicyEnabled(option.DefaultEnforcement)

	d, _, err := NewDaemon(context.Background(),
		WithCustomEndpointManager(&dummyEpSyncher{}),
		fakedatapath.NewDatapath())
	c.Assert(err, IsNil)
	ds.d = d

	kvstore.Client().DeletePrefix(context.TODO(), common.OperationalPath)
	kvstore.Client().DeletePrefix(context.TODO(), kvstore.BaseKeyPrefix)

	ds.OnGetPolicyRepository = d.GetPolicyRepository
	ds.OnQueueEndpointBuild = nil
	ds.OnGetCompilationLock = d.GetCompilationLock
	ds.OnSendNotification = d.SendNotification
	ds.OnGetCIDRPrefixLengths = nil

	// Reset the most common endpoint states before each test.
	for _, s := range []string{
		string(models.EndpointStateReady),
		string(models.EndpointStateWaitingForIdentity),
		string(models.EndpointStateWaitingToRegenerate)} {
		metrics.EndpointStateCount.WithLabelValues(s).Set(0.0)
	}
}

func (ds *DaemonSuite) TearDownTest(c *C) {
	controller.NewManager().RemoveAllAndWait()
	ds.d.endpointManager.RemoveAll()

	// It's helpful to keep the directories around if a test failed; only delete
	// them if tests succeed.
	if !c.Failed() {
		os.RemoveAll(option.Config.RunDir)
	}

	if ds.kvstoreInit {
		kvstore.Client().DeletePrefix(context.TODO(), common.OperationalPath)
		kvstore.Client().DeletePrefix(context.TODO(), kvstore.BaseKeyPrefix)
	}

	// Restore the policy enforcement mode.
	policy.SetPolicyEnabled(ds.oldPolicyEnabled)

	// Release the identity allocator reference created by NewDaemon. This
	// is done manually here as we have no Close() function daemon
	ds.d.identityAllocator.Close()

	identitymanager.RemoveAll()

	ds.d.Close()
	ds.d.cancel()
}

type DaemonEtcdSuite struct {
	DaemonSuite
}

var _ = Suite(&DaemonEtcdSuite{})

func (e *DaemonEtcdSuite) SetUpSuite(c *C) {
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

func (ds *DaemonSuite) SendNotification(typ monitorAPI.AgentNotification, text string) error {
	if ds.OnSendNotification != nil {
		return ds.OnSendNotification(typ, text)
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

func (ds *DaemonSuite) GetNodeSuffix() string {
	return ds.d.GetNodeSuffix()
}

func (ds *DaemonSuite) UpdateIdentities(added, deleted cache.IdentityCache) {
	ds.d.UpdateIdentities(added, deleted)
}
