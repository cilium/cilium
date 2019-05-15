// Copyright 2016-2019 Authors of Cilium
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

package main

import (
	"context"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/datapath"
	fakedatapath "github.com/cilium/cilium/pkg/datapath/fake"
	e "github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/metrics"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/revert"

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
	OnTracingEnabled          func() bool
	OnAlwaysAllowLocalhost    func() bool
	OnGetCachedLabelList      func(id identity.NumericIdentity) (labels.LabelArray, error)
	OnGetPolicyRepository     func() *policy.Repository
	OnUpdateProxyRedirect     func(e *e.Endpoint, l4 *policy.L4Filter, proxyWaitGroup *completion.WaitGroup) (uint16, error, revert.FinalizeFunc, revert.RevertFunc)
	OnRemoveProxyRedirect     func(e *e.Endpoint, id string, proxyWaitGroup *completion.WaitGroup) (error, revert.FinalizeFunc, revert.RevertFunc)
	OnUpdateNetworkPolicy     func(e *e.Endpoint, policy *policy.L4Policy, labelsMap cache.IdentityCache, proxyWaitGroup *completion.WaitGroup) (error, revert.RevertFunc)
	OnRemoveNetworkPolicy     func(e *e.Endpoint)
	OnQueueEndpointBuild      func(ctx context.Context, epID uint64) (func(), error)
	OnRemoveFromEndpointQueue func(epID uint64)
	OnDebugEnabled            func() bool
	OnGetCompilationLock      func() *lock.RWMutex
	OnSendNotification        func(typ monitorAPI.AgentNotification, text string) error
	OnNewProxyLogRecord       func(l *accesslog.LogRecord) error
	OnClearPolicyConsumers    func(id uint16) *sync.WaitGroup
}

func (ds *DaemonSuite) SetUpTest(c *C) {
	option.Config.Populate()
	ds.oldPolicyEnabled = policy.GetPolicyEnabled()
	policy.SetPolicyEnabled(option.DefaultEnforcement)

	// kvstore is initialized before generic SetUpTest so it must have been completed
	ds.kvstoreInit = true

	time.Local = time.UTC
	tempRunDir, err := ioutil.TempDir("", "cilium-test-run")
	c.Assert(err, IsNil)
	err = os.Mkdir(filepath.Join(tempRunDir, "globals"), 0777)
	c.Assert(err, IsNil)

	option.Config.DryMode = true
	option.Config.Opts = option.NewIntOptions(&option.DaemonMutableOptionLibrary)
	option.Config.Device = "undefined"
	option.Config.RunDir = tempRunDir
	option.Config.StateDir = tempRunDir
	option.Config.AccessLog = filepath.Join(tempRunDir, "cilium-access.log")

	// GetConfig the default labels prefix filter
	err = labels.ParseLabelPrefixCfg(nil, "")
	c.Assert(err, IsNil)
	option.Config.Opts.SetBool(option.DropNotify, true)
	option.Config.Opts.SetBool(option.TraceNotify, true)

	// Disable restore of host IPs for unit tests. There can be arbitrary
	// state left on disk.
	option.Config.EnableHostIPRestore = false

	d, _, err := NewDaemon(fakedatapath.NewDatapath())
	c.Assert(err, IsNil)
	ds.d = d

	kvstore.DeletePrefix(common.OperationalPath)
	kvstore.DeletePrefix(kvstore.BaseKeyPrefix)

	ds.OnTracingEnabled = nil
	ds.OnAlwaysAllowLocalhost = nil
	ds.OnGetCachedLabelList = nil
	ds.OnGetPolicyRepository = nil
	ds.OnUpdateProxyRedirect = nil
	ds.OnRemoveProxyRedirect = nil
	ds.OnUpdateNetworkPolicy = nil
	ds.OnRemoveNetworkPolicy = nil
	ds.OnQueueEndpointBuild = nil
	ds.OnRemoveFromEndpointQueue = nil
	ds.OnDebugEnabled = nil
	ds.OnGetCompilationLock = nil
	ds.OnSendNotification = nil
	ds.OnNewProxyLogRecord = nil
	ds.OnClearPolicyConsumers = nil
}

func (ds *DaemonSuite) TearDownTest(c *C) {
	endpointmanager.RemoveAll()

	if ds.d != nil {
		os.RemoveAll(option.Config.RunDir)
	}

	if ds.kvstoreInit {
		kvstore.DeletePrefix(common.OperationalPath)
		kvstore.DeletePrefix(kvstore.BaseKeyPrefix)
	}

	// Restore the policy enforcement mode.
	policy.SetPolicyEnabled(ds.oldPolicyEnabled)

	// Release the identity allocator reference created by NewDaemon. This
	// is done manually here as we have no Close() function daemon
	cache.Close()

	ds.d.Close()

	_, collectors := metrics.CreateConfiguration(common.MapStringStructToSlice(metrics.DefaultMetrics()))
	for _, collector := range collectors {
		metrics.Unregister(collector)
	}
}

type DaemonEtcdSuite struct {
	DaemonSuite
}

var _ = Suite(&DaemonEtcdSuite{})

func (e *DaemonEtcdSuite) SetUpTest(c *C) {
	kvstore.SetupDummy("etcd")
	e.DaemonSuite.SetUpTest(c)
}

func (e *DaemonEtcdSuite) TearDownTest(c *C) {
	e.DaemonSuite.TearDownTest(c)
}

type DaemonConsulSuite struct {
	DaemonSuite
}

var _ = Suite(&DaemonConsulSuite{})

func (e *DaemonConsulSuite) SetUpTest(c *C) {
	kvstore.SetupDummy("consul")
	e.DaemonSuite.SetUpTest(c)
}

func (e *DaemonConsulSuite) TearDownTest(c *C) {
	e.DaemonSuite.TearDownTest(c)
}

func (ds *DaemonSuite) TestMinimumWorkerThreadsIsSet(c *C) {
	c.Assert(numWorkerThreads() >= 2, Equals, true)
	c.Assert(numWorkerThreads() >= runtime.NumCPU(), Equals, true)
}

func (ds *DaemonSuite) AlwaysAllowLocalhost() bool {
	if ds.OnAlwaysAllowLocalhost != nil {
		return ds.OnAlwaysAllowLocalhost()
	}
	panic("AlwaysAllowLocalhost should not have been called")
}

func (ds *DaemonSuite) GetCachedLabelList(id identity.NumericIdentity) (labels.LabelArray, error) {
	if ds.OnGetCachedLabelList != nil {
		return ds.OnGetCachedLabelList(id)
	}
	panic("GetCachedLabelList should not have been called")
}

func (ds *DaemonSuite) GetPolicyRepository() *policy.Repository {
	if ds.OnGetPolicyRepository != nil {
		return ds.OnGetPolicyRepository()
	}
	panic("GetPolicyRepository should not have been called")
}

func (ds *DaemonSuite) UpdateProxyRedirect(e *e.Endpoint, l4 *policy.L4Filter, proxyWaitGroup *completion.WaitGroup) (uint16, error, revert.FinalizeFunc, revert.RevertFunc) {
	if ds.OnUpdateProxyRedirect != nil {
		return ds.OnUpdateProxyRedirect(e, l4, proxyWaitGroup)
	}
	panic("UpdateProxyRedirect should not have been called")
}

func (ds *DaemonSuite) RemoveProxyRedirect(e *e.Endpoint, id string, proxyWaitGroup *completion.WaitGroup) (error, revert.FinalizeFunc, revert.RevertFunc) {
	if ds.OnRemoveProxyRedirect != nil {
		return ds.OnRemoveProxyRedirect(e, id, proxyWaitGroup)
	}
	panic("RemoveProxyRedirect should not have been called")
}

func (ds *DaemonSuite) UpdateNetworkPolicy(e *e.Endpoint, policy *policy.L4Policy,
	labelsMap cache.IdentityCache, proxyWaitGroup *completion.WaitGroup) (error, revert.RevertFunc) {
	if ds.OnUpdateNetworkPolicy != nil {
		return ds.OnUpdateNetworkPolicy(e, policy, labelsMap, proxyWaitGroup)
	}
	panic("UpdateNetworkPolicy should not have been called")
}

func (ds *DaemonSuite) RemoveNetworkPolicy(e *e.Endpoint) {
	if ds.OnRemoveNetworkPolicy != nil {
		ds.OnRemoveNetworkPolicy(e)
	}
	panic("RemoveNetworkPolicy should not have been called")
}

func (ds *DaemonSuite) QueueEndpointBuild(ctx context.Context, epID uint64) (func(), error) {
	if ds.OnQueueEndpointBuild != nil {
		return ds.OnQueueEndpointBuild(ctx, epID)
	}
	panic("QueueEndpointBuild should not have been called")
}

func (ds *DaemonSuite) RemoveFromEndpointQueue(epID uint64) {
	if ds.OnRemoveFromEndpointQueue != nil {
		ds.OnRemoveFromEndpointQueue(epID)
		return
	}
	panic("RemoveFromEndpointQueue should not have been called")
}

func (ds *DaemonSuite) DebugEnabled() bool {
	if ds.OnDebugEnabled != nil {
		return ds.OnDebugEnabled()
	}
	panic("DebugEnabled should not have been called")
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

func (ds *DaemonSuite) NewProxyLogRecord(l *accesslog.LogRecord) error {
	if ds.OnNewProxyLogRecord != nil {
		return ds.OnNewProxyLogRecord(l)
	}
	panic("NewProxyLogRecord should not have been called")
}

func (ds *DaemonSuite) Datapath() datapath.Datapath {
	return ds.d.datapath
}

func (ds *DaemonSuite) ClearPolicyConsumers(id uint16) *sync.WaitGroup {
	if ds.OnClearPolicyConsumers != nil {
		return ds.OnClearPolicyConsumers(id)
	}
	panic("ClearPolicyConsumers should not have been called")
}

func (ds *DaemonSuite) GetNodeSuffix() string {
	return ds.d.GetNodeSuffix()
}

func (ds *DaemonSuite) UpdateIdentities(added, deleted cache.IdentityCache) {
	ds.d.UpdateIdentities(added, deleted)
}
