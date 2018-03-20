// Copyright 2016-2017 Authors of Cilium
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

package main

import (
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/daemon/options"
	e "github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/monitor"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/accesslog"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type DaemonSuite struct {
	d *Daemon

	kvstoreInit bool

	// Owners interface mock
	OnTracingEnabled                  func() bool
	OnDryModeEnabled                  func() bool
	OnEnableEndpointPolicyEnforcement func(e *e.Endpoint) (bool, bool)
	OnPolicyEnforcement               func() string
	OnAlwaysAllowLocalhost            func() bool
	OnGetCachedLabelList              func(id identity.NumericIdentity) (labels.LabelArray, error)
	OnGetPolicyRepository             func() *policy.Repository
	OnUpdateProxyRedirect             func(e *e.Endpoint, l4 *policy.L4Filter) (uint16, error)
	OnRemoveProxyRedirect             func(e *e.Endpoint, id string) error
	OnUpdateNetworkPolicy             func(e *e.Endpoint, policy *policy.L4Policy, labelsMap identity.IdentityCache, deniedIngressIdentities, deniedEgressIdentities map[identity.NumericIdentity]bool) error
	OnRemoveNetworkPolicy             func(e *e.Endpoint)
	OnGetStateDir                     func() string
	OnGetBpfDir                       func() string
	OnGetTunnelMode                   func() string
	OnQueueEndpointBuild              func(r *e.Request)
	OnRemoveFromEndpointQueue         func(epID uint64)
	OnDebugEnabled                    func() bool
	OnGetCompilationLock              func() *lock.RWMutex
	OnResetProxyPort                  func(e *e.Endpoint, isCTLocal bool, ips []net.IP, idsToMod policy.SecurityIDContexts)
	OnFlushCTEntries                  func(e *e.Endpoint, isCTLocal bool, ips []net.IP, idsToKeep policy.SecurityIDContexts)
	OnSendNotification                func(typ monitor.AgentNotification, text string) error
	OnNewProxyLogRecord               func(l *accesslog.LogRecord) error
}

func (ds *DaemonSuite) SetUpTest(c *C) {
	// kvstore is initialized before generic SetUpTest so it must have been completed
	ds.kvstoreInit = true

	time.Local = time.UTC
	tempRunDir, err := ioutil.TempDir("", "cilium-test-run")
	c.Assert(err, IsNil)
	err = os.Mkdir(filepath.Join(tempRunDir, "globals"), 0777)
	c.Assert(err, IsNil)

	daemonConf := &Config{
		DryMode:  true,
		Opts:     option.NewBoolOptions(&options.Library),
		Device:   "undefined",
		RunDir:   tempRunDir,
		StateDir: tempRunDir,
	}

	// Get the default labels prefix filter
	err = labels.ParseLabelPrefixCfg(nil, "")
	c.Assert(err, IsNil)
	daemonConf.Opts.Set(e.OptionDropNotify, true)
	daemonConf.Opts.Set(e.OptionTraceNotify, true)

	d, err := NewDaemon(daemonConf)
	c.Assert(err, IsNil)
	ds.d = d

	kvstore.DeletePrefix(common.OperationalPath)
	kvstore.DeletePrefix(kvstore.BaseKeyPrefix)

	identity.InitIdentityAllocator(d)

	ds.OnTracingEnabled = nil
	ds.OnDryModeEnabled = nil
	ds.OnEnableEndpointPolicyEnforcement = nil
	ds.OnPolicyEnforcement = nil
	ds.OnAlwaysAllowLocalhost = nil
	ds.OnGetCachedLabelList = nil
	ds.OnGetPolicyRepository = nil
	ds.OnUpdateProxyRedirect = nil
	ds.OnRemoveProxyRedirect = nil
	ds.OnUpdateNetworkPolicy = nil
	ds.OnRemoveNetworkPolicy = nil
	ds.OnGetStateDir = nil
	ds.OnGetBpfDir = nil
	ds.OnGetTunnelMode = nil
	ds.OnQueueEndpointBuild = nil
	ds.OnRemoveFromEndpointQueue = nil
	ds.OnDebugEnabled = nil
	ds.OnGetCompilationLock = nil
	ds.OnResetProxyPort = nil
	ds.OnFlushCTEntries = nil
	ds.OnSendNotification = nil
	ds.OnNewProxyLogRecord = nil
}

func (ds *DaemonSuite) TearDownTest(c *C) {
	if ds.d != nil {
		os.RemoveAll(ds.d.conf.RunDir)
	}

	if ds.kvstoreInit {
		kvstore.DeletePrefix(common.OperationalPath)
		kvstore.DeletePrefix(kvstore.BaseKeyPrefix)
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

func (ds *DaemonSuite) TestMiniumWorkerThreadsIsSet(c *C) {
	c.Assert(numWorkerThreads() >= 4, Equals, true)
	c.Assert(numWorkerThreads() >= runtime.NumCPU(), Equals, true)
}

func (ds *DaemonSuite) TracingEnabled() bool {
	if ds.OnTracingEnabled != nil {
		return ds.OnTracingEnabled()
	}
	panic("TracingEnabled should not have been called")
}

func (ds *DaemonSuite) DryModeEnabled() bool {
	if ds.OnDryModeEnabled != nil {
		return ds.OnDryModeEnabled()
	}
	panic("DryModeEnabled should not have been called")
}

func (ds *DaemonSuite) EnableEndpointPolicyEnforcement(e *e.Endpoint) (bool, bool) {
	if ds.OnEnableEndpointPolicyEnforcement != nil {
		return ds.OnEnableEndpointPolicyEnforcement(e)
	}
	panic("UpdateEndpointPolicyEnforcement should not have been called")
}

func (ds *DaemonSuite) PolicyEnforcement() string {
	if ds.OnPolicyEnforcement != nil {
		return ds.OnPolicyEnforcement()
	}
	panic("PolicyEnforcement should not have been called")
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

func (ds *DaemonSuite) UpdateProxyRedirect(e *e.Endpoint, l4 *policy.L4Filter) (uint16, error) {
	if ds.OnUpdateProxyRedirect != nil {
		return ds.OnUpdateProxyRedirect(e, l4)
	}
	panic("UpdateProxyRedirect should not have been called")
}

func (ds *DaemonSuite) RemoveProxyRedirect(e *e.Endpoint, id string) error {
	if ds.OnRemoveProxyRedirect != nil {
		return ds.OnRemoveProxyRedirect(e, id)
	}
	panic("RemoveProxyRedirect should not have been called")
}

func (ds *DaemonSuite) UpdateNetworkPolicy(e *e.Endpoint, policy *policy.L4Policy,
	labelsMap identity.IdentityCache, deniedIngressIdentities, deniedEgressIdentities map[identity.NumericIdentity]bool) error {
	if ds.OnUpdateNetworkPolicy != nil {
		return ds.OnUpdateNetworkPolicy(e, policy, labelsMap, deniedIngressIdentities, deniedEgressIdentities)
	}
	panic("UpdateNetworkPolicy should not have been called")
}

func (ds *DaemonSuite) RemoveNetworkPolicy(e *e.Endpoint) {
	if ds.OnRemoveNetworkPolicy != nil {
		ds.OnRemoveNetworkPolicy(e)
	}
	panic("RemoveNetworkPolicy should not have been called")
}

func (ds *DaemonSuite) GetStateDir() string {
	if ds.OnGetStateDir != nil {
		return ds.OnGetStateDir()
	}
	panic("GetStateDir should not have been called")
}

func (ds *DaemonSuite) GetBpfDir() string {
	if ds.OnGetBpfDir != nil {
		return ds.OnGetBpfDir()
	}
	panic("GetBpfDir should not have been called")
}

func (ds *DaemonSuite) GetTunnelMode() string {
	if ds.OnGetTunnelMode != nil {
		return ds.OnGetTunnelMode()
	}
	panic("GetTunnelMode should not have been called")
}

func (ds *DaemonSuite) QueueEndpointBuild(r *e.Request) {
	if ds.OnQueueEndpointBuild != nil {
		ds.OnQueueEndpointBuild(r)
		return
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

func (ds *DaemonSuite) ResetProxyPort(e *e.Endpoint, isCTLocal bool, ips []net.IP, idsToMod policy.SecurityIDContexts) {
	if ds.OnResetProxyPort != nil {
		ds.OnResetProxyPort(e, isCTLocal, ips, idsToMod)
		return
	}
	panic("ResetProxyPort should not have been called")
}

func (ds *DaemonSuite) FlushCTEntries(e *e.Endpoint, isCTLocal bool, ips []net.IP, idsToKeep policy.SecurityIDContexts) {
	if ds.OnFlushCTEntries != nil {
		ds.OnFlushCTEntries(e, isCTLocal, ips, idsToKeep)
		return
	}
	panic("FlushCTEntries should not have been called")
}

func (ds *DaemonSuite) SendNotification(typ monitor.AgentNotification, text string) error {
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
